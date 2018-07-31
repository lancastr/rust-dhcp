//! The main DHCP client module.

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
};

use tokio::{
    io,
    prelude::*,
};
use futures::StartSend;
use eui48::MacAddress;
use hostname;

use protocol::{
    Message,
    MessageType,
    DHCP_PORT_SERVER,
};

use builder::MessageBuilder;
use state::{
    State,
    DhcpState,
};

/// May be used to request stuff explicitly.
struct RequestOptions {
    /// Explicit network address request.
    address_request     : Option<Ipv4Addr>,
    /// Explicit lease time request.
    address_time        : Option<u32>,
}

/// The `Client` future result type.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub your_ip_address     : Ipv4Addr,
    pub server_ip_address   : Ipv4Addr,
    pub subnet_mask         : Option<Ipv4Addr>,
    pub routers             : Option<Vec<Ipv4Addr>>,
    pub domain_name_servers : Option<Vec<Ipv4Addr>>,
    pub static_routes       : Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
}

/// The commands used for `Sink` to send `DHCPRELEASE`, `DHCPDECLINE` and `DHCPINFORM` messages.
#[derive(Clone)]
pub enum Command {
    Release {
        message: Option<String>,
    },
    Decline {
        address: Ipv4Addr,
        message: Option<String>,
    },
    Inform {
        address: Ipv4Addr,
    },
}

type DhcpStream = Stream<Item = (SocketAddr, Message), Error = io::Error> + Send + Sync;
type DhcpSink = Sink<SinkItem = (SocketAddr, Message), SinkError = io::Error> + Send + Sync;

/// The struct implementing the `Future` trait.
pub struct Client {
    stream              : Box<DhcpStream>,
    sink                : Box<DhcpSink>,
    builder             : MessageBuilder,
    state               : State,
    options             : RequestOptions,
}

impl Client {
    /// Creates a client future.
    ///
    /// * `stream`
    /// The external socket `Stream` part.
    ///
    /// * `sink`
    /// The external socket `Sink` part.
    ///
    /// * `client_hardware_address`
    /// The mandatory client MAC address.
    ///
    /// * `client_id`
    /// The optional client identifier.
    /// If `None`, is defaulted to the 6-byte MAC address.
    ///
    /// * `hostname`
    /// May be explicitly set by a client user.
    /// Otherwise it is defaulted to the machine hostname.
    /// If the hostname cannot be get, remains unset.
    ///
    /// * `server_address`
    /// The DHCP server address.
    /// Set it if your know the server address.
    /// If set, the client communicates with the server using unicast.
    /// Otherwise, broadcasting to 255.255.255.255 is used.
    ///
    /// * `client_address`
    /// The previous client address.
    /// Set it if you want to reacquire your previous network address.
    /// If set, the client is started in INIT-REBOOT state.
    /// If not set, the client is started in INIT state.
    ///
    /// * `address_request`
    /// The requested network address.
    /// Set it if you want to requested a static network address.
    /// If not set, the server will give you either
    /// your current or previous address, or an address from its dynamic pool.
    ///
    /// * `address_time`
    /// The requested lease time.
    /// If not set, the server will determine the lease time by itself.
    /// The server may lease the address for different amount time if it decides so.
    ///
    pub fn new(
        stream                  : Box<DhcpStream>,
        sink                    : Box<DhcpSink>,
        client_hardware_address : MacAddress,
        client_id               : Option<Vec<u8>>,
        hostname                : Option<String>,
        server_address          : Option<Ipv4Addr>,
        client_address          : Option<Ipv4Addr>,
        address_request         : Option<Ipv4Addr>,
        address_time            : Option<u32>,
    ) -> Self {
        let hostname: Option<String> = if hostname.is_none() {
            hostname::get_hostname()
        } else {
            None
        };

        /*
        RFC 2131 §4.4.4
        The DHCP client broadcasts DhcpDiscover, DhcpRequest and DHCPINFORM
        messages, unless the client knows the address of a DHCP server. The
        client unicasts DHCPRELEASE messages to the server. Because the
        client is declining the use of the IP address supplied by the server,
        the client broadcasts DHCPDECLINE messages.

        When the DHCP client knows the address of a DHCP server, in either
        INIT or REBOOTING state, the client may use that address in the
        DhcpDiscover or DhcpRequest rather than the IP broadcast address.
        The client may also use unicast to send DHCPINFORM messages to a
        known DHCP server.  If the client receives no response to DHCP
        messages sent to the IP address of a known DHCP server, the DHCP
        client reverts to using the IP broadcast address.
        */
        let (destination, is_broadcast) = if let Some(ip) = server_address {
            (ip, false)
        } else {
            /*
            RFC 2131 §4.1
            DHCP messages broadcast by a client prior to that client obtaining
            its IP address must have the source address field in the IP header
            set to 0.

            Note: must be done with the external user provided Stream+Sink abstraction.
            */
            (Ipv4Addr::new(255,255,255,255), true)
        };
        let destination = SocketAddr::new(IpAddr::V4(destination), DHCP_PORT_SERVER);

        let client_id = client_id.unwrap_or(client_hardware_address.as_bytes().to_vec());

        let message_builder = MessageBuilder::new(
            client_hardware_address,
            client_id,
            hostname,
        );

        let mut options = RequestOptions {
            address_request,
            address_time,
        };

        let dhcp_state = match client_address {
            Some(ip) => {
                options.address_request = Some(ip);
                DhcpState::InitReboot
            },
            None => DhcpState::Init,
        };

        let state = State::new(destination, dhcp_state, is_broadcast);

        Client {
            stream,
            sink,
            builder: message_builder,
            state,
            options,
        }
    }
}

impl Stream for Client {
    type Item = Configuration;
    type Error = io::Error;

    /// Yields a `Configuration` after each configuration update.
    ///
    ///               The DHCP client lifecycle (RFC 2131)
    ///  --------                               -------
    /// |        | +-------------------------->|       |<-------------------+
    /// | INIT-  | |     +-------------------->| INIT  |                    |
    /// | REBOOT |DhcpNak/         +---------->|       |<---+               |
    /// |        |Restart|         |            -------     |               |
    ///  --------  |  DhcpNak/     |               |        |               |
    ///     |      Discard offer   |      -/Send DhcpDiscover               |
    /// -/Send DhcpRequest         |               |        |               |
    ///     |      |     |      DhcpAck            v        |               |
    ///  -----------     |   (not accept.)/   -----------   |               |
    /// |           |    |  Send DHCPDECLINE |           |  |               |
    /// | REBOOTING |    |         |         | SELECTING |<----+            |
    /// |           |    |        /          |           |  |  |DHCPOFFER/  |
    ///  -----------     |       /            -----------   |  |Collect     |
    ///     |            |      /                  |   |    |  |  replies   |
    /// DhcpAck/         |     /  +----------------+   +-------+            |
    /// Record lease, set|    |   v   Select offer/         |               |
    /// timers T1, T2   ------------  send DhcpRequest      |               |
    ///     |   +----->|            |             DhcpNak, Lease expired/   |
    ///     |   |      | REQUESTING |                  Halt network         |
    ///     DHCPOFFER/ |            |                       |               |
    ///     Discard     ------------                        |               |
    ///     |   |        |        |                   -----------           |
    ///     |   +--------+     DhcpAck/              |           |          |
    ///     |              Record lease, set    -----| REBINDING |          |
    ///     |                timers T1, T2     /     |           |          |
    ///     |                     |        DhcpAck/   -----------           |
    ///     |                     v     Record lease, set   ^               |
    ///     +----------------> -------      /timers T1,T2   |               |
    ///                +----->|       |<---+                |               |
    ///                |      | BOUND |<---+                |               |
    ///   DHCPOFFER, DhcpAck, |       |    |            T2 expires/   DhcpNak/
    ///    DhcpNak/Discard     -------     |             Broadcast  Halt network
    ///                |       | |         |            DhcpRequest         |
    ///                +-------+ |        DhcpAck/          |               |
    ///                     T1 expires/   Record lease, set |               |
    ///                  Send DhcpRequest timers T1, T2     |               |
    ///                  to leasing server |                |               |
    ///                          |   ----------             |               |
    ///                          |  |          |------------+               |
    ///                          +->| RENEWING |                            |
    ///                             |          |----------------------------+
    ///                              ----------
    ///
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            poll_complete!(self.sink);

            match self.state.dhcp_state() {
                DhcpState::Init => {
                    /*
                    RFC 2131 §4.4.1
                    The client begins in INIT state and forms a DhcpDiscover message.
                    The client MAY suggest a network address and/or lease time by including
                    the 'requested IP address' and 'IP address lease time' options.
                    */

                    self.state.init_to_selecting();
                },
                DhcpState::Selecting => {
                    /*
                    RFC 2131 §4.4.1
                    If the parameters are acceptable, the client records the address of
                    the server that supplied the parameters from the 'server identifier'
                    field and sends that address in the 'server identifier' field of a
                    DhcpRequest broadcast message.
                    */

                    if !self.state.is_discover_sent() {
                        let request = self.builder.discover(
                            self.state.xid(),
                            self.state.is_broadcast(),
                            self.options.address_request,
                            self.options.address_time,
                        );
                        log_send!(request, self.state.destination());
                        start_send!(self.sink, self.state.destination(), request);
                        self.state.set_discover_sent(true);
                    }

                    let (addr, response) = match self.stream.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            poll_backoff!(self.state.timer_offer);
                            self.state.set_discover_sent(false);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.xid(), response.transaction_id);
                    check_message_type!(dhcp_message_type, MessageType::DhcpOffer);

                    self.state.selecting_to_requesting(
                        response.your_ip_address,
                        expect!(response.options.address_time),
                        Some(expect!(response.options.dhcp_server_id)),
                    );
                },
                current @ DhcpState::Requesting => {
                    /*
                    RFC 2131 §4.4.1
                    Once the DhcpAck message from the server arrives,
                    the client is initialized and moves to BOUND state.
                    */

                    if !self.state.is_request_sent() {
                        let request = self.builder.request_selecting(
                            self.state.xid(),
                            self.state.is_broadcast(),
                            self.state.offered_address(),
                            Some(self.state.offered_time()),
                            expect!(self.state.dhcp_server_id()),
                        );
                        log_send!(request, self.state.destination());
                        start_send!(self.sink, self.state.destination(), request);
                        self.state.set_request_sent(true);
                    }

                    let (addr, response) = match self.stream.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            if let DhcpState::Init = poll_backoff!(self.state.timer_ack, DhcpState::Selecting, DhcpState::Init) {
                                self.state.requesting_to_init();
                            }
                            self.state.set_request_sent(false);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.xid(), response.transaction_id);

                    match dhcp_message_type {
                        MessageType::DhcpNak => {
                            warn!("Got {} in {} state", dhcp_message_type, current);
                            self.state.requesting_to_init();
                            continue;
                        },
                        MessageType::DhcpAck => {},
                        _ => {
                            warn!("Got an unexpected DHCP message type {}", dhcp_message_type);
                            continue;
                        },
                    }

                    self.state.requesting_to_bound(
                        response.your_ip_address,
                        response.options.renewal_time,
                        response.options.rebinding_time,
                        expect!(response.options.address_time),
                    );
                    return Ok(Async::Ready(Some(Configuration {
                        your_ip_address     : response.your_ip_address,
                        server_ip_address   : response.server_ip_address,
                        subnet_mask         : response.options.subnet_mask,
                        routers             : response.options.routers,
                        domain_name_servers : response.options.domain_name_servers,
                        static_routes       : response.options.static_routes,
                    })));
                },

                DhcpState::InitReboot => {
                    /*
                    RFC 2131 §4.4.2
                    The client begins in INIT-REBOOT state and sends a DhcpRequest
                    message.  The client MUST insert its known network address as a
                    'requested IP address' option in the DhcpRequest message.
                    */

                    self.state.initreboot_to_rebooting();
                },
                current @ DhcpState::Rebooting => {
                    /*
                    RFC 2131 §4.4.2
                    Once a DhcpAck message with an 'xid' field matching that in the
                    client's DhcpRequest message arrives from any server, the client is
                    initialized and moves to BOUND state.
                    */

                    if !self.state.is_request_sent() {
                        let request = self.builder.request_init_reboot(
                            self.state.xid(),
                            self.state.is_broadcast(),
                            expect!(self.options.address_request),
                            self.options.address_time,
                        );
                        log_send!(request, self.state.destination());
                        start_send!(self.sink, self.state.destination(), request);
                        self.state.set_request_sent(true);
                    }

                    let (addr, response) = match self.stream.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            if let DhcpState::Init = poll_backoff!(self.state.timer_ack, DhcpState::InitReboot, DhcpState::Init) {
                                self.state.rebooting_to_init();
                            }
                            self.state.set_request_sent(false);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.xid(), response.transaction_id);

                    match dhcp_message_type {
                        MessageType::DhcpNak => {
                            warn!("Got {} in {} state", dhcp_message_type, current);
                            self.state.rebooting_to_init();
                            continue;
                        },
                        MessageType::DhcpAck => {},
                        _ => {
                            warn!("Got an unexpected DHCP message type {}", dhcp_message_type);
                            continue;
                        },
                    }

                    self.state.rebooting_to_bound(
                        response.your_ip_address,
                        response.options.renewal_time,
                        response.options.rebinding_time,
                        expect!(response.options.address_time),
                        Some(expect!(response.options.dhcp_server_id)),
                    );
                    return Ok(Async::Ready(Some(Configuration {
                        your_ip_address     : response.your_ip_address,
                        server_ip_address   : response.server_ip_address,
                        subnet_mask         : response.options.subnet_mask,
                        routers             : response.options.routers,
                        domain_name_servers : response.options.domain_name_servers,
                        static_routes       : response.options.static_routes,
                    })));
                },

                DhcpState::Bound => {
                    /*
                    RFC 2131 §4.4.5
                    At time T1 the client moves to RENEWING state and sends (via unicast)
                    a DHCPREQUEST message to the server to extend its lease.  The client
                    sets the 'ciaddr' field in the DHCPREQUEST to its current network
                    address. The client records the local time at which the DHCPREQUEST
                    message is sent for computation of the lease expiration time.  The
                    client MUST NOT include a 'server identifier' in the DHCPREQUEST
                    message.
                    */

                    poll_delay!(self.state.timer_renewal);
                    self.state.bound_to_renewing();
                },
                DhcpState::Renewing => {
                    /*
                    RFC 2131 §4.4.5
                    If no DHCPACK arrives before time T2, the client moves to REBINDING
                    state and sends (via broadcast) a DHCPREQUEST message to extend its
                    lease.  The client sets the 'ciaddr' field in the DHCPREQUEST to its
                    current network address.  The client MUST NOT include a 'server
                    identifier' in the DHCPREQUEST message.
                    */

                    if !self.state.is_request_sent() {
                        let request = self.builder.request_renew(
                            self.state.xid(),
                            self.state.is_broadcast(),
                            self.state.assigned_address(),
                            self.options.address_time,
                        );
                        log_send!(request, self.state.destination());
                        start_send!(self.sink, self.state.destination(), request);
                        self.state.set_request_sent(true);
                    }

                    let (addr, response) = match self.stream.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            if let DhcpState::Rebinding = poll_forthon!(self.state.timer_rebinding, DhcpState::Renewing, DhcpState::Rebinding) {
                                self.state.renewing_to_rebinding();
                            }
                            self.state.set_request_sent(false);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.xid(), response.transaction_id);
                    check_message_type!(dhcp_message_type, MessageType::DhcpAck);

                    self.state.renewing_to_bound(
                        response.your_ip_address,
                        response.options.renewal_time,
                        response.options.rebinding_time,
                        expect!(response.options.address_time),
                    );
                    return Ok(Async::Ready(Some(Configuration {
                        your_ip_address     : response.your_ip_address,
                        server_ip_address   : response.server_ip_address,
                        subnet_mask         : response.options.subnet_mask,
                        routers             : response.options.routers,
                        domain_name_servers : response.options.domain_name_servers,
                        static_routes       : response.options.static_routes,
                    })));
                },
                DhcpState::Rebinding => {
                    /*
                    RFC 2131 §4.4.5
                    If the lease expires before the client receives a DHCPACK, the client
                    moves to INIT state, MUST immediately stop any other network
                    processing and requests network initialization parameters as if the
                    client were uninitialized.  If the client then receives a DHCPACK
                    allocating that client its previous network address, the client
                    SHOULD continue network processing.  If the client is given a new
                    network address, it MUST NOT continue using the previous network
                    address and SHOULD notify the local users of the problem.
                    */

                    if !self.state.is_request_sent() {
                        let request = self.builder.request_renew(
                            self.state.xid(),
                            self.state.is_broadcast(),
                            self.state.assigned_address(),
                            self.options.address_time,
                        );
                        log_send!(request, self.state.destination());
                        start_send!(self.sink, self.state.destination(), request);
                        self.state.set_request_sent(true);
                    }

                    let (addr, response) = match self.stream.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            if let DhcpState::Init = poll_forthon!(self.state.timer_expiration, DhcpState::Rebinding, DhcpState::Init) {
                                warn!("Unable to extend the expired lease!");
                                self.state.rebinding_to_init();
                            }
                            self.state.set_request_sent(false);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.xid(), response.transaction_id);
                    check_message_type!(dhcp_message_type, MessageType::DhcpAck);

                    self.state.rebinding_to_bound(
                        response.your_ip_address,
                        response.options.renewal_time,
                        response.options.rebinding_time,
                        expect!(response.options.address_time),
                    );
                    return Ok(Async::Ready(Some(Configuration {
                        your_ip_address     : response.your_ip_address,
                        server_ip_address   : response.server_ip_address,
                        subnet_mask         : response.options.subnet_mask,
                        routers             : response.options.routers,
                        domain_name_servers : response.options.domain_name_servers,
                        static_routes       : response.options.static_routes,
                    })));
                },
            }
        }
    }
}

impl Sink for Client {
    type SinkItem = Command;
    type SinkError = io::Error;

    /// Translates a `Command` into a DHCP message and sends to the user provided `Sink`.
    fn start_send(&mut self, command: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let (request, destination) = match command {
            Command::Release{ref message} => {
                let dhcp_server_id = match self.state.dhcp_server_id() {
                    Some(dhcp_server_id) => dhcp_server_id,
                    None => return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Nothing to release")),
                };
                let destination = SocketAddr::new(IpAddr::V4(dhcp_server_id), DHCP_PORT_SERVER);
                let request = self.builder.release(
                    self.state.xid(),
                    self.state.assigned_address(),
                    dhcp_server_id,
                    message.to_owned(),
                );
                (request, destination)
            },
            Command::Decline{ref address, ref message} => {
                let dhcp_server_id = match self.state.dhcp_server_id() {
                    Some(dhcp_server_id) => dhcp_server_id,
                    None => return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Nothing to decline")),
                };
                let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255,255,255,255)), DHCP_PORT_SERVER);
                let request = self.builder.decline(
                    self.state.xid(),
                    address.to_owned(),
                    dhcp_server_id,
                    message.to_owned(),
                );
                (request, destination)
            },
            Command::Inform{ref address} => {
                let dhcp_server_id = match self.state.dhcp_server_id() {
                    Some(dhcp_server_id) => dhcp_server_id,
                    None => Ipv4Addr::new(255,255,255,255),
                };
                let destination = SocketAddr::new(IpAddr::V4(dhcp_server_id), DHCP_PORT_SERVER);
                let request = self.builder.inform(
                    self.state.xid(),
                    self.state.is_broadcast(),
                    address.to_owned(),
                );
                (request, destination)
            },
        };

        log_send!(request, destination);
        match self.sink.start_send((destination, request)) {
            Ok(AsyncSink::Ready) => Ok(AsyncSink::Ready),
            Ok(AsyncSink::NotReady(_item)) => Ok(AsyncSink::NotReady(command)),
            Err(error) => Err(error),
        }
    }

    /// Just a proxy.
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.sink.poll_complete()
    }

    /// Just a proxy.
    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.poll_complete()
    }
}