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
use chrono::prelude::*;
use hostname;
use rand;

use framed::{
    DhcpFramed,
    DHCP_PORT_SERVER,
    DHCP_PORT_CLIENT,
};
use protocol::MessageType;

use message::{
    MessageBuilder,
    ClientId,
};
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
    your_ip_address     : Ipv4Addr,
    server_ip_address   : Ipv4Addr,
    subnet_mask         : Option<Ipv4Addr>,
    routers             : Option<Vec<Ipv4Addr>>,
    domain_name_servers : Option<Vec<Ipv4Addr>>,
    static_routes       : Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
}

/// The struct implementing the `Future` trait.
pub struct Client {
    socket              : DhcpFramed,
    message_builder     : MessageBuilder,
    state               : State,
    options             : RequestOptions,
}

impl Client {
    /// Creates a client future.
    ///
    /// * `client_id`
    /// The client identifier.
    /// May be either a MAC-48 or a custom byte array.
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
        client_id               : ClientId,
        hostname                : Option<String>,
        server_address          : Option<Ipv4Addr>,
        client_address          : Option<Ipv4Addr>,
        address_request         : Option<Ipv4Addr>,
        address_time            : Option<u32>,
    ) -> io::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), DHCP_PORT_CLIENT);
        let socket = DhcpFramed::new(addr, true, true)?;

        let hostname: Option<String> = if hostname.is_none() { hostname::get_hostname() } else { None };

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
            (Ipv4Addr::new(255,255,255,255), true)
        };
        let destination = SocketAddr::new(IpAddr::V4(destination), DHCP_PORT_SERVER);

        let message_builder = MessageBuilder::new(
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

        Ok(Client {
            socket,
            message_builder,
            state,
            options,
        })
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
            poll_complete!(self.socket);

            match self.state.dhcp_state {
                current @ DhcpState::Init => {
                    /*
                    RFC 2131 §4.4.1
                    The client begins in INIT state and forms a DhcpDiscover message.
                    The client MAY suggest a network address and/or lease time by including
                    the 'requested IP address' and 'IP address lease time' options.
                    */

                    self.state.transaction_id = rand::random::<u32>();
                    let discover = self.message_builder.discover(
                        self.state.transaction_id,
                        self.state.is_broadcast,
                        self.options.address_request,
                        self.options.address_time,
                    );
                    log_send!(discover, self.state.destination);
                    start_send!(self.socket, self.state.destination, discover);
                    self.state.transcend(current, DhcpState::Selecting);
                },
                current @ DhcpState::Selecting => {
                    /*
                    RFC 2131 §4.4.1
                    If the parameters are acceptable, the client records the address of
                    the server that supplied the parameters from the 'server identifier'
                    field and sends that address in the 'server identifier' field of a
                    DhcpRequest broadcast message.
                    */

                    // Wait for a DHCPOFFER if self.state.dhcp_server_id is unset
                    if self.state.dhcp_server_id.is_none() {
                        let (mut addr, response) = match self.socket.poll() {
                            Ok(Async::Ready(data)) => expect!(data),
                            Ok(Async::NotReady) => {
                                let next = poll_timer!(self.state.timer_offer, DhcpState::Init);
                                self.state.transcend(current, next);
                                continue;
                            },
                            Err(error) => {
                                warn!("Socket error: {}", error);
                                continue;
                            },
                        };

                        let dhcp_message_type = validate!(response, addr);
                        log_receive!(response, addr);
                        check_xid!(self.state.transaction_id, response.transaction_id);

                        if let MessageType::DhcpOffer = dhcp_message_type {} else {
                            warn!("Got an unexpected DHCP message type {}", dhcp_message_type);
                            continue;
                        }

                        self.state.set_destination(expect!(response.options.dhcp_server_id));
                        self.state.offered_address = response.your_ip_address;
                        self.state.offered_time = expect!(response.options.address_time);
                        self.state.requested_at = Utc::now().timestamp() as u32;
                        self.state.dhcp_server_id = Some(expect!(response.options.dhcp_server_id));
                    }

                    // self.state.dhcp_server_id is set. Retransmit the DHCPREQUEST
                    let request = self.message_builder.request_selecting(
                        self.state.transaction_id,
                        self.state.is_broadcast,
                        self.state.offered_address,
                        Some(self.state.offered_time),
                        expect!(self.state.dhcp_server_id),
                    );
                    log_send!(request, self.state.destination);
                    start_send!(self.socket, self.state.destination, request);
                    self.state.transcend(current, DhcpState::Requesting);
                },
                current @ DhcpState::Requesting => {
                    /*
                    RFC 2131 §4.4.1
                    Once the DhcpAck message from the server arrives,
                    the client is initialized and moves to BOUND state.
                    */

                    let (mut addr, response) = match self.socket.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            let next = poll_timer!(self.state.timer_ack, DhcpState::Selecting, DhcpState::Init);
                            self.state.transcend(current, next);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.transaction_id, response.transaction_id);

                    match dhcp_message_type {
                        MessageType::DhcpNak => {
                            warn!("Got {} in {} state", dhcp_message_type, current);
                            self.state.set_destination_broadcast();
                            self.state.transcend(current, DhcpState::Init);
                            continue;
                        },
                        MessageType::DhcpAck => {},
                        _ => {
                            warn!("Got an unexpected DHCP message type {}", dhcp_message_type);
                            continue;
                        },
                    }

                    self.state.assigned_address = response.your_ip_address;
                    self.state.set_timers(
                        response.options.renewal_time,
                        response.options.rebinding_time,
                        expect!(response.options.address_time),
                    );
                    self.state.transcend(current, DhcpState::Bound);
                    return Ok(Async::Ready(Some(Configuration {
                        your_ip_address     : response.your_ip_address,
                        server_ip_address   : response.server_ip_address,
                        subnet_mask         : response.options.subnet_mask,
                        routers             : response.options.routers,
                        domain_name_servers : response.options.domain_name_servers,
                        static_routes       : response.options.static_routes,
                    })));
                },

                current @ DhcpState::InitReboot => {
                    /*
                    RFC 2131 §4.4.2
                    The client begins in INIT-REBOOT state and sends a DhcpRequest
                    message.  The client MUST insert its known network address as a
                    'requested IP address' option in the DhcpRequest message.
                    */

                    self.state.transaction_id = rand::random::<u32>();
                    let request = self.message_builder.request_init_reboot(
                        self.state.transaction_id,
                        self.state.is_broadcast,
                        expect!(self.options.address_request),
                        self.options.address_time,
                    );
                    log_send!(request, self.state.destination);
                    start_send!(self.socket, self.state.destination, request);
                    self.state.transcend(current, DhcpState::Rebooting);
                },
                current @ DhcpState::Rebooting => {
                    /*
                    RFC 2131 §4.4.2
                    Once a DhcpAck message with an 'xid' field matching that in the
                    client's DhcpRequest message arrives from any server, the client is
                    initialized and moves to BOUND state.
                    */

                    let (mut addr, response) = match self.socket.poll() {
                        Ok(Async::Ready(data)) => expect!(data),
                        Ok(Async::NotReady) => {
                            let next = poll_timer!(self.state.timer_ack, DhcpState::InitReboot, DhcpState::Init);
                            self.state.transcend(current, next);
                            continue;
                        },
                        Err(error) => {
                            warn!("Socket error: {}", error);
                            continue;
                        },
                    };

                    let dhcp_message_type = validate!(response, addr);
                    log_receive!(response, addr);
                    check_xid!(self.state.transaction_id, response.transaction_id);

                    match dhcp_message_type {
                        MessageType::DhcpNak => {
                            warn!("Got {} in {} state", dhcp_message_type, current);
                            self.state.set_destination_broadcast();
                            self.state.transcend(current, DhcpState::InitReboot);
                            continue;
                        },
                        MessageType::DhcpAck => {},
                        _ => {
                            warn!("Got an unexpected DHCP message type {}", dhcp_message_type);
                            continue;
                        },
                    }

                    self.state.set_timers(
                        response.options.renewal_time,
                        response.options.rebinding_time,
                        expect!(response.options.address_time),
                    );
                    self.state.transcend(current, DhcpState::Bound);
                    return Ok(Async::Ready(Some(Configuration {
                        your_ip_address     : response.your_ip_address,
                        server_ip_address   : response.server_ip_address,
                        subnet_mask         : response.options.subnet_mask,
                        routers             : response.options.routers,
                        domain_name_servers : response.options.domain_name_servers,
                        static_routes       : response.options.static_routes,
                    })));
                },

                current @ DhcpState::Bound => {
                    if let Some(ref mut timer) = self.state.timer_renewal {
                        match timer.poll() {
                            Ok(Async::Ready(_)) => {
                                info!("Entering RENEWING state");
                                self.state.dhcp_state = DhcpState::Renewing;
                                continue;
                            },
                            Ok(Async::NotReady) => return Ok(Async::NotReady),
                            Err(error) => panic!("Timer error: {}", error),
                        }
                    } else {
                        panic!("Timer is None in {} state", current);
                    }
                },
                current @ DhcpState::Renewing => {
                    if let Some(ref mut timer) = self.state.timer_rebinding {
                        match timer.poll() {
                            Ok(Async::Ready(_)) => {
                                info!("Entering REBINDING state");
                                self.state.dhcp_state = DhcpState::Rebinding;
                                continue;
                            },
                            Ok(Async::NotReady) => return Ok(Async::NotReady),
                            Err(error) => panic!("Timer error: {}", error),
                        }
                    } else {
                        panic!("Timer is None in {} state", current);
                    }
                },
                current @ DhcpState::Rebinding => {
                    if let Some(ref mut timer) = self.state.timer_expiration {
                        match timer.poll() {
                            Ok(Async::Ready(_)) => {
                                info!("Reverting to INIT state");
                                // A new timer must be constructed for the SELECTING state
                                self.state.timer_offer = None;

                                self.state.dhcp_state = DhcpState::Init;
                                continue;
                            },
                            Ok(Async::NotReady) => return Ok(Async::NotReady),
                            Err(error) => panic!("Timer error: {}", error),
                        }
                    } else {
                        panic!("Timer is None in {} state", current);
                    }
                },
            }
        }
    }
}