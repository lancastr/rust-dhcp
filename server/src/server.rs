//! The main DHCP server module.

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
use hostname;

use framed::{
    DhcpFramed,
    DHCP_PORT_SERVER,
    DHCP_PORT_CLIENT,
};

use message::MessageBuilder;
use database::{
    Error::LeaseHasDifferentAddress,
    Database,
};
use storage::Storage;

/// The struct implementing the `Future` trait.
pub struct Server {
    socket                  : DhcpFramed,
    message_builder         : MessageBuilder,
    database                : Database,
}

impl Server {
    /// Creates a server future
    ///
    /// * `server_ip_address`
    /// The address clients will receive in the `server_ip_address` field.
    /// Is usually set to needed network interface address.
    ///
    /// * `server_name`
    /// May be explicitly set by a server user.
    /// Otherwise it is defaulted to the machine hostname.
    /// If the hostname cannot be get, remains empty.
    ///
    /// * `static_address_range`
    /// An inclusive IPv4 address range. Gaps may be implemented later.
    ///
    /// * `dynamic_address_range`
    /// An inclusive IPv4 address range. Gaps may be implemented later.
    ///
    /// * `storage`
    /// The `Storage` trait object. The trait must be implemented by a crate user.
    ///
    /// * `subnet_mask`
    /// Static data for client configuration.
    ///
    /// * `routers`
    /// Static data for client configuration.
    ///
    /// * `domain_name_servers`
    /// Static data for client configuration.
    ///
    /// * `static_routes`
    /// Static data for client configuration.
    ///
    pub fn new(
        server_ip_address       : Ipv4Addr,
        server_name             : Option<String>,
        static_address_range    : (Ipv4Addr, Ipv4Addr),
        dynamic_address_range   : (Ipv4Addr, Ipv4Addr),
        storage                 : Box<Storage>,

        subnet_mask             : Ipv4Addr,
        routers                 : Vec<Ipv4Addr>,
        domain_name_servers     : Vec<Ipv4Addr>,
        static_routes           : Vec<(Ipv4Addr, Ipv4Addr)>,
    ) -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), DHCP_PORT_SERVER);
        let socket = DhcpFramed::new(addr, false, false)?;

        let message_builder = MessageBuilder::new(
            server_ip_address,
            server_name.unwrap_or(hostname::get_hostname().unwrap_or_default()),

            subnet_mask,
            routers,
            domain_name_servers,
            static_routes,
        );

        let storage = Database::new(
            static_address_range,
            dynamic_address_range,
            storage,
        );

        Ok(Server {
            socket,
            message_builder,
            database: storage,
        })
    }
}

/// By design the pending message must be flushed before sending the next one.
macro_rules! start_send_or_panic(
    ($socket:expr, $address:expr, $message:expr) => (
        if let AsyncSink::NotReady(_) = $socket.start_send(($address, $message))? {
            panic!("Must wait for poll_complete first");
        }
    )
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! poll_complete_or_continue (
    ($socket:expr) => (
        match $socket.poll_complete() {
            Ok(Async::Ready(_)) => {},
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(error) => {
                warn!("Socket error: {}", error);
                continue;
            },
        }
    )
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! poll_or_continue (
    ($socket:expr) => (
        match $socket.poll() {
            Ok(Async::Ready(Some(data))) => data,
            Ok(Async::Ready(None)) => continue,
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(error) => {
                warn!("Unable to parse a packet: {}", error);
                continue;
            },
        };
    )
);

/// The passed `Option` must be already validated in `protocol::Message::validate` method.
macro_rules! unwrap_validated (
    ($option:expr) => (
        $option.expect("A bug in DHCP message validation")
    )
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! validate_or_continue (
    ($message:expr, $address:expr) => (
        match $message.validate() {
            Ok(dhcp_message_type) => dhcp_message_type,
            Err(error) => {
                warn!("The request from {} is invalid: {} {}", $address, error, $message);
                continue;
            },
        };
    )
);

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    /// Works infinite time.
    fn poll(&mut self) -> Poll<(), io::Error> {
        use protocol::MessageType::*;

        loop {
            poll_complete_or_continue!(self.socket);
            let (mut addr, request) = poll_or_continue!(self.socket);
            let dhcp_message_type = validate_or_continue!(request, addr);
            info!("{:?} from {}: {}", dhcp_message_type, addr, request);

            /*
            RFC 2131 §4.1
            If the  'ciaddr' field is nonzero, then the server unicasts
            DHCPOFFER and DHCPACK messages to the address in 'ciaddr'.
            If 'ciaddr' is zero, and the broadcast bit is set, then the server
            broadcasts DHCPOFFER and DHCPACK messages to 0xffffffff. If the
            broadcast bit is not set and the 'ciaddr' is zero, then the server
            unicasts DHCPOFFER and DHCPACK messages to the client's hardware
            address and 'yiaddr' address. In all cases, when 'giaddr' is zero,
            the server broadcasts any DHCPNAK messages to 0xffffffff.
            */
            if !request.client_ip_address.is_unspecified() {
                addr = SocketAddr::new(IpAddr::V4(request.client_ip_address), DHCP_PORT_CLIENT)
            }

            let client_id = match request.options.client_id {
                Some(ref client_id) => client_id.as_ref(),
                None => request.client_hardware_address.as_bytes(),
            };

            match dhcp_message_type {
                DhcpDiscover => {
                    /*
                    RFC 2131 §4.3.1
                    When a server receives a DHCPDISCOVER message from a client, the
                    server chooses a network address for the requesting client.  If no
                    address is available, the server may choose to report the problem to
                    the system administrator.
                    */

                    match self.database.allocate(
                        client_id,
                        request.options.address_time,
                        request.options.address_request,
                    ) {
                        Ok(offer) => {
                            let response = self.message_builder.dhcp_discover_to_offer(&request, &offer);
                            info!("DhcpOffer to {}: {}", addr, response);
                            start_send_or_panic!(self.socket, addr, response);
                        },
                        Err(error) => warn!("Address allocation error: {}", error.to_string()),
                    };
                },
                DhcpRequest => {
                    /*
                    RFC 2131 §4.3.2
                    A DHCPREQUEST message may come from a client responding to a
                    DHCPOFFER message from a server, from a client verifying a previously
                    allocated IP address or from a client extending the lease on a
                    network address.  If the DHCPREQUEST message contains a 'server
                    identifier' option, the message is in response to a DHCPOFFER
                    message.  Otherwise, the message is a request to verify or extend an
                    existing lease.

                    RFC 2131 §4.3.6 (table 4)
                    ---------------------------------------------------------------------
                    |              |INIT-REBOOT  |SELECTING    |RENEWING     |REBINDING |
                    ---------------------------------------------------------------------
                    |broad/unicast |broadcast    |broadcast    |unicast      |broadcast |
                    |server-ip     |MUST NOT     |MUST         |MUST NOT     |MUST NOT  |
                    |requested-ip  |MUST         |MUST         |MUST NOT     |MUST NOT  |
                    |ciaddr        |zero         |zero         |IP address   |IP address|
                    ---------------------------------------------------------------------

                    Note: server-ip     = request.options.dhcp_server_id
                          ciaddr        = request.client_ip_address
                          requested-ip  = request.options.address_request
                    */

                    // the client is in SELECTING state
                    if request.options.dhcp_server_id.is_some() {
                        let address = unwrap_validated!(request.options.address_request);
                        let lease_time = request.options.address_time;

                        match self.database.assign(client_id, &address, lease_time) {
                            Ok(ack) => {
                                let response = self.message_builder.dhcp_request_to_ack(&request, &ack);
                                info!("DhcpAck to {}: {}", addr, response);
                                start_send_or_panic!(self.socket, addr, response);
                            },
                            Err(error) => {
                                warn!("Address assignment error: {}", error.to_string());
                                let response = self.message_builder.dhcp_request_to_nak(&request, &error);
                                info!("DhcpNak to {}: {}", addr, response);
                                start_send_or_panic!(self.socket, addr, response);
                            },
                        };
                        continue;
                    }

                    // the client is in INIT-REBOOT state
                    if request.client_ip_address.is_unspecified() {
                        let address = unwrap_validated!(request.options.address_request);

                        match self.database.check(client_id, &address) {
                            Ok(ack) => {
                                let response = self.message_builder.dhcp_request_to_ack(&request, &ack);
                                info!("DhcpAck to {}: {}", addr, response);
                                start_send_or_panic!(self.socket, addr, response);
                            },
                            Err(error) => {
                                warn!("Address checking error: {}", error.to_string());
                                if let LeaseHasDifferentAddress = error {
                                    let response = self.message_builder.dhcp_request_to_nak(&request, &error);
                                    info!("DhcpNak to {}: {}", addr, response);
                                    start_send_or_panic!(self.socket, addr, response);
                                }
                                /*
                                RFC 2131 §4.3.2
                                If the DHCP server has no record of this client, then it MUST
                                remain silent, and MAY output a warning to the network administrator.
                                */
                            },
                        }
                        continue;
                    }

                    // the client is in RENEWING or REBINDING state
                    let lease_time = request.options.address_time;
                    match self.database.renew(client_id, &request.client_ip_address, lease_time) {
                        Ok(ack) => {
                            let response = self.message_builder.dhcp_request_to_ack(&request, &ack);
                            info!("DhcpAck to {}: {}", addr, response);
                            start_send_or_panic!(self.socket, addr, response);
                        },
                        Err(error) => warn!("Address checking error: {}", error.to_string()),
                    }
                },
                DhcpDecline => {
                    /*
                    RFC 2131 §4.3.3
                    If the server receives a DHCPDECLINE message, the client has
                    discovered through some other means that the suggested network
                    address is already in use.  The server MUST mark the network address
                    as not available and SHOULD notify the local system administrator of
                    a possible configuration problem.
                    */

                    let address = unwrap_validated!(request.options.address_request);

                    match self.database.freeze(&address) {
                        Ok(_) => info!("Address {:?} has been marked as unavailable", address),
                        Err(error) => warn!("Address freezing error: {}", error.to_string()),
                    };
                },
                DhcpRelease => {
                    /*
                    RFC 2131 §4.3.4
                    Upon receipt of a DHCPRELEASE message, the server marks the network
                    address as not allocated.  The server SHOULD retain a record of the
                    client's initialization parameters for possible reuse in response to
                    subsequent requests from the client.
                    */

                    let address = unwrap_validated!(request.options.address_request);

                    match self.database.deallocate(client_id, &address) {
                        Ok(_) => info!("Address {} has been released", address),
                        Err(error) => warn!("Address releasing error: {}", error.to_string()),
                    };
                },
                DhcpInform => {
                    /*
                    RFC 2131 §4.3.5
                    The server responds to a DHCPINFORM message by sending a DHCPACK
                    message directly to the address given in the 'ciaddr' field of the
                    DHCPINFORM message.  The server MUST NOT send a lease expiration time
                    to the client and SHOULD NOT fill in 'yiaddr'.
                    */

                    let address = unwrap_validated!(request.options.address_request);

                    let response = self.message_builder.dhcp_inform_to_ack(&request, "Accepted");
                    info!("Address {} has been taken by some client manually", address);
                    info!("DhcpAck to {}: {}", addr, response);
                    start_send_or_panic!(self.socket, addr, response);
                },
                _ => {},
            }
        }
    }
}