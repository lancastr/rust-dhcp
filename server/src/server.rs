//! Server module

use std::{
    ops::Range,
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

use protocol;
use framed::*;
use message::{
    self,
    MessageBuilder,
};
use storage::Storage;

/// The struct implementing the `Future` trait.
pub struct Server {
    socket                  : DhcpFramed,
    message_builder         : MessageBuilder,
    storage                 : Storage,
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
    /// Otherwise is defaulted to the machine hostname.
    /// If the hostname cannot be get, remains empty.
    ///
    /// * `static_address_range`
    /// Non-inclusive IPv4 address range.
    ///
    /// * `dynamic_address_range`
    /// Non-inclusive IPv4 address range.
    ///
    /// * `subnet_mask`
    /// Static data for clients.
    ///
    /// * `routers`
    /// Static data for clients.
    ///
    /// * `domain_name_servers`
    /// Static data for clients.
    ///
    /// * `static_routes`
    /// Static data for clients.
    ///
    pub fn new(
        server_ip_address       : Ipv4Addr,
        server_name             : Option<String>,
        static_address_range    : Range<Ipv4Addr>,
        dynamic_address_range   : Range<Ipv4Addr>,
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

        let storage = Storage::new(
            static_address_range,
            dynamic_address_range,
        );

        Ok(Server {
            socket,
            message_builder,
            storage,
        })
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    /// Works infinite time.
    fn poll(&mut self) -> Poll<(), io::Error> {
        use protocol::MessageType::*;

        loop {
            if let Async::NotReady = self.socket.poll_complete()? { return Ok(Async::NotReady); }

            if let Some((mut addr, request)) = try_ready!(self.socket.poll()) {
                info!("Request from {}:\n{}", addr, request);
                if let Err(protocol::Error::Validation) = request.validate() {
                    warn!("The request is invalid");
                    continue;
                }
                let dhcp_message_type = request.options.dhcp_message_type.expect("The is an error in DHCP message validation");

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
                        match self.storage.allocate(
                            client_id,
                            request.options.address_time,
                            request.options.address_request,
                        ) {
                            Ok(offer) => {
                                let response = self.message_builder.dhcp_discover_to_offer(&request, &offer);
                                info!("DHCPOFFER to {}:\n{}", addr, response);
                                if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                                    panic!("Must wait for poll_complete first");
                                }
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
                            match self.storage.assign(
                                client_id,
                                request.options.address_time,
                                request.options.address_request,
                            ) {
                                Ok(ack) => {
                                    let response = self.message_builder.dhcp_request_to_ack(&request, &ack);
                                    info!("DHCPACK to {}:\n{}", addr, response);
                                    if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                                        panic!("Must wait for poll_complete first");
                                    }
                                },
                                Err(error) => {
                                    warn!("Address assignment error: {}", error.to_string());
                                    let response = self.message_builder.dhcp_request_to_nak(&request, &error);
                                    info!("DHCPNAK to {}:\n{}", addr, response);
                                    if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                                        panic!("Must wait for poll_complete first");
                                    }
                                },
                            };
                            continue;
                        }

                        // the client is in INIT-REBOOT state
                        if request.client_ip_address.is_unspecified() {
                            match self.storage.check(
                                client_id,
                                request.options.address_request,
                            ) {
                                Ok(ack) => {
                                    let response = self.message_builder.dhcp_request_to_ack(&request, &ack);
                                    info!("DHCPACK to {}:\n{}", addr, response);
                                    if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                                        panic!("Must wait for poll_complete first");
                                    }
                                },
                                Err(error) => {
                                    warn!("Address checking error: {}", error.to_string());
                                    if let message::Error::LeaseHasDifferentAddress = error {
                                        let response = self.message_builder.dhcp_request_to_nak(&request, &error);
                                        info!("DHCPNAK to {}:\n{}", addr, response);
                                        if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                                            panic!("Must wait for poll_complete first");
                                        }
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
                        match self.storage.renew(
                            client_id,
                            &request.client_ip_address,
                            request.options.address_time,
                        ) {
                            Ok(ack) => {
                                let response = self.message_builder.dhcp_request_to_ack(&request, &ack);
                                info!("DHCPACK to {}:\n{}", addr, response);
                                if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                                    panic!("Must wait for poll_complete first");
                                }
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
                        match self.storage.freeze(
                            client_id,
                            request.options.address_request,
                        ) {
                            Ok(_) => info!("Address {:?} has been marked as unavailable", request.options.address_request),
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
                        match self.storage.deallocate(
                            client_id,
                            request.options.address_request,
                        ) {
                            Ok(_) => info!("Address {:?} has been released", request.options.address_request),
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
                        let response = self.message_builder.dhcp_inform_to_ack(&request, "Accepted");
                        info!("Address {:?} has been taken by some client manually", request.options.address_request);
                        info!("DHCPACK to {}:\n{}", addr, response);
                        if let AsyncSink::NotReady(_) = self.socket.start_send((addr, response))? {
                            panic!("Must wait for poll_complete first");
                        }
                    },
                    _ => {},
                }
            }
        }
    }
}