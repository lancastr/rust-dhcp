//! The main DHCP server module.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hostname;
use tokio::{io, prelude::*};
use tokio_process::OutputAsync;

use dhcp_arp::{self, Arp};
use dhcp_framed::DhcpFramed;
use dhcp_protocol::{Message, MessageType, DHCP_PORT_CLIENT, DHCP_PORT_SERVER};

use builder::MessageBuilder;
use database::{Database, Error::LeaseInvalid};
use storage::Storage;

/// The struct implementing the `Future` trait.
pub struct Server {
    socket: DhcpFramed,
    server_ip_address: Ipv4Addr,
    iface_name: String,
    builder: MessageBuilder,
    database: Database,
    arp: Option<OutputAsync>,
}

impl Server {
    /// Creates a server future
    ///
    /// * `server_ip_address`
    /// The address clients will receive in the `dhcp_server_id` option.
    /// Is usually set to needed network interface address.
    ///
    /// * `iface_name`
    /// The interface the server should work on. Is required for ARP injection.
    /// Something like `ens33` on Linux or like `Ethernet` on Windows.
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
        server_ip_address: Ipv4Addr,
        iface_name: String,
        static_address_range: (Ipv4Addr, Ipv4Addr),
        dynamic_address_range: (Ipv4Addr, Ipv4Addr),
        storage: Box<Storage>,

        subnet_mask: Ipv4Addr,
        routers: Vec<Ipv4Addr>,
        domain_name_servers: Vec<Ipv4Addr>,
        static_routes: Vec<(Ipv4Addr, Ipv4Addr)>,
    ) -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DHCP_PORT_SERVER);
        let socket = DhcpFramed::new(addr, false, false)?;
        let hostname = hostname::get_hostname();

        let message_builder = MessageBuilder::new(
            server_ip_address,
            hostname,
            subnet_mask,
            routers,
            domain_name_servers,
            static_routes,
        );

        let storage = Database::new(static_address_range, dynamic_address_range, storage);

        Ok(Server {
            socket,
            server_ip_address,
            iface_name,
            builder: message_builder,
            database: storage,
            arp: None,
        })
    }

    /// Chooses the destination IP according to RFC 2131 rules.
    ///
    /// Performs the ARP query in hardware unicast cases and sets the `arp_future` field
    /// if ARP processing is expected to be too long for the tokio reactor.
    fn destination(&mut self, request: &Message, response: &Message) -> Ipv4Addr {
        if !request.client_ip_address.is_unspecified() {
            return request.client_ip_address;
        }

        if request.is_broadcast {
            return Ipv4Addr::new(255, 255, 255, 255);
        }

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            info!(
                "Injecting an ARP entry {} -> {}",
                request.client_hardware_address, response.your_ip_address,
            );
            match dhcp_arp::add(
                request.client_hardware_address,
                response.your_ip_address,
                self.iface_name.to_owned(),
            ) {
                Ok(Arp::Linux(_)) => {}
                Ok(Arp::Windows(future)) => self.arp = Some(future),
                Err(error) => error!("ARP error: {:?}", error),
            }
        }

        /*
        RFC 2131 §4.1
        If unicasting is not possible, the message
        MAY be sent as an IP broadcast using an IP broadcast address
        (preferably 0xffffffff) as the IP destination address and the link-
        layer broadcast address as the link-layer destination address.

        Note: I don't know yet when unicasting is not possible.
        */

        response.your_ip_address
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    /// Works infinite time.
    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            poll_arp!(self.arp);
            poll_complete!(self.socket);
            let (addr, request) = poll!(self.socket);
            log_receive!(request, addr);
            let dhcp_message_type = validate!(request, addr);

            if let Some(dhcp_server_id) = request.options.dhcp_server_id {
                if dhcp_server_id != self.server_ip_address {
                    warn!("Ignoring a message destined for server {}", dhcp_server_id);
                    continue;
                }
            }

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

            let client_id = match request.options.client_id {
                Some(ref client_id) => client_id.as_ref(),
                None => request.client_hardware_address.as_bytes(),
            };

            match dhcp_message_type {
                MessageType::DhcpDiscover => {
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
                            let response = self.builder.dhcp_discover_to_offer(&request, &offer);
                            let destination = self.destination(&request, &response);
                            log_send!(response, destination);
                            start_send!(self.socket, destination, response);
                        }
                        Err(error) => warn!("Address allocation error: {}", error.to_string()),
                    };
                }
                MessageType::DhcpRequest => {
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

                    // the client is in the SELECTING state
                    if request.options.dhcp_server_id.is_some() {
                        let address = expect!(request.options.address_request);
                        let lease_time = request.options.address_time;

                        match self.database.assign(client_id, &address, lease_time) {
                            Ok(ack) => {
                                let response = self.builder.dhcp_request_to_ack(&request, &ack);
                                let destination = self.destination(&request, &response);
                                log_send!(response, destination);
                                start_send!(self.socket, destination, response);
                            }
                            Err(error) => {
                                warn!("Address assignment error: {}", error.to_string());
                                let response = self.builder.dhcp_request_to_nak(&request, &error);
                                let destination = Ipv4Addr::new(255, 255, 255, 255);
                                log_send!(response, destination);
                                start_send!(self.socket, destination, response);
                            }
                        };
                        continue;
                    }

                    // the client is in the INIT-REBOOT state
                    if request.client_ip_address.is_unspecified() {
                        let address = expect!(request.options.address_request);

                        match self.database.check(client_id, &address) {
                            Ok(ack) => {
                                let response = self.builder.dhcp_request_to_ack(&request, &ack);
                                let destination = self.destination(&request, &response);
                                log_send!(response, destination);
                                start_send!(self.socket, destination, response);
                            }
                            Err(error) => {
                                warn!("Address checking error: {}", error.to_string());
                                if let LeaseInvalid = error {
                                    let response =
                                        self.builder.dhcp_request_to_nak(&request, &error);
                                    let destination = Ipv4Addr::new(255, 255, 255, 255);
                                    log_send!(response, destination);
                                    start_send!(self.socket, destination, response);
                                }
                                /*
                                RFC 2131 §4.3.2
                                If the DHCP server has no record of this client, then it MUST
                                remain silent, and MAY output a warning to the network administrator.
                                */
                            }
                        }
                        continue;
                    }

                    // the client is in the RENEWING or REBINDING state
                    let lease_time = request.options.address_time;
                    match self.database
                        .renew(client_id, &request.client_ip_address, lease_time)
                    {
                        Ok(ack) => {
                            let response = self.builder.dhcp_request_to_ack(&request, &ack);
                            let destination = self.destination(&request, &response);
                            log_send!(response, destination);
                            start_send!(self.socket, destination, response);
                        }
                        Err(error) => warn!("Address checking error: {}", error.to_string()),
                    }
                }
                MessageType::DhcpDecline => {
                    /*
                    RFC 2131 §4.3.3
                    If the server receives a DHCPDECLINE message, the client has
                    discovered through some other means that the suggested network
                    address is already in use.  The server MUST mark the network address
                    as not available and SHOULD notify the local system administrator of
                    a possible configuration problem.
                    */

                    let address = expect!(request.options.address_request);
                    match self.database.freeze(&address) {
                        Ok(_) => info!("Address {} has been marked as unavailable", address),
                        Err(error) => warn!("Address freezing error: {}", error.to_string()),
                    };
                }
                MessageType::DhcpRelease => {
                    /*
                    RFC 2131 §4.3.4
                    Upon receipt of a DHCPRELEASE message, the server marks the network
                    address as not allocated.  The server SHOULD retain a record of the
                    client's initialization parameters for possible reuse in response to
                    subsequent requests from the client.
                    */

                    let address = request.client_ip_address;
                    match self.database.deallocate(client_id, &address) {
                        Ok(_) => info!("Address {} has been released", address),
                        Err(error) => warn!("Address releasing error: {}", error.to_string()),
                    };
                }
                MessageType::DhcpInform => {
                    /*
                    RFC 2131 §4.3.5
                    The server responds to a DHCPINFORM message by sending a DHCPACK
                    message directly to the address given in the 'ciaddr' field of the
                    DHCPINFORM message.  The server MUST NOT send a lease expiration time
                    to the client and SHOULD NOT fill in 'yiaddr'.
                    */

                    info!(
                        "Address {} has been taken by some client manually",
                        request.client_ip_address
                    );
                    let response = self.builder.dhcp_inform_to_ack(&request, "Accepted");
                    let destination = self.destination(&request, &response);
                    log_send!(response, destination);
                    start_send!(self.socket, destination, response);
                }
                _ => {}
            }
        }
    }
}
