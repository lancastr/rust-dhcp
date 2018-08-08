//! The main DHCP server module.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hostname;
use tokio::{io, prelude::*};
#[cfg(target_os = "windows")]
use tokio_process::OutputAsync;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
use futures_cpupool::CpuPool;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
use eui48::{MacAddress, EUI48LEN};

use dhcp_framed::DhcpFramed;
use dhcp_protocol::{Message, MessageType, DHCP_PORT_CLIENT, DHCP_PORT_SERVER};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use dhcp_arp;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
use dhcp_bpf::Bpf;

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
    #[cfg(any(target_os = "windows"))]
    arp: Option<OutputAsync>,
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    bpf: Bpf,
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    cpu_pool: CpuPool,
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
            iface_name: iface_name.to_owned(),
            server_ip_address,
            builder: message_builder,
            database: storage,
            #[cfg(any(target_os = "windows"))]
            arp: None,
            #[cfg(any(target_os = "freebsd", target_os = "macos"))]
            bpf: Bpf::new(iface_name.to_owned())?,
            #[cfg(any(target_os = "freebsd", target_os = "macos"))]
            cpu_pool: CpuPool::new(4), //FIXME
        })
    }

    /// Chooses the destination IP according to RFC 2131 rules.
    ///
    /// Performs the ARP query in hardware unicast cases and sets the `arp` field
    /// if ARP processing is expected to be too long for the tokio reactor.    ///
    /// The bool flag is `true` if hardware unicast is required.
    fn destination(&mut self, request: &Message, response: &Message) -> (Ipv4Addr, bool) {
        if !request.client_ip_address.is_unspecified() {
            return (request.client_ip_address, false);
        }

        if request.is_broadcast {
            return (Ipv4Addr::new(255, 255, 255, 255), false);
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
                Ok(_result) => {
                    #[cfg(target_os = "windows")]
                    {
                        self.arp = Some(_result);
                    }
                }
                Err(error) => error!("ARP error: {:?}", error),
            }
        }

        (response.your_ip_address, true)

        /*
        RFC 2131 §4.1
        If unicasting is not possible, the message
        MAY be sent as an IP broadcast using an IP broadcast address
        (preferably 0xffffffff) as the IP destination address and the link-
        layer broadcast address as the link-layer destination address.

        Note: I don't know yet when unicasting is not possible.
        */
    }

    /// Sends a response using OS-specific features.
    #[allow(unused)]
    fn send(&mut self, response: Message, destination: Ipv4Addr, hw_unicast: bool) -> io::Result<()> {
        log_send!(response, destination);

        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        {
            if hw_unicast {
                const BPF_PACKET_BUFFER_SIZE: usize = 8192;

                trace!("Sending to {} via BPF", destination);
                let mut payload = vec![0u8; BPF_PACKET_BUFFER_SIZE];
                let amount = response.to_bytes(payload.as_mut())?;

                let packet = Self::ethernet_packet(
                    MacAddress::new([0x08,0x00,0x27,0x26,0xdc,0x79]),
                    response.client_hardware_address.to_owned(),
                    self.server_ip_address.to_owned(),
                    destination.to_owned(),
                    &payload[..amount],
                )?;
                let mut bpf = self.bpf.clone();
                self.cpu_pool.clone().spawn_fn(move || {
                    if let Err(error) = bpf.write_all(&packet) {
                        error!("BPF sending error: {}", error);
                    } else {
                        trace!("Response has been sent via BPF");
                    }
                    Ok::<(),()>(())
                }).forget();
                return Ok(());
            }
        }

        let destination = SocketAddr::new(IpAddr::V4(destination), DHCP_PORT_CLIENT);
        start_send!(self.socket, destination, response);
        Ok(())
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    fn ethernet_packet(
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        use etherparse::{PacketBuilder, WriteError};
        const BPF_IP_TTL: u8 = 64;

        let builder = PacketBuilder::ethernet2(
            *array_ref!(src_mac.as_bytes(), 0, EUI48LEN),
            *array_ref!(dst_mac.as_bytes(), 0, EUI48LEN),
        )
            .ipv4(src_ip.octets(), dst_ip.octets(), BPF_IP_TTL)
            .udp(DHCP_PORT_SERVER, DHCP_PORT_CLIENT);

        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        match builder.write(&mut result, payload) {
            Ok(_) => Ok(result),
            Err(WriteError::IoError(error)) => Err(error),
            Err(WriteError::ValueError(error)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{:?}", error),
            )),
        }
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    /// Works infinite time.
    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            #[cfg(any(target_os = "windows"))]
            {
                poll_arp!(self.arp);
            }
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
                            let (destination, hw_unicast) = self.destination(&request, &response);
                            self.send(response, destination, hw_unicast)?;
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
                                let (destination, hw_unicast) = self.destination(&request, &response);
                                self.send(response, destination, hw_unicast)?;
                            }
                            Err(error) => {
                                warn!("Address assignment error: {}", error.to_string());
                                let response = self.builder.dhcp_request_to_nak(&request, &error);
                                let destination = Ipv4Addr::new(255, 255, 255, 255);
                                self.send(response, destination, false)?;
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
                                let (destination, hw_unicast) = self.destination(&request, &response);
                                self.send(response, destination, hw_unicast)?;
                            }
                            Err(error) => {
                                warn!("Address checking error: {}", error.to_string());
                                if let LeaseInvalid = error {
                                    let response =
                                        self.builder.dhcp_request_to_nak(&request, &error);
                                    let destination = Ipv4Addr::new(255, 255, 255, 255);
                                    self.send(response, destination, false)?;
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
                            let (destination, hw_unicast) = self.destination(&request, &response);
                            self.send(response, destination, hw_unicast)?;
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
                    let (destination, hw_unicast) = self.destination(&request, &response);
                    self.send(response, destination, hw_unicast)?;
                }
                _ => {}
            }
        }
    }
}
