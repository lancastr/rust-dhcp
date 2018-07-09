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

use protocol::*;
use framed::*;
use message_builder::MessageBuilder;
use storage::Storage;

pub struct Server {
    socket                  : DhcpFramed,
    message_builder         : MessageBuilder,
    storage                 : Storage,
}

impl Server {
    ///
    /// server_name:
    ///     Some(string) if you want to specify the server name manually
    ///     None to get the hostname automatically
    ///
    /// dynamic_address_range:
    ///     is not inclusive yet, but may become so later
    ///
    pub fn new(
        server_ip_address       : Ipv4Addr,
        gateway_ip_address      : Ipv4Addr,
        server_name             : Option<String>,

        static_address_range    : Range<Ipv4Addr>,
        dynamic_address_range   : Range<Ipv4Addr>,

        subnet_mask             : Ipv4Addr,
    ) -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), UDP_PORT_SERVER);
        let socket = DhcpFramed::new(addr, false, false)?;

        let message_builder = MessageBuilder::new(
            server_ip_address,
            gateway_ip_address,
            server_name.unwrap_or(hostname::get_hostname().unwrap_or_default()),

            subnet_mask,
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

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            match self.socket.poll_complete()? {
                Async::Ready(_) => {},
                Async::NotReady => return Ok(Async::NotReady),
            }

            if let Some((mut addr, request)) = try_ready!(self.socket.poll()) {
                /*
                RFC 2131 §4.1
                If the 'giaddr' field in a DHCP message from a client is non-zero,
                the server sends any return messages to the 'DHCP server' port on the
                BOOTP relay agent whose address appears in 'giaddr'. If the 'giaddr'
                field is zero and the 'ciaddr' field is nonzero, then the server
                unicasts DHCPOFFER and DHCPACK messages to the address in 'ciaddr'.
                If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
                set, then the server broadcasts DHCPOFFER and DHCPACK messages to
                0xffffffff. If the broadcast bit is not set and 'giaddr' is zero and
                'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
                messages to the client's hardware address and 'yiaddr' address.  In
                all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
                messages to 0xffffffff.

                Note: SHOULD also send IP datagrams if the broadcast bit is not set (not implemented)
                */
                if !request.gateway_ip_address.is_unspecified() {
                    addr = SocketAddr::new(IpAddr::V4(request.gateway_ip_address), UDP_PORT_SERVER)
                }
                if !request.client_ip_address.is_unspecified() {
                    addr = SocketAddr::new(IpAddr::V4(request.client_ip_address), UDP_PORT_CLIENT)
                }

                match request.options.dhcp_message_type {
                    Some(DhcpMessageType::Discover) => {
                        let answer = match self.storage.allocate(
                            request.transaction_identifier,
                            request.options.address_time,
                            request.options.address_request,
                        ) {
                            Ok(offer) => self.message_builder.offer(&request, &offer),
                            _ => panic!("HOLY SHIT"),
                        };

                        println!("Request from {}:\n{}", addr, request);
                        println!("Answer to {}:\n{}", addr, answer);

                        match self.socket.start_send((addr, answer))? {
                            AsyncSink::Ready => continue,
                            AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                        }
                    },
                    Some(DhcpMessageType::Request) => {},
                    Some(DhcpMessageType::Decline) => {},
                    Some(DhcpMessageType::Release) => {},
                    Some(DhcpMessageType::Inform) => {},
                    _ => {},
                }
            }
        }
    }
}