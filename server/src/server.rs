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

    pending                 : bool,
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

        dynamic_address_range   : Range<Ipv4Addr>,

        subnet_mask             : Ipv4Addr,
    ) -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), UDP_PORT_SERVER);
        let socket = DhcpFramed::new(addr)?;

        let message_builder = MessageBuilder::new(
            server_ip_address,
            gateway_ip_address,
            server_name.unwrap_or(hostname::get_hostname().unwrap_or_default()),

            subnet_mask,
        );

        let storage = Storage::new(dynamic_address_range);

        Ok(Server {
            socket,
            message_builder,
            storage,

            pending: false,
        })
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            if self.pending {
                match self.socket.poll_complete()? {
                    Async::Ready(_) => self.pending = false,
                    Async::NotReady => return Ok(Async::NotReady),
                }
            }

            if let Some((mut addr, request)) = try_ready!(self.socket.poll()) {
                // RFC 2131 §4.1
                // SHOULD also be able to send IP datagrams if the broadcast bit is not set (not implemented)
                if !request.gateway_ip_address.is_unspecified() {
                    addr = SocketAddr::new(IpAddr::V4(request.gateway_ip_address), UDP_PORT_SERVER)
                }
                if !request.client_ip_address.is_unspecified() {
                    addr = SocketAddr::new(IpAddr::V4(request.client_ip_address), UDP_PORT_CLIENT)
                }

                match request.options.message_type {
                    Some(MessageType::Discover) => {
                        let your_ip_address = self.storage.allocate(
                            request.transaction_identifier,
                            request.options.address_time,
                            request.options.address_request,
                        ).unwrap(); // TODO handle error
                        let answer = self.message_builder.offer(
                            &request,
                            your_ip_address,
                        );

                        println!("Request from {}:\n{}", addr, request);
                        println!("Answer to {}:\n{}", addr, answer);

                        match self.socket.start_send((addr, answer))? {
                            AsyncSink::Ready => {
                                self.pending = true;
                                continue;
                            },
                            AsyncSink::NotReady(_) => return Ok(Async::NotReady),
                        }
                    },
                    Some(MessageType::Request) => {},
                    Some(MessageType::Decline) => {},
                    Some(MessageType::Release) => {},
                    Some(MessageType::Inform) => {},
                    _ => {},
                }
            }
        }
    }
}