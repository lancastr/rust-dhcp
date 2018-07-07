use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr,
};
use tokio::{
    io,
    prelude::*,
};
use hostname;

use protocol::*;
use framed::DhcpFramed;
use message_builder::MessageBuilder;

pub struct Server {
    socket          : DhcpFramed,
    message_builder : MessageBuilder,
}

impl Server {
    pub fn new() -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 10067);
        let socket = DhcpFramed::new(addr)?;

        let message_builder = MessageBuilder::new(
            &Ipv4Addr::new(192,168,0,12),
            &Ipv4Addr::new(192,168,0,1),
            hostname::get_hostname().unwrap_or_default(),
        );

        Ok(Server {
            socket,
            message_builder,
        })
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            let (addr, message) = match self.socket.poll() {
                Ok(Async::Ready(Some(data))) => data,
                Err(error) => {
                    println!("Error: {}", error);
                    continue;
                },
                _ => continue,
            };

            match message.options.message_type {
                Some(MessageType::Discover) => {
                    let offer = self.message_builder.offer(&message, Ipv4Addr::new(1,2,3,4));

                    println!("Discover:\n{}", message);
                    println!("Offer:\n{}", offer);

                    self.socket.start_send((addr, offer))?;
                },
                Some(MessageType::Request) => continue,
                Some(MessageType::Decline) => continue,
                Some(MessageType::Release) => continue,
                Some(MessageType::Inform) => continue,
                _ => continue,
            }
        }
    }
}