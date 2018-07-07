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

    pending         : bool,
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

            if let Some((addr, message)) = try_ready!(self.socket.poll()) {
                match message.options.message_type {
                    Some(MessageType::Discover) => {
                        let offer = self.message_builder.offer(&message, Ipv4Addr::new(1,2,3,4));

                        println!("Discover:\n{}", message);
                        println!("Offer:\n{}", offer);

                        match self.socket.start_send((addr, offer))? {
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