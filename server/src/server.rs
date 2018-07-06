use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr,
};
use tokio::{
    io,
    net::{
        UdpSocket,
        UdpFramed,
    },
    prelude::*,
};
use hostname;

use protocol::*;
use builder::MessageBuilder;

pub struct Server {
    socket          : UdpFramed<Codec>,
    message_builder : MessageBuilder,
}

impl Server {
    pub fn new() -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 10067);
        let socket = UdpSocket::bind(&addr)?;
        let socket = UdpFramed::new(socket, Codec);

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
            let (message, addr) = match try_ready!(self.socket.poll()) {
                Some((message, addr)) => (message, addr),
                None => continue,
            };

            match message.options.message_type {
                Some(MessageType::Discover) => {
                    let offer = self.message_builder.offer(&message, Ipv4Addr::new(1,2,3,4));

                    println!("{}", message);
                    println!("{}", offer);

                    self.socket.start_send((offer, addr)).into_future().wait();
                    self.socket.poll_complete().into_future().wait();
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