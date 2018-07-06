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
use eui48::{
    MacAddress,
};

use protocol::*;
use message_builder::MessageBuilder;

enum State {
    Init,
    Selecting,
}

pub struct Client {
    socket:             UdpFramed<Codec>,
    server_addr:        SocketAddr,
    message_builder:    MessageBuilder,
    state:              State,
}

impl Client {
    pub fn new(
        server_addr: Option<Ipv4Addr>,
    ) -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), UDP_PORT_CLIENT);
        let socket = UdpSocket::bind(&addr)?;

        let server_addr = SocketAddr::new(IpAddr::V4(if let Some(ip) = server_addr {
            ip
        } else {
            socket.set_broadcast(true)?;
            Ipv4Addr::new(255,255,255,255)
        }), UDP_PORT_SERVER);

        let socket = UdpFramed::new(socket, Codec);

        let message_builder = MessageBuilder::new(
            &MacAddress::new([0x01,0x02,0x03,0x04,0x05,0x06]),
        );

        Ok(Client {
            socket,
            server_addr,

            message_builder,
            state: State::Init,
        })
    }
}

impl Future for Client {
    type Item = Option<(Message, SocketAddr)>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                State::Init => {
                    let discover = self.message_builder.discover();

                    match self.socket.start_send((discover, self.server_addr)) {
                        Ok(AsyncSink::Ready) => self.state = State::Selecting,
                        Ok(AsyncSink::NotReady(_)) => return Ok(Async::NotReady),
                        Err(error) => return Err(error),
                    }
                },
                State::Selecting => {
                    try_ready!(self.socket.poll_complete());
                    return Ok(Async::Ready(try_ready!(self.socket.poll())))
                },
            }
        }
    }
}