use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr,
};
use tokio::{
    io,
    prelude::*,
};
use eui48::{
    MacAddress,
};

use protocol::*;
use framed::*;
use message_builder::MessageBuilder;

enum State {
    Init,
    Selecting,
}

pub struct Client {
    socket              : DhcpFramed,
    server_addr         : SocketAddr,

    message_builder     : MessageBuilder,
    state               : State,

    pending             : bool,
}

impl Client {
    ///
    /// server_addr:
    ///     Some(ip) if you know the DHCP server address
    ///     None to use broadcast
    ///
    pub fn new(
        server_addr             : Option<Ipv4Addr>,

        client_id               : u32,
        client_hardware_address : MacAddress,
    ) -> io::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), UDP_PORT_CLIENT);
        let socket = DhcpFramed::new(addr)?;

        let server_addr = SocketAddr::new(IpAddr::V4(if let Some(ip) = server_addr {
            ip
        } else {
            Ipv4Addr::new(255,255,255,255)
        }), UDP_PORT_SERVER);

        let message_builder = MessageBuilder::new(
            client_id,
            client_hardware_address,
        );

        Ok(Client {
            socket,
            server_addr,

            message_builder,
            state: State::Init,

            pending: false,
        })
    }
}

impl Future for Client {
    type Item = Option<(Message, SocketAddr)>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if self.pending {
                match self.socket.poll_complete()? {
                    Async::Ready(_) => self.pending = false,
                    Async::NotReady => return Ok(Async::NotReady),
                }
            }

            match self.state {
                State::Init => {
                    let discover = self.message_builder.discover();
                    match self.socket.start_send((self.server_addr, discover))? {
                        AsyncSink::Ready => {
                            self.pending = true;
                            self.state = State::Selecting;
                            continue;
                        },
                        AsyncSink::NotReady(_) => return Ok(Async::NotReady),
                    }
                },
                State::Selecting => {
                    let (offer, addr) = match try_ready!(self.socket.poll()) {
                        Some((offer, addr)) => (offer, addr),
                        None => continue,
                    };

                    return Ok(Async::Ready(Some((addr, offer))));
                },
            }
        }
    }
}