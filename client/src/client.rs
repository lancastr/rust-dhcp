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
use rand;

use protocol::{self, *};
use framed::*;
use message::MessageBuilder;

#[allow(dead_code)]
pub enum DhcpState {
    // initial state sequence
    Init,
    Selecting,
    Requesting,
    Bound,
    // reboot state sequence
    InitReboot,
    Rebooting,
    // continuous state sequence
    Renewing,
    Rebinding,
}

pub struct State {
    pub destination     : SocketAddr,
    pub dhcp_state      : DhcpState,
    pub transaction_id  : u32,
}

pub struct Client {
    socket              : DhcpFramed,
    message_builder     : MessageBuilder,
    state               : State,
}

impl Client {
    //
    // server_addr:
    //     Some(ip) if you know the DHCP server address
    //     None to use the broadcast address 255.255.255.255
    //
    pub fn new(
        server_addr             : Option<Ipv4Addr>,

        // header fields for the message builder
        client_hardware_address : MacAddress,

        // option fields for the message builder
        client_id               : Vec<u8>,
    ) -> io::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), DHCP_PORT_CLIENT);
        let socket = DhcpFramed::new(addr, false, false)?;

        let destination = SocketAddr::new(IpAddr::V4(if let Some(ip) = server_addr {
            ip
        } else {
            Ipv4Addr::new(255,255,255,255)
        }), DHCP_PORT_SERVER);

        let message_builder = MessageBuilder::new(
            client_hardware_address,

            client_id,
        );

        let state = State {
            destination,
            dhcp_state          : DhcpState::Init,
            transaction_id      : rand::random::<u32>(),
        };

        Ok(Client {
            socket,
            message_builder,
            state,
        })
    }
}

impl Future for Client {
    type Item = Option<(SocketAddr, Message)>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if let Async::NotReady = self.socket.poll_complete()? { return Ok(Async::NotReady); }

            match self.state.dhcp_state {
                DhcpState::Init => {
                    let discover = self.message_builder.discover(
                        self.state.transaction_id,
                        Some(Ipv4Addr::new(192,168,0,13)),
                        Some(604800),
                    );
                    trace!("DhcpDiscover to {}:\n{}", self.state.destination, discover);

                    if let AsyncSink::NotReady(_) = self.socket.start_send((self.state.destination, discover))? {
                        panic!("Must wait for poll_complete first");
                    }
                    self.state.dhcp_state = DhcpState::Selecting;
                },
                DhcpState::Selecting => {
                    let (addr, offer) = if let Some(item) = try_ready!(self.socket.poll()) { item } else { continue };
                    info!("DhcpOffer from {}:\n{}", addr, offer);
                    if let Err(protocol::Error::Validation(description)) = offer.validate() {
                        warn!("The offer is invalid: {}", description.to_string());
                        continue;
                    }

                    self.state.destination = SocketAddr::new(IpAddr::V4(offer.server_ip_address), DHCP_PORT_SERVER);
                    let request = self.message_builder.request_selecting(
                        self.state.transaction_id,
                        Ipv4Addr::new(192,168,0,13),
                        Some(604800),
                        offer.options.dhcp_server_id.unwrap(),
                    );
                    trace!("DhcpRequest to {}:\n{}", self.state.destination, request);

                    if let AsyncSink::NotReady(_) = self.socket.start_send((self.state.destination, request))? {
                        panic!("Must wait for poll_complete first");
                    }
                    self.state.dhcp_state = DhcpState::Requesting;
                },
                DhcpState::Requesting => {
                    let (addr, ack) = if let Some(item) = try_ready!(self.socket.poll()) { item } else { continue };
                    info!("DhcpAck from {}:\n{}", addr, ack);
                    if let Err(protocol::Error::Validation(description)) = ack.validate() {
                        warn!("The ack is invalid: {}", description.to_string());
                        continue;
                    }

                    self.state.dhcp_state = DhcpState::Bound;
                    return Ok(Async::Ready(Some((addr, ack))));
                },
                _ => {},
            }
        }
    }
}