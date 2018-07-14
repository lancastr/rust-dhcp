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
use chrono::prelude::*;
use rand;

use protocol;
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
    pub is_broadcast    : bool,

    pub offered_address : Ipv4Addr,
    pub offered_time    : u32,
    pub requested_at    : u32,
    pub renewal_at      : u32,
    pub rebinding_at    : u32,
    pub expired_at      : u32,
}

pub struct OptionalOptions {
    address_request     : Option<Ipv4Addr>,
    address_time        : Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Result {
    your_ip_address     : Ipv4Addr,
    server_ip_address   : Ipv4Addr,
    subnet_mask         : Option<Ipv4Addr>,
    routers             : Option<Vec<Ipv4Addr>>,
    domain_name_servers : Option<Vec<Ipv4Addr>>,
    static_routes       : Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
}

pub struct Client {
    socket              : DhcpFramed,
    message_builder     : MessageBuilder,
    state               : State,
    options             : OptionalOptions,
    result              : Option<Result>,
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
        // required option fields for the message builder
        client_id               : Vec<u8>,

        // optional option fields
        address_request         : Option<Ipv4Addr>,
        address_time            : Option<u32>,
    ) -> io::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), DHCP_PORT_CLIENT);
        let socket = DhcpFramed::new(addr, false, false)?;

        let (destination, is_broadcast) = if let Some(ip) = server_addr {
            (ip, false)
        } else {
            (Ipv4Addr::new(255,255,255,255), true)
        };
        let destination = SocketAddr::new(IpAddr::V4(destination), DHCP_PORT_SERVER);

        let message_builder = MessageBuilder::new(
            client_hardware_address,
            client_id,
        );

        let state = State {
            destination,
            dhcp_state          : DhcpState::Init,
            transaction_id      : rand::random::<u32>(),
            is_broadcast,

            offered_address     : Ipv4Addr::new(0,0,0,0),
            offered_time        : 0u32,
            requested_at        : 0u32,
            renewal_at          : 0u32,
            rebinding_at        : 0u32,
            expired_at          : 0u32,
        };

        let options = OptionalOptions {
            address_request,
            address_time,
        };

        Ok(Client {
            socket,
            message_builder,
            state,
            options,
            result: None,
        })
    }
}

impl Future for Client {
    type Item = Option<Result>;
    type Error = io::Error;

    //
    // unwrap()'s in this code are safe.
    // All the validation is done in the protocol crate.
    //
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if let Async::NotReady = self.socket.poll_complete()? { return Ok(Async::NotReady); }

            match self.state.dhcp_state {
                DhcpState::Init => {
                    let discover = self.message_builder.discover(
                        self.state.transaction_id,
                        self.state.is_broadcast,
                        self.options.address_request,
                        self.options.address_time,
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
                    if let Err(protocol::Error::Validation) = offer.validate() {
                        warn!("The offer is invalid");
                        continue;
                    }
                    if offer.transaction_id != self.state.transaction_id {
                        warn!("Got an offer with different transaction ID: {} (yours is {})", offer.transaction_id, self.state.transaction_id);
                        continue;
                    }

                    self.state.destination = SocketAddr::new(IpAddr::V4(offer.options.dhcp_server_id.unwrap()), DHCP_PORT_SERVER);
                    self.state.offered_address = offer.your_ip_address;
                    self.state.offered_time = offer.options.address_time.unwrap();
                    self.state.requested_at = Utc::now().timestamp() as u32;

                    let request = self.message_builder.request_selecting(
                        self.state.transaction_id,
                        self.state.is_broadcast,
                        self.state.offered_address,
                        Some(self.state.offered_time),
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
                    if let Err(protocol::Error::Validation) = ack.validate() {
                        warn!("The ack is invalid");
                        continue;
                    }
                    if ack.transaction_id != self.state.transaction_id {
                        warn!("Got an ack with different transaction ID: {} (yours is {})", ack.transaction_id, self.state.transaction_id);
                        continue;
                    }

                    self.state.renewal_at = self.state.requested_at + ack.options.renewal_time.unwrap_or(self.state.requested_at);
                    self.state.rebinding_at = self.state.requested_at + ack.options.rebinding_time.unwrap_or(self.state.requested_at);
                    self.state.expired_at = self.state.requested_at + ack.options.address_time.unwrap_or(self.state.requested_at);

                    self.result = Some(Result{
                        your_ip_address     : ack.your_ip_address,
                        server_ip_address   : ack.server_ip_address,
                        subnet_mask         : ack.options.subnet_mask,
                        routers             : ack.options.routers,
                        domain_name_servers : ack.options.domain_name_servers,
                        static_routes       : ack.options.static_routes,
                    });
                    self.state.dhcp_state = DhcpState::Bound;
                },
                DhcpState::Bound => {
                    return Ok(Async::Ready(self.result.to_owned()));
                },
                _ => {},
            }
        }
    }
}