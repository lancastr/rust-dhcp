//! Run this with administrator privileges where it is required
//! in order to bind the DHCP client socket to its port 68.

#[macro_use]
extern crate log;
extern crate tokio;
#[macro_use]
extern crate futures;
extern crate env_logger;
extern crate eui48;
extern crate rand;

extern crate dhcp_client;
extern crate dhcp_framed;
extern crate dhcp_protocol;

use std::{
    io, net::{IpAddr, Ipv4Addr, SocketAddr},
};

use eui48::MacAddress;
use tokio::prelude::*;

use dhcp_client::{Client, Command};
use dhcp_framed::DhcpFramed;
use dhcp_protocol::{Message, DHCP_PORT_CLIENT};

struct SuperClient<I, O>(Client<I, O>, u64)
where
    I: Stream<Item = (SocketAddr, Message), Error = io::Error> + Send + Sync,
    O: Sink<SinkItem = (SocketAddr, Message), SinkError = io::Error> + Send + Sync;

impl<I, O> Future for SuperClient<I, O>
where
    I: Stream<Item = (SocketAddr, Message), Error = io::Error> + Send + Sync,
    O: Sink<SinkItem = (SocketAddr, Message), SinkError = io::Error> + Send + Sync,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let result =
                try_ready!(self.0.poll()).expect("The client returned None but it must not");
            info!("{:?}", result);
            self.1 += 1;
            if self.1 == 5 {
                self.0.start_send(Command::Release {
                    message: Some("Releasing".to_owned()),
                })?;
                //                self.0.start_send(Command::Decline {
                //                    address: result.your_ip_address,
                //                    message: Some("Releasing".to_owned()),
                //                })?;
                //                self.0.start_send(Command::Inform {
                //                    address: result.your_ip_address,
                //                })?;
                self.0.poll_complete()?;
                break;
            }
        }
        Ok(Async::Ready(()))
    }
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "client=info");
    env_logger::init();

    let (sink, stream) = DhcpFramed::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DHCP_PORT_CLIENT),
        true,
        true,
    ).expect("Socket binding error")
        .split();

    let server_address = Some(Ipv4Addr::new(192, 168, 0, 4));
    let client_address = None;
    let address_request = None;
    let address_time = Some(60);

    let client = SuperClient(
        Client::new(
            stream,
            sink,
            MacAddress::new([0x00, 0x0c, 0x29, 0x56, 0xab, 0xcc]),
            None,
            None,
            server_address,
            client_address,
            address_request,
            address_time,
        ),
        0,
    );

    let future = client.map_err(|error| error!("Error: {}", error));

    info!("DHCP client started");
    tokio::run(future);
}
