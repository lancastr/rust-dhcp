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
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use eui48::MacAddress;
use tokio::prelude::*;

use dhcp_client::{Client, Command};
use dhcp_framed::{DhcpFramed, DhcpSinkItem, DhcpStreamItem};
use dhcp_protocol::{DHCP_PORT_CLIENT, SIZE_MESSAGE_MINIMAL};

struct SuperClient<I, O>
where
    I: Stream<Item = DhcpStreamItem, Error = io::Error> + Send + Sync,
    O: Sink<SinkItem = DhcpSinkItem, SinkError = io::Error> + Send + Sync,
{
    inner: Client<I, O>,
    counter: u64,
}

impl<I, O> SuperClient<I, O>
where
    I: Stream<Item = DhcpStreamItem, Error = io::Error> + Send + Sync,
    O: Sink<SinkItem = DhcpSinkItem, SinkError = io::Error> + Send + Sync,
{
    pub fn new(client: Client<I, O>) -> Self {
        SuperClient {
            inner: client,
            counter: 0,
        }
    }
}

impl<I, O> Future for SuperClient<I, O>
where
    I: Stream<Item = DhcpStreamItem, Error = io::Error> + Send + Sync,
    O: Sink<SinkItem = DhcpSinkItem, SinkError = io::Error> + Send + Sync,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let result =
                try_ready!(self.inner.poll()).expect("The client returned None but it must not");
            info!("{:?}", result);
            self.counter += 1;
            if self.counter == 5 {
                self.inner.start_send(Command::Release {
                    message: Some("Releasing".to_owned()),
                })?;
                //                self.0.start_send(Command::Decline {
                //                    address: result.your_ip_address,
                //                    message: Some("Releasing".to_owned()),
                //                })?;
                //                self.0.start_send(Command::Inform {
                //                    address: result.your_ip_address,
                //                })?;
                self.inner.poll_complete()?;
                break;
            }
        }
        Ok(Async::Ready(()))
    }
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "client=trace,dhcp_client=trace");
    env_logger::init();

    let (sink, stream) = DhcpFramed::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DHCP_PORT_CLIENT),
        true,
        true,
    ).expect("Socket binding error")
        .split();

    let server_address = Some(Ipv4Addr::new(192, 168, 0, 2));
    let client_address = None;
    let address_request = Some(Ipv4Addr::new(192, 168, 0, 60));
    let address_time = Some(60);
    let max_message_size = Some(SIZE_MESSAGE_MINIMAL as u16);

    let client = SuperClient::new(Client::new(
        stream,
        sink,
        MacAddress::new([0x00, 0x0c, 0x29, 0x13, 0x0e, 0x37]),
        None,
        None,
        server_address,
        client_address,
        address_request,
        address_time,
        max_message_size,
    ));

    let future = client.map_err(|error| error!("Error: {}", error));

    info!("DHCP client started");
    tokio::run(future);
}
