//! Run this with administrator privileges where it is required
//! in order to bind the DHCP client socket to its port 68.

#[macro_use] extern crate log;
extern crate tokio;
#[macro_use] extern crate futures;
extern crate eui48;
extern crate rand;
extern crate env_logger;

extern crate client;

#[allow(unused_imports)]
use std::{
    io,
    net::Ipv4Addr,
};

use eui48::MacAddress;
use tokio::prelude::*;

use client::{
    Client,
    ClientId,
};

struct SuperClient(Client);

impl Future for SuperClient {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let result = try_ready!(self.0.poll());
            info!("{:?}", result.expect("The client returned None but it must not"));
        }
    }
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "client=info");
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    #[allow(unused_variables)]
    let client_id = args.get(1).unwrap_or(&"666".to_owned()).to_owned();

    let client = SuperClient(Client::new(
        ClientId::Mac(MacAddress::new([0x00,0x0c,0x29,0x56,0xab,0xcc])),
        None,
        Some(Ipv4Addr::new(192,168,0,100)),
        None,//Some(Ipv4Addr::new(192,168,0,100)),
        None,//Some(Ipv4Addr::new(192,168,0,15)),
        Some(60),//Some(1000000),
    ).expect("Client creating error"));

    let future = client
        .map_err(|error| error!("Error: {}", error));

    info!("DHCP client started");
    tokio::run(future);
}