//! Run this with administrator privileges where it is required
//! in order to bind the DHCP client socket to its port 68.

#[macro_use] extern crate log;
extern crate tokio;
extern crate eui48;
extern crate rand;
extern crate env_logger;

extern crate client;

#[allow(unused_imports)]
use std::net::Ipv4Addr;

use eui48::MacAddress;
use tokio::prelude::*;

use client::{
    Client,
    ClientId,
};

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "client=info");
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    #[allow(unused_variables)]
    let client_id = args.get(1).unwrap_or(&"666".to_owned()).to_owned();

    let client = Client::new(
        ClientId::Mac(MacAddress::new([0x00,0x0c,0x29,0x56,0xab,0xcc])),
        None,
        None,//Some(Ipv4Addr::new(192,168,0,1)),
        None,//Some(Ipv4Addr::new(192,168,0,103)),
        None,//Some(Ipv4Addr::new(192,168,0,15)),
        None,//Some(1000000),
    ).expect("Client creating error");

    info!("DHCP client started");
    for result in client.wait() {
        info!("Result: {:?}", result.unwrap());
        break;
    }
}