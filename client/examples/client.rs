#[macro_use] extern crate log;
extern crate tokio;
extern crate eui48;
extern crate rand;
extern crate env_logger;

extern crate client;

use std::net::Ipv4Addr;

use eui48::MacAddress;
use tokio::prelude::*;

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let client_id = args.get(1).unwrap_or(&"666".to_owned()).to_owned();

    let client = client::Client::new(
        None,//Some(Ipv4Addr::new(192,168,0,12)),
        MacAddress::new([0x01,0x02,0x03,0x04,0x05,0x06]),
        client_id.as_bytes().to_vec(),

        Some(Ipv4Addr::new(192,168,0,15)),
        Some(1000000),
    ).unwrap();

    let future = client
        .map_err(|error| error!("{}", error))
        .map(|result| match result {
            Some(result) => info!("{:?}", result),
            None => {},
        });

    tokio::run(future);
}