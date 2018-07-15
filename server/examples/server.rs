#[macro_use] extern crate log;
extern crate tokio;
extern crate env_logger;

extern crate server;

use std::net::Ipv4Addr;

use tokio::prelude::Future;

fn main() {
    env_logger::init();

    let server = server::Server::new(
        Ipv4Addr::new(192,168,0,12),
        Some("The test server".to_owned()),

        Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
        Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        Box::new(server::RamStorage::new()),

        Ipv4Addr::new(255,255,0,0),
        vec![Ipv4Addr::new(192,168,0,1)],
        vec![Ipv4Addr::new(8,8,8,8), Ipv4Addr::new(8,8,4,4)],
        vec![(Ipv4Addr::new(192,168,0,12), Ipv4Addr::new(192,168,0,12))],
    ).expect("Server creating error");

    let future = server
        .map_err(|error| error!("Error: {}", error));

    tokio::run(future);
}