extern crate tokio;

extern crate server;

use std::net::Ipv4Addr;
use tokio::prelude::Future;

fn main() {
    tokio::run(
        server::Server::new(
            Ipv4Addr::new(192,168,0,12),
            Ipv4Addr::new(192,168,0,1),
            Some("The test server".to_owned()),
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
            Ipv4Addr::new(255,255,0,0),
        )
            .unwrap()
            .map_err(|error| println!("Server error: {:?}", error))
    );
}