//! Run this with administrator privileges where it is required
//! in order to bind the DHCP server socket to its port 67.

#[macro_use] extern crate log;
extern crate tokio;
extern crate env_logger;

extern crate server;
extern crate protocol;

use std::net::Ipv4Addr;

use tokio::prelude::Future;

use protocol::DHCP_PORT_SERVER;

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "server=trace");
    env_logger::init();

    let server_ip_address = Ipv4Addr::new(192,168,0,2);

    let server = server::Server::new(
        server_ip_address,

        (Ipv4Addr::new(192,168,0,50), Ipv4Addr::new(192,168,0,99)),
        (Ipv4Addr::new(192,168,0,100), Ipv4Addr::new(192,168,0,199)),
        Box::new(server::RamStorage::new()),

        Ipv4Addr::new(255,255,0,0),
        vec![Ipv4Addr::new(192,168,0,1)],
        vec![Ipv4Addr::new(192,168,0,1)],
        vec![],
    ).expect("Server creating error");

    let future = server
        .map_err(|error| error!("Error: {}", error));

    info!("DHCP server started on {}:{}", server_ip_address, DHCP_PORT_SERVER);
    tokio::run(future);
}