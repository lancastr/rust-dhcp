//! Run this with administrator privileges where it is required
//! in order to bind the DHCP server socket to its port 67 or use other OS-specific features.

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tokio;

extern crate dhcp_protocol;
extern crate dhcp_server;

use std::net::Ipv4Addr;

use tokio::prelude::Future;

use dhcp_protocol::DHCP_PORT_SERVER;

fn main() {
    std::env::set_var("RUST_BACKTRACE", "full");
    std::env::set_var("RUST_LOG", "server=trace,dhcp_server=trace");
    env_logger::init();

    let server_ip_address = Ipv4Addr::new(192, 168, 0, 2);
    let iface_name = "Ethernet".to_string();

    #[allow(unused_mut)]
    let mut builder = dhcp_server::ServerBuilder::new(
        server_ip_address,
        iface_name,
        (
            Ipv4Addr::new(192, 168, 0, 50),
            Ipv4Addr::new(192, 168, 0, 99),
        ),
        (
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 199),
        ),
        dhcp_server::RamStorage::new(),
        Ipv4Addr::new(255, 255, 0, 0),
        vec![],
        vec![Ipv4Addr::new(192, 168, 0, 1)],
        vec![],
        vec![
            (Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(0,0,0,0), Ipv4Addr::new(192,168,0,1)),
            (Ipv4Addr::new(10,0,0,0), Ipv4Addr::new(255,0,0,0), Ipv4Addr::new(192,168,0,1)),
            (Ipv4Addr::new(10,0,0,0), Ipv4Addr::new(255,255,255,0), Ipv4Addr::new(192,168,0,1)),
            (Ipv4Addr::new(10,17,0,0), Ipv4Addr::new(255,255,0,0), Ipv4Addr::new(192,168,0,1)),
            (Ipv4Addr::new(10,27,129,0), Ipv4Addr::new(255,255,255,0), Ipv4Addr::new(192,168,0,1)),
            (Ipv4Addr::new(10,229,0,128), Ipv4Addr::new(255,255,255,128), Ipv4Addr::new(192,168,0,1)),
            (Ipv4Addr::new(10,198,122,47), Ipv4Addr::new(255,255,255,255), Ipv4Addr::new(192,168,0,1)),
        ],
    );
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        builder.with_bpf_num_threads(8);
    }
    let server = builder.finish().expect("Server creating error");

    let future = server.map_err(|error| error!("Error: {}", error));

    info!(
        "DHCP server started on {}:{}",
        server_ip_address, DHCP_PORT_SERVER
    );
    tokio::run(future);
}
