//! Just adds an ARP entry.

extern crate dhcp_arp;
extern crate eui48;

use std::net::Ipv4Addr;

fn main() {
    let result = dhcp_arp::add(
        eui48::MacAddress::new([0x00, 0xe0, 0x4c, 0x60, 0x71, 0x6a]),
        Ipv4Addr::new(192, 168, 0, 100),
        "ens33".to_string(),
    );
    println!("{:?}", result);
}
