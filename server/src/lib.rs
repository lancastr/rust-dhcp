//! The original Rust DHCP server implementation.

#[macro_use]
mod macros;
mod builder;
mod database;
mod lease;
mod server;
mod storage;
mod storage_ram;

#[macro_use]
extern crate log;
extern crate bytes;
extern crate chrono;
extern crate eui48;
extern crate futures;
extern crate hostname;
extern crate tokio;
extern crate tokio_process;
#[macro_use]
extern crate failure;
extern crate dhcp_framed;
extern crate dhcp_protocol;

#[cfg(any(target_os = "linux", target_os = "windows"))]
extern crate dhcp_arp;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate dhcp_bpf;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate futures_cpupool;

pub use self::{server::Server, storage::Storage, storage_ram::RamStorage};

// #[macro_use]
// extern crate arrayref;
// fn ethernet_packet(
//     src_mac: MacAddress,
//     dst_mac: MacAddress,
//     src: SocketAddrV4,
//     dst: SocketAddrV4,
//     payload: &[u8],
// ) -> Vec<u8> {
//     let builder = PacketBuilder::ethernet2(
//         *array_ref!(src_mac.as_bytes(), 0, 6),
//         *array_ref!(dst_mac.as_bytes(), 0, 6),
//     ).ipv4(src.ip().octets(), dst.ip().octets(), 1) //don't fragment by default
//         .udp(src.port(), dst.port());

//     let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

//     builder.write(&mut result, payload).unwrap();

//     result
// }
