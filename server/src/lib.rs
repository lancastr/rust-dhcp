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
extern crate futures;
extern crate hostname;
extern crate tokio;
#[macro_use]
extern crate failure;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate etherparse;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate eui48;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate futures_cpupool;
#[cfg(target_os = "windows")]
extern crate tokio_process;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
#[macro_use]
extern crate arrayref;

#[cfg(any(target_os = "linux", target_os = "windows"))]
extern crate dhcp_arp;
extern crate dhcp_framed;
extern crate dhcp_protocol;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate ifcontrol;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
extern crate netif_bpf;

pub use self::{
    server::{Server, ServerBuilder},
    storage::Storage,
    storage_ram::RamStorage,
};
