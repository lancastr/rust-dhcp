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

extern crate dhcp_arp;
extern crate dhcp_framed;
extern crate dhcp_protocol;

pub use self::{dhcp_server::Server, storage::Storage, storage_ram::RamStorage};
