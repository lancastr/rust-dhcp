//! The original Rust DHCP server implementation.

#[macro_use] mod macros;
mod server;
mod builder;
mod database;
mod storage;
mod storage_ram;
mod lease;

#[macro_use] extern crate log;
extern crate tokio;
extern crate tokio_process;
extern crate futures;
extern crate bytes;
extern crate eui48;
extern crate hostname;
extern crate chrono;
#[macro_use] extern crate failure;

extern crate dhcp_protocol;
extern crate dhcp_framed;
extern crate dhcp_arp;

pub use self::{
    dhcp_server::Server,
    storage::Storage,
    storage_ram::RamStorage,
};