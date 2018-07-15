//! The original Rust DHCP server implementation.

mod server;
mod message;
mod database;
mod storage;
mod storage_ram;
mod lease;

#[macro_use] extern crate log;
extern crate tokio;
#[macro_use] extern crate futures;
extern crate bytes;
extern crate eui48;
extern crate hostname;
extern crate chrono;
#[macro_use] extern crate failure;

extern crate protocol;
extern crate framed;

pub use self::{
    server::Server,
    storage::Storage,
    storage_ram::RamStorage,
};