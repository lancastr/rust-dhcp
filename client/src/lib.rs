//! The original Rust DHCP client implementation.

mod client;
mod message;

#[macro_use] extern crate log;
extern crate tokio;
extern crate futures;
extern crate bytes;
extern crate eui48;
extern crate chrono;
extern crate hostname;
extern crate rand;

extern crate protocol;
extern crate framed;

pub use self::{
    client::{
        Client,
        Result,
    },
    message::ClientId,
};