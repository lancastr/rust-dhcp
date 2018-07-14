//! Offer module

use std::net::Ipv4Addr;

#[derive(Debug)]
/// Data required to create a `DHCPOFFER` message.
/// Is returned by `Storage::allocate` method.
pub struct Offer {
    pub address     : Ipv4Addr,
    pub lease_time  : u32,
    pub message     : String,
}