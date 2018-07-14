//! Ack module

use std::net::Ipv4Addr;

#[derive(Debug)]
/// Data required to create a `DHCPACK` message.
/// Is returned by `Storage::assign` method.
pub struct Ack {
    pub address         : Ipv4Addr,
    pub lease_time      : u32,
    pub renewal_time    : u32,
    pub rebinding_time  : u32,
    pub message         : String,
}