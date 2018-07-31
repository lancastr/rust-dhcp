mod linux;

extern crate libc;
#[macro_use] extern crate nix;
extern crate eui48;

use std::net::Ipv4Addr;
use eui48::MacAddress;

#[derive(Debug)]
pub enum Error {
    Linux(linux::Error),
}

impl From<linux::Error> for Error {
    fn from(error: linux::Error) -> Self {
        Error::Linux(error)
    }
}

/// The facade function choosing the OS implementation.
pub fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<(), Error> {
    Ok(linux::add(hwaddr, ip, iface)?)
}