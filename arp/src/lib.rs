#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;
#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod os;

#[cfg(target_os = "linux")]
extern crate libc;
#[cfg(target_os = "linux")]
#[macro_use] extern crate nix;

extern crate eui48;

use std::net::Ipv4Addr;
use eui48::MacAddress;

/// The OS-polymorphic OS-error.
#[derive(Debug)]
pub struct Error(os::Error);

impl From<os::Error> for Error {
    fn from(error: os::Error) -> Self {
        Error(error)
    }
}

/// The facade function choosing the OS implementation.
pub fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<(), Error> {
    Ok(os::add(hwaddr, ip, iface)?)
}