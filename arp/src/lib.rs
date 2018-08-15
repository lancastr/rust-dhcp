//! The OS-polymorphic ARP interface.

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;
#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod os;

extern crate eui48;

#[cfg(target_os = "linux")]
extern crate libc;
#[cfg(target_os = "linux")]
#[macro_use]
extern crate nix;
#[cfg(target_os = "windows")]
extern crate tokio_process;

use eui48::MacAddress;
use std::net::Ipv4Addr;

/// The OS-polymorphic OS-error.
#[derive(Debug)]
pub struct Error(os::Error);

impl From<os::Error> for Error {
    fn from(error: os::Error) -> Self {
        Error(error)
    }
}

#[cfg(target_os = "linux")]
pub type Arp = ();
#[cfg(target_os = "windows")]
pub type Arp = tokio_process::OutputAsync;

/// The facade function choosing the OS implementation.
pub fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<Arp, Error> {
    Ok(os::add(hwaddr, ip, iface)?)
}
