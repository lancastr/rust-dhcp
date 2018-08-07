#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;
#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod os;
#[cfg(target_os = "freebsd")]
#[path = "freebsd.rs"]
mod os;

extern crate eui48;
extern crate tokio_process;

#[cfg(target_os = "linux")]
extern crate libc;
#[cfg(target_os = "linux")]
#[macro_use]
extern crate nix;

use eui48::MacAddress;
use std::net::Ipv4Addr;
use tokio_process::OutputAsync;

/// The OS-polymorphic OS-error.
#[derive(Debug)]
pub struct Error(os::Error);

impl From<os::Error> for Error {
    fn from(error: os::Error) -> Self {
        Error(error)
    }
}

pub enum Arp {
    Linux(()),
    Windows(OutputAsync),
}

/// The facade function choosing the OS implementation.
pub fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<Arp, Error> {
    Ok(os::add(hwaddr, ip, iface)?)
}
