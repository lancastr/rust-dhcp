//! The Windows implementation using `netsh` subprocess.

use std::{io, net::Ipv4Addr, process::Command};

use eui48::{MacAddress, MacAddressFormat};
use tokio_process::CommandExt;

#[derive(Debug)]
pub enum Error {
    Process(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Process(error)
    }
}

pub(crate) fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<super::Arp, Error> {
    Ok((
        Some(
            Command::new("netsh")
                .arg("interface")
                .arg("ip")
                .arg("delete")
                .arg("neighbors")
                .arg(iface.to_owned())
                .output_async(),
        ),
        Some(
            Command::new("netsh")
                .arg("interface")
                .arg("ip")
                .arg("add")
                .arg("neighbors")
                .arg(iface.to_owned())
                .arg(ip.to_string())
                .arg(hwaddr.to_string(MacAddressFormat::Canonical))
                .output_async(),
        ),
    ))
}
