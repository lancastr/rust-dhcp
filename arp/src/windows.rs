use std::{io, net::Ipv4Addr, process::Command};

use eui48::{MacAddress, MacAddressFormat};
use tokio_process::CommandExt;

use super::Arp;

#[derive(Debug)]
pub enum Error {
    Process(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Process(error)
    }
}

pub(crate) fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<Arp, Error> {
    Ok(Arp::Windows(
        Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("add")
            .arg("neighbors")
            .arg(iface)
            .arg(ip.to_string())
            .arg(hwaddr.to_string(MacAddressFormat::Canonical))
            .output_async(),
    ))
}
