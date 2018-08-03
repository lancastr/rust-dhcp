use std::{
    io,
    process::Command,
    net::{
        Ipv4Addr,
    },
};

use eui48::{
    MacAddress,
    MacAddressFormat,
};

#[derive(Debug)]
pub enum Error {
    Process(io::Error),
    Netsh((i32, String)),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Process(error)
    }
}

pub(crate) fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<(), Error> {
    let netsh = Command::new("netsh")
        .arg("interface")
        .arg("ip")
        .arg("add")
        .arg("neighbors")
        .arg(iface)
        .arg(ip.to_string())
        .arg(hwaddr.to_string(MacAddressFormat::Canonical))
        .output()?;

    if !netsh.status.success() {
        return Err(Error::Netsh((
            netsh.status.code().unwrap_or_default(),
            String::from_utf8_lossy(&netsh.stdout).trim().to_owned(),
        )));
    }

    Ok(())
}