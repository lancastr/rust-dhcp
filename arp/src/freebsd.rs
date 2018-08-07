use super::Arp;
use eui48::MacAddress;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum Error {
    Unimplemented,
}

pub(crate) fn add(_hwaddr: MacAddress, _ip: Ipv4Addr, _iface: String) -> Result<Arp, Error> {
    Err(Error::Unimplemented)
}
