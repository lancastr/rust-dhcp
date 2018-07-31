use std::{
    ptr,
    mem,
    net::{
        SocketAddr,
        IpAddr,
        Ipv4Addr,
    },
};

use libc::{
    self,
    arpreq,
    c_char,
    c_int,
};
use nix::{
    self,
    sys::{
        socket::{
            self,
            AddressFamily,
            SockType,
            SockFlag,
        }
    }
};
use eui48::{
    MacAddress,
    EUI48LEN,
};

ioctl_write_ptr_bad!(siocsarp, libc::SIOCSARP, arpreq);

#[derive(Debug)]
pub enum Error {
    Socket(nix::Error),
    Syscall(nix::Error),
}

const AF_INET: u16 = 0x02;
const ARPHRD_ETHER: u16 = 0x01;
const ATF_COM: c_int = 0x02;

pub(crate) fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<(), Error> {
    let mut req: arpreq = unsafe { mem::zeroed() };

    let addr = SocketAddr::new(IpAddr::V4(ip), 0);
    req.arp_pa = unsafe {
        *socket::SockAddr::Inet(socket::InetAddr::from_std(&addr)).as_ffi_pair().0
    };

    req.arp_ha.sa_family = ARPHRD_ETHER;
    unsafe {
        ptr::copy_nonoverlapping(
            hwaddr.as_bytes().as_ptr() as *const c_char,
            req.arp_ha.sa_data.as_mut_ptr(),
            EUI48LEN,
        )
    };

    req.arp_flags = ATF_COM;

    req.arp_netmask.sa_family = AF_INET;

    let iface_len = iface.len();
    unsafe {
        ptr::copy_nonoverlapping(
            iface.as_ptr() as *const c_char,
            req.arp_dev.as_mut_ptr(),
            iface_len,
        )
    };

    let fd = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ).map_err(|error| Error::Socket(error))?;

    unsafe { siocsarp(fd, &req) }
        .map_err(|error| Error::Syscall(error))?;

    Ok(())
}