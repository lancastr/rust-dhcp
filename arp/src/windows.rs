use std::{
//    mem,
//    ptr,
    io,
    process::Command,
    net::{
        Ipv4Addr,
    },
};

use eui48::{
    MacAddress,
    MacAddressFormat,
//    EUI48LEN,
};
use winapi::shared::minwindef::{
    INT,
};

#[derive(Debug)]
pub enum Error {
    Process(io::Error),
    Netsh((INT, String)),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Process(error)
    }
}

// DAZN'T VORK SOMEWHY
//
//const MAXLEN_PHYSADDR: usize = 8;
//
//#[repr(C, packed)]
//#[allow(non_camel_case_types)]
//struct MIB_IPNETROW {
//    dw_index: DWORD,
//    dw_phys_addr_len: DWORD,
//    b_phys_addr: [UCHAR; MAXLEN_PHYSADDR],
//    dw_addr: DWORD,
//    dw_type: DWORD,
//}
//
//#[link(name = "iphlpapi")]
//extern "stdcall" {
//    fn CreateIpNetEntry(data: *mut MIB_IPNETROW) -> DWORD;
//}
//
//#[allow(dead_code)]
//enum MibIpnetType {
//    Other = 1,
//    Invalid = 2,
//    Dynamic = 3,
//    Static = 4,
//}

pub(crate) fn add(hwaddr: MacAddress, ip: Ipv4Addr, iface: String) -> Result<(), Error> {
//    DAZN'T VORK SOMEWHY
//    let mut row: MIB_IPNETROW = unsafe { mem::zeroed() };
//    row.dw_index = 3;
//    row.dw_phys_addr_len = EUI48LEN as DWORD;
//    unsafe {
//        ptr::copy_nonoverlapping(
//            hwaddr.as_bytes().as_ptr(),
//            row.b_phys_addr.as_mut_ptr(),
//            EUI48LEN,
//        )
//    };
//    row.dw_addr = u32::from(ip);
//    row.dw_type = MibIpnetType::Dynamic as DWORD;
//
//    let result = unsafe { CreateIpNetEntry(&mut row as *mut MIB_IPNETROW) };
//    if result != NO_ERROR {
//        return Err(Error(result));
//    }

    let netsh = Command::new("netsh")
        .arg("interface")
        .arg("ip")
        .arg("add")
        .arg("neighbors")
        .arg("Ethernet")
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