extern crate libc;
#[macro_use]
extern crate nix;

use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::Path;

#[allow(non_camel_case_types)]
pub type caddr_t = *mut libc::c_char;

#[derive(Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ifmap {
    pub mem_start: libc::c_ulong,
    pub mem_end: libc::c_ulong,
    pub base_addr: libc::c_ushort,
    pub irq: libc::c_uchar,
    pub dma: libc::c_uchar,
    pub port: libc::c_uchar,
}

#[derive(Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ifreq_buffer {
    pub length: libc::size_t,
    pub buffer: *mut libc::c_void,
}

#[cfg(any(target_os = "macos"))]
#[derive(Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub union ifreq_inner {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_phys: libc::c_int,
    pub ifru_media: libc::c_int,
    pub ifru_data: caddr_t,
}

#[cfg(any(target_os = "freebsd"))]
#[derive(Copy, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub union ifreq_inner {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_buffer: ifreq_buffer,
    pub ifru_flags: [libc::c_short; 2],
    pub ifru_index: libc::c_short,
    pub ifru_jid: libc::c_int,
    pub ifru_metric: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_phys: libc::c_int,
    pub ifru_media: libc::c_int,
    pub ifru_data: caddr_t,
    pub ifru_cap: [libc::c_int; 2],
    pub ifru_fib: libc::c_uint,
    pub ifru_vlan_pcp: libc::c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct ifreq {
    pub ifr_name: [u8; libc::IFNAMSIZ],
    pub inner: ifreq_inner,
}

impl ifreq {
    pub fn set_name(&mut self, name: &str) -> io::Result<()> {
        let name_c = &CString::new(name.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "malformed interface name"))?;
        let name_slice = name_c.as_bytes_with_nul();
        if name_slice.len() > libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, ""));
        }
        self.ifr_name[..name_slice.len()].clone_from_slice(name_slice);

        Ok(())
    }

    pub fn get_name(&self) -> io::Result<String> {
        let nul_pos = match self.ifr_name.iter().position(|x| *x == 0) {
            Some(p) => p,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed interface name",
                ))
            }
        };

        CString::new(&self.ifr_name[..nul_pos])
            .unwrap()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed interface name"))
    }

    #[cfg(any(target_os = "macos"))]
    pub fn get_ifr_flags(&self) -> i32 {
        unsafe { self.inner.ifru_flags }.into()
    }

    #[cfg(any(target_os = "freebsd"))]
    pub fn get_ifr_flags(&self) -> i32 {
        unsafe { self.inner.ifru_flags[0] }.into()
    }

    #[cfg(any(target_os = "macos"))]
    pub fn set_ifr_flags(&mut self, flags: i32) {
        self.inner.ifru_flags = flags as libc::c_short;
    }

    #[cfg(any(target_os = "freebsd"))]
    pub fn set_ifr_flags(&mut self, flags: i32) {
        unsafe { self.inner.ifru_flags[0] = flags as libc::c_short };
    }
}

pub struct Bpf {
    iface: String,
    file: File,
}

// #define BIOCSETIF	_IOW(B,108, struct ifreq)
ioctl_write_ptr!(bpf_set_interface, b'B', 108, ifreq);

impl Bpf {
    pub fn new(iface: &str) -> io::Result<Bpf> {
        let mut i = 0;
        loop {
            let path_str = format!("/dev/bpf{}", i);
            i += 1;
            let path = Path::new(&path_str);
            if !path.exists() {
                return Err(io::Error::new(io::ErrorKind::NotFound, ""));
            }

            let f = OpenOptions::new().read(true).write(true).open(path);
            if let Err(ref e) = f {
                if let Some(raw_error) = e.raw_os_error() {
                    if raw_error == libc::EBUSY {
                        continue;
                    }
                }
            }

            let file = f?;

            return Ok(Bpf {
                file,
                iface: iface.to_owned(),
            });
        }
    }
}

impl Write for Bpf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Not sure why associate on each read, follow the dnsmasq code
        let mut req: ifreq = unsafe { mem::zeroed() };
        req.set_name(&self.iface)?;

        if let Err(e) = unsafe { bpf_set_interface(self.file.as_raw_fd(), &mut req) } {
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        }

        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Clone for Bpf {
    fn clone(&self) -> Self {
        Bpf {
            iface: self.iface.clone(),
            file: self.file.try_clone().unwrap(),
        }
    }
}
