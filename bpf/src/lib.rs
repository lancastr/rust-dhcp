extern crate ifreq as _ifreq;
extern crate libc;
#[macro_use]
extern crate nix;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use _ifreq::ifreq;

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
        let mut req = ifreq::from_name(&self.iface)?;

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
