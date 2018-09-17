//! BPF features module.
//! Wrap it with conditional compilation attribute only for operating systems supporting it.

use std::{
    io::{self, Write},
    net::Ipv4Addr,
};

use eui48::{EUI48LEN, MacAddress};
use futures_cpupool::CpuPool;
use ifcontrol::{self, Iface};
use netif_bpf::Bpf;

use dhcp_protocol::{Message, DHCP_PORT_CLIENT, DHCP_PORT_SERVER};

const DEFAULT_BPF_NUM_THREADS_SIZE: usize = 4;
const DEFAULT_IP_TTL: u8 = 64;
const DEFAULT_PACKET_BUFFER_SIZE: usize = 8192;

pub struct BpfData {
    /// The BPF object used to send hardware unicasts.
    bpf: Bpf,
    /// The CPU pool used to send hardware unicasts.
    cpu_pool: CpuPool,
    /// The interface MAC address.
    iface_hw_addr: MacAddress,
}

impl BpfData {
    /// Constructs a new BPF object on the specified interface with a CPU pool.
    ///
    /// The CPU pool size is defaulted to `DEFAULT_BPF_NUM_THREADS_SIZE` if not specified.
    ///
    /// # Errors
    /// `io::Error` if there is something wrong with the interface.
    pub fn new(iface_name: &str, bpf_num_threads_size: Option<usize>) -> io::Result<Self> {
        Ok(BpfData {
            bpf: Bpf::new(iface_name)?,
            cpu_pool: CpuPool::new(bpf_num_threads_size.unwrap_or(DEFAULT_BPF_NUM_THREADS_SIZE)),
            iface_hw_addr: {
                let iface = Iface::find_by_name(iface_name).map_err(|error| match error {
                    ifcontrol::IfError::NotFound => {
                        io::Error::new(io::ErrorKind::Other, "Interface not found")
                    }
                    ifcontrol::IfError::Io(error) => error,
                    error => io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to find the interface: {:?}", error),
                    ),
                })?;
                match iface.is_up() {
                    Err(error) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("Failed to check the interface state: {:?}", error),
                        ))
                    }
                    Ok(false) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "The interface is not UP",
                        ))
                    }
                    _ => {}
                };
                iface.hw_addr().ok_or(io::Error::new(
                    io::ErrorKind::Other,
                    "No hardware address on the interface",
                ))?
            },
        })
    }

    /// Sends a DHCP `message` from `source` to `destination` via BPF.
    ///
    /// # Errors
    /// `io::Error` on a message serializing error.
    /// `io::Error` on an Ethernet packet building error.
    pub fn send(
        &mut self,
        source: &Ipv4Addr,
        destination: &Ipv4Addr,
        message: Message,
        max_size: Option<u16>,
    ) -> io::Result<()> {
        trace!("Sending to {} via BPF", destination);

        let mut payload = vec![0u8; DEFAULT_PACKET_BUFFER_SIZE];
        let amount = message.to_bytes(payload.as_mut(), max_size)?;
        let packet = Self::ethernet_packet(
            self.iface_hw_addr.to_owned(),
            message.client_hardware_address.to_owned(),
            source.to_owned(),
            destination.to_owned(),
            &payload[..amount],
        )?;

        let mut bpf = self.bpf.clone();
        self.cpu_pool
            .clone()
            .spawn_fn(move || {
                if let Err(error) = bpf.write_all(&packet) {
                    error!("BPF sending error: {}", error);
                } else {
                    trace!("Response has been sent via BPF");
                }
                Ok::<(), ()>(())
            })
            .forget();

        Ok(())
    }

    /// Constructs a multi-layer DHCP packet for BPF communication.
    fn ethernet_packet(
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        use etherparse::{PacketBuilder, WriteError};

        let builder = PacketBuilder::ethernet2(
            *array_ref!(src_mac.as_bytes(), 0, EUI48LEN),
            *array_ref!(dst_mac.as_bytes(), 0, EUI48LEN),
        ).ipv4(src_ip.octets(), dst_ip.octets(), DEFAULT_IP_TTL)
            .udp(DHCP_PORT_SERVER, DHCP_PORT_CLIENT);

        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        match builder.write(&mut result, payload) {
            Ok(_) => Ok(result),
            Err(WriteError::IoError(error)) => Err(error),
            Err(WriteError::ValueError(error)) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", error)))
            }
        }
    }
}
