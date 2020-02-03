//! A modified version of `tokio::UdpFramed` socket
//! designed to work with high level DHCP messages.

mod socket;

pub use socket::{
    DhcpFramed, DhcpSinkItem, DhcpStreamItem, BUFFER_READ_CAPACITY, BUFFER_WRITE_CAPACITY,
};
