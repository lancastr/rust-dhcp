//! A modified version of `tokio::UdpFramed` socket
//! designed to work with high level DHCP messages.

mod socket;

extern crate tokio;
#[macro_use]
extern crate futures;
extern crate net2;

extern crate dhcp_protocol;

pub use socket::DhcpFramed;
