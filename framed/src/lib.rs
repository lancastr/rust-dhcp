mod socket;

extern crate tokio;
#[macro_use] extern crate futures;
extern crate net2;

extern crate protocol;

mod constants {
    pub const DHCP_PORT_SERVER: u16 = 67 + 10000;
    pub const DHCP_PORT_CLIENT: u16 = 68 + 10000;
}

pub use socket::DhcpFramed;
pub use constants::*;