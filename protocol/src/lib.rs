//! DHCP message serializing, deserializing and validating.

extern crate bytes;
extern crate eui48;
#[macro_use] extern crate failure;

mod v4;

pub use self::{
    v4::{
        Message,
        OperationCode,
        HardwareType,
        options::{
            Options,
            OptionTag,
            MessageType,
        },
        constants::*,
    },
};

pub const DHCP_PORT_SERVER: u16 = 67;
pub const DHCP_PORT_CLIENT: u16 = 68;