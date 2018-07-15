//! DHCP protocol message decoding and encoding crate.

extern crate bytes;
#[macro_use] extern crate nom;
extern crate eui48;
#[macro_use] extern crate failure;

mod message;
mod parser;
mod options;

mod constants {
    pub const SIZE_FLAGS: usize                 = 16;
    pub const SIZE_HARDWARE_ADDRESS: usize      = 16;
    pub const SIZE_SERVER_NAME: usize           = 64;
    pub const SIZE_BOOT_FILENAME: usize         = 128;
    pub const FLAG_BROADCAST: u16               = 0x0001;
    pub const MAGIC_COOKIE: &'static [u8]       = &[0x63, 0x82, 0x53, 0x63];
}

pub use self::{
    message::{
        Message,
        OperationCode,
        HardwareType,
        Error,
    },
    options::{
        Options,
        OptionTag,
        MessageType,
    },
    constants::*,
};