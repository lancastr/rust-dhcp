//! DHCP protocol message decoding and encoding crate

#![allow(dead_code)]
#![allow(unused_macros)]

extern crate bytes;
#[macro_use] extern crate nom;
extern crate eui48;
#[macro_use] extern crate failure;

mod message;
mod parser;
mod error;
mod operation_code;
mod hardware_type;
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
    message::Message,
    error::Error,
    operation_code::OperationCode,
    hardware_type::HardwareType,
    options::{
        Options,
        OptionTag,
        MessageType,
    },
    constants::*,
};