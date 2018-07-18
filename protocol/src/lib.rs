//! DHCP message serializing, deserializing and validating.

extern crate bytes;
extern crate eui48;
#[macro_use] extern crate failure;

mod message;

pub use self::{
    message::{
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