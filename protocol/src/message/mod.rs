mod operation_code;
mod hardware_type;
mod options;

pub mod parser;

use std::{
    fmt,
    net::Ipv4Addr,
};

use eui48::{
    MacAddress,
    EUI48LEN,
};

mod constants {
    pub const SIZE_FLAGS: usize                 = 16;
    pub const SIZE_HARDWARE_ADDRESS: usize      = 16;
    pub const SIZE_SERVER_NAME: usize           = 64;
    pub const SIZE_BOOT_FILENAME: usize         = 128;

    pub const FLAG_BROADCAST: u16               = 0x0001;

    pub const MAGIC_COOKIE: &'static [u8]       = &[0x63, 0x82, 0x53, 0x63];
}

pub use self::{
    operation_code::OperationCode,
    hardware_type::HardwareType,
    options::{
        Options,
        OptionTag,
        DhcpMessageType,
    },
    constants::*,
};

pub struct Message {
    pub operation_code              : OperationCode,
    pub hardware_type               : HardwareType,
    pub hardware_address_length     : u8,
    pub hardware_options            : u8,

    pub transaction_identifier      : u32,
    pub seconds                     : u16,
    pub is_broadcast                : bool,

    pub client_ip_address           : Ipv4Addr,
    pub your_ip_address             : Ipv4Addr,
    pub server_ip_address           : Ipv4Addr,
    pub gateway_ip_address          : Ipv4Addr,

    pub client_hardware_address     : MacAddress,
    pub server_name                 : String,
    pub boot_filename               : String,

    pub options                     : Options,
}

impl Message {
    pub fn is_valid(&self) -> bool {
        match self.hardware_type {
            HardwareType::Undefined => return false,
            _ => (),
        }

        if self.hardware_address_length != EUI48LEN as u8 {
            return false;
        }

        match self.options.dhcp_message_type {
            None => return false,
            Some(DhcpMessageType::Discover) => {
                match self.operation_code {
                    OperationCode::BootRequest => (),
                    _ => return false,
                }
            },
            Some(DhcpMessageType::Offer) => {
                match self.operation_code {
                    OperationCode::BootReply => (),
                    _ => return false,
                }
            },
            _ => return false,
        }

        true
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Operation code             : {:?}", self.operation_code)?;
        writeln!(f, "Hardware type              : {:?}", self.hardware_type)?;
        writeln!(f, "Hardware address length    : {}", self.hardware_address_length)?;
        writeln!(f, "Hardware options           : {}", self.hardware_options)?;

        writeln!(f, "Transaction ID (client ID) : {}", self.transaction_identifier)?;
        writeln!(f, "Seconds                    : {}", self.seconds)?;
        writeln!(f, "Broadcast                  : {}", self.is_broadcast)?;

        writeln!(f, "Client IP address          : {}", self.client_ip_address)?;
        writeln!(f, "Your IP address            : {}", self.your_ip_address)?;
        writeln!(f, "Server IP address          : {}", self.server_ip_address)?;
        writeln!(f, "Gateway IP address         : {}", self.gateway_ip_address)?;

        writeln!(f, "Client hardware adddress   : {}", self.client_hardware_address)?;
        writeln!(f, "Server name                : {}", self.server_name)?;
        writeln!(f, "Boot filename              : {}", self.boot_filename)?;

        writeln!(f, "Options                    : {:?}", self.options)?;

        Ok(())
    }
}