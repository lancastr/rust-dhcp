mod operation_code;
mod hardware_type;
mod options;

use std::{
    fmt,
    string::ToString,
    net::Ipv4Addr,
};
use eui48::{
    MacAddress,
    EUI48LEN,
};

mod constants {
    pub const SIZE_HEADER_REQUIRED: usize       = 240;
    pub const SIZE_HARDWARE_ADDRESS: usize      = 16;
    pub const SIZE_SERVER_NAME: usize           = 64;
    pub const SIZE_BOOT_FILENAME: usize         = 128;

    pub const MAGIC_COOKIE: u32                 = 0x63825363;
}

pub use self::{
    operation_code::OperationCode,
    hardware_type::HardwareType,
    options::{
        Options,
        OptionTag,
        MessageType,
    },
    constants::*,
};

#[allow(dead_code)]
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

#[allow(dead_code)]
impl Message {
    pub fn empty() -> Self {
        Message {
            operation_code              : OperationCode::Undefined,
            hardware_type               : HardwareType::Undefined,
            hardware_address_length     : 0u8,
            hardware_options            : 0u8,

            transaction_identifier      : 0u32,
            seconds                     : 0u16,
            is_broadcast                : false,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : MacAddress::nil(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options                     : Options::new(),
        }
    }

    pub fn discover<>(
        transaction_identifier  : u32,
        client_hardware_address : MacAddress,
        address_time            : Option<u32>,
    ) -> Self {
        let mut options = Options::new();
        options.address_time = address_time;
        options.message_type = Some(MessageType::Discover);

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : true,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address,
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self.hardware_type {
            HardwareType::Undefined => return false,
            _ => (),
        }

        if self.hardware_address_length != EUI48LEN as u8 {
            return false;
        }

        match self.options.message_type {
            None => return false,
            Some(MessageType::Discover) => {
                match self.operation_code {
                    OperationCode::BootRequest => (),
                    _ => return false,
                }
            },
            Some(MessageType::Offer) => {
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

        writeln!(f, "Transaction identifier     : {}", self.transaction_identifier)?;
        writeln!(f, "Seconds                    : {}", self.seconds)?;
        writeln!(f, "Broadcast                  : {}", self.is_broadcast)?;

        writeln!(f, "Client IP address          : {}", self.client_ip_address)?;
        writeln!(f, "Your IP address            : {}", self.your_ip_address)?;
        writeln!(f, "Server IP address          : {}", self.server_ip_address)?;
        writeln!(f, "Gateway IP address         : {}", self.gateway_ip_address)?;

        writeln!(f, "Client hardware adddress   : {}", self.client_hardware_address)?;
        writeln!(f, "Server name                : {}", self.server_name)?;
        writeln!(f, "Boot filename              : {}", self.boot_filename)?;

        writeln!(f, "Magic cookie               : 0x{:x}", MAGIC_COOKIE)?;
        writeln!(f, "Options                    : {:?}", self.options)?;

        Ok(())
    }
}