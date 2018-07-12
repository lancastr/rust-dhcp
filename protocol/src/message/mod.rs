mod operation_code;
mod hardware_type;
mod options;

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
        MessageType,
    },
    constants::*,
};

pub struct Message {
    pub operation_code              : OperationCode,
    pub hardware_type               : HardwareType,
    pub hardware_address_length     : u8,
    pub hardware_options            : u8,

    pub transaction_id              : u32,
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
        if let HardwareType::Undefined = self.hardware_type { return false }
        if self.hardware_address_length != EUI48LEN as u8
        || self.hardware_options != 0u8
        || self.seconds != 0u16
        {
            return false;
        }

        match self.options.dhcp_message_type {
            // client generated packets section
            Some(MessageType::DhcpDiscover) => {
                if let OperationCode::BootRequest = self.operation_code {} else { return false }
                if self.transaction_id == 0
                || !self.client_ip_address.is_unspecified()
                || !self.your_ip_address.is_unspecified()
                || !self.server_ip_address.is_unspecified()
                || !self.gateway_ip_address.is_unspecified()

                || self.options.client_id.is_none()
                {
                    return false;
                }
            },

            // server generated packets section
            Some(MessageType::DhcpOffer) => {
                if let OperationCode::BootReply = self.operation_code {} else { return false }
                if self.transaction_id == 0
                || !self.client_ip_address.is_unspecified()
                || self.your_ip_address.is_unspecified()
                || self.server_ip_address.is_unspecified()

                || self.options.address_request.is_some()
                || self.options.address_time.is_none()
                || self.options.dhcp_server_id.is_none()
                || self.options.parameter_list.is_some()
                || self.options.dhcp_max_message_size.is_some()
                || self.options.client_id.is_none()
                {
                    return false;
                }
            },
            Some(MessageType::DhcpAck) => {
                if let OperationCode::BootReply = self.operation_code {} else { return false }
                if self.transaction_id == 0
                || self.your_ip_address.is_unspecified()
                || self.server_ip_address.is_unspecified()

                || self.options.address_request.is_some()
                || self.options.dhcp_server_id.is_none()
                || self.options.parameter_list.is_some()
                || self.options.dhcp_max_message_size.is_some()
                {
                    return false;
                }
            },
            Some(MessageType::DhcpNak) => {
                if let OperationCode::BootReply = self.operation_code {} else { return false }
                if self.transaction_id == 0
                || !self.client_ip_address.is_unspecified()
                || !self.your_ip_address.is_unspecified()
                || !self.server_ip_address.is_unspecified()

                || self.options.address_request.is_some()
                || self.options.address_time.is_some()
                || self.options.dhcp_server_id.is_none()
                || self.options.parameter_list.is_some()
                || self.options.dhcp_max_message_size.is_some()
                {
                    return false;
                }
            },
            _ => return false,
        }

        true
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "_____________________________________________________________________HEADER")?;
        writeln!(f, "operation_code             : {:?}", self.operation_code)?;
        writeln!(f, "hardware_type              : {:?}", self.hardware_type)?;
        writeln!(f, "hardware_address_length    : {:?}", self.hardware_address_length)?;
        writeln!(f, "hardware_options           : {:?}", self.hardware_options)?;
        writeln!(f, "transaction_id (client ID) : {:?}", self.transaction_id)?;
        writeln!(f, "seconds                    : {:?}", self.seconds)?;
        writeln!(f, "is_broadcast               : {:?}", self.is_broadcast)?;
        writeln!(f, "client_ip_address          : {:?}", self.client_ip_address)?;
        writeln!(f, "your_ip_address            : {:?}", self.your_ip_address)?;
        writeln!(f, "server_ip_address          : {:?}", self.server_ip_address)?;
        writeln!(f, "gateway_ip_address         : {:?}", self.gateway_ip_address)?;
        writeln!(f, "client_hardware_address    : {:?}", self.client_hardware_address)?;
        writeln!(f, "server_name                : {}", self.server_name)?;
        writeln!(f, "boot_filename              : {}", self.boot_filename)?;

        writeln!(f, "____________________________________________________________________OPTIONS")?;
        if let Some(ref v) = self.options.subnet_mask               { writeln!(f, "subnet_mask                : {:?}", v)?;}

        if let Some(ref v) = self.options.domain_name_servers       { writeln!(f, "domain_name_servers        : {:?}", v)?;}

        if let Some(ref v) = self.options.static_routes             { writeln!(f, "static_routes              : {:?}", v)?;}

        if let Some(ref v) = self.options.address_request           { writeln!(f, "address_request            : {:?}", v)?;}
        if let Some(ref v) = self.options.address_time              { writeln!(f, "address_time               : {:?}", v)?;}
        if let Some(ref v) = self.options.overload                  { writeln!(f, "overload                   : {:?}", v)?;}
        if let Some(ref v) = self.options.dhcp_message_type         { writeln!(f, "dhcp_message_type          : {:?}", v)?;}
        if let Some(ref v) = self.options.dhcp_server_id            { writeln!(f, "dhcp_server_id             : {:?}", v)?;}
        if let Some(ref v) = self.options.parameter_list            { writeln!(f, "parameter_list             : {:?}", v)?;}
        if let Some(ref v) = self.options.dhcp_message              { writeln!(f, "dhcp_message               : {:?}", v)?;}
        if let Some(ref v) = self.options.dhcp_max_message_size     { writeln!(f, "dhcp_max_message_size      : {:?}", v)?;}

        if let Some(ref v) = self.options.client_id                 { writeln!(f, "client_id                  : {:?}", v)?;}

        Ok(())
    }
}