//! The main DHCP message module.

use std::{
    fmt,
    io,
    mem,
    net::Ipv4Addr,
};

use bytes::BufMut;
use eui48::{
    MacAddress,
    EUI48LEN,
};

use parser;
use options::{
    Options,
    OptionTag,
    MessageType,
};
use super::constants::*;

/// DHCP message.
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

/// The error type returned by `Message::validate`.
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Validation error")]
    Validation,
}

/// DHCP opcode.
#[derive(Debug, Clone, Copy)]
pub enum OperationCode {
    Undefined,
    BootRequest,
    BootReply,
}

impl From<u8> for OperationCode {
    fn from(value: u8) -> Self {
        use self::OperationCode::*;
        match value {
            1 => BootRequest,
            2 => BootReply,
            _ => Undefined,
        }
    }
}

/// DHCP hardware type.
///
/// Only MAC-48 is implemented.
#[derive(Debug, Clone, Copy)]
pub enum HardwareType {
    Undefined,
    Mac48,
}

impl From<u8> for HardwareType {
    fn from(value: u8) -> Self {
        use self::HardwareType::*;
        match value {
            1 => Mac48,
            _ => Undefined,
        }
    }
}

macro_rules! must_equal (($name:expr, $target:expr) => ( if $target != $name { return Err(Validation); } ));
macro_rules! must_enum_equal (($name:expr, $target:pat) => (if let $target = $name {} else { return Err(Validation); } ));
macro_rules! must_set_option (($name:expr) => ( if $name.is_none() { return Err(Validation); } ));
macro_rules! must_set_ipv4 (($name:expr) => ( if $name.is_unspecified() { return Err(Validation); } ));
macro_rules! must_not_equal (($name:expr, $target:expr) => ( if $target == $name { return Err(Validation); } ));
macro_rules! must_not_enum_equal (($name:expr, $target:pat) => (if let $target = $name { return Err(Validation); } ));
macro_rules! must_not_set_option (($name:expr) => ( if $name.is_some() { return Err(Validation); } ));
macro_rules! must_not_set_ipv4 (($name:expr) => ( if !$name.is_unspecified() { return Err(Validation); } ));

impl Message {
    /// DHCP message deserialization.
    ///
    /// May be changed to `serde::Deserializer` later.
    ///
    /// # Errors
    /// `io::Error` on parsing error.
    pub fn from_bytes(src: &[u8]) -> io::Result<Self> {
        let message = match parser::parse_message(src) {
            Ok((_, message)) => message,
            Err(error) => return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                error.to_string()
            )),
        };

        Ok(message)
    }

    /// DHCP message serialization.
    ///
    /// May be changed to `serde::Serializer` later.
    ///
    /// # Panics
    /// If `dst` is too small, consider at least 1024 bytes.
    pub fn to_bytes(&self, dst: &mut [u8]) -> io::Result<usize> {
        let mut cursor = io::Cursor::new(dst);

        cursor.put_u8(self.operation_code as u8);
        cursor.put_u8(self.hardware_type as u8);
        cursor.put_u8(self.hardware_address_length);
        cursor.put_u8(self.hardware_options);

        cursor.put_u32_be(self.transaction_id);
        cursor.put_u16_be(self.seconds);
        cursor.put_u16_be(if self.is_broadcast {0x0001} else {0x0000});

        cursor.put_u32_be(u32::from(self.client_ip_address));
        cursor.put_u32_be(u32::from(self.your_ip_address));
        cursor.put_u32_be(u32::from(self.server_ip_address));
        cursor.put_u32_be(u32::from(self.gateway_ip_address));

        // 6 byte MAC-48
        cursor.put(self.client_hardware_address.as_bytes());
        // 10 byte padding
        cursor.put(vec![0u8; SIZE_HARDWARE_ADDRESS - self.client_hardware_address.as_bytes().len()]);

        cursor.put(self.server_name.as_bytes());
        // (64 - length) byte padding
        cursor.put(vec![0u8; SIZE_SERVER_NAME - self.server_name.len()]);

        cursor.put(self.boot_filename.as_bytes());
        // (128 - length) byte padding
        cursor.put(vec![0u8; SIZE_BOOT_FILENAME - self.boot_filename.len()]);

        cursor.put(MAGIC_COOKIE);
        if let Some(value) = self.options.subnet_mask {
            cursor.put_u8(OptionTag::SubnetMask as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(u32::from(value));
        }
        if let Some(ref value) = self.options.routers {
            cursor.put_u8(OptionTag::Routers as u8);
            cursor.put_u8((mem::size_of::<u32>() * value.len()) as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.to_owned()));
            }
        }
        if let Some(ref value) = self.options.domain_name_servers {
            cursor.put_u8(OptionTag::DomainServers as u8);
            cursor.put_u8((mem::size_of::<u32>() * value.len()) as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.to_owned()));
            }
        }
        if let Some(ref value) = self.options.static_routes {
            cursor.put_u8(OptionTag::StaticRoutes as u8);
            cursor.put_u8((mem::size_of::<u32>() * value.len() * 2) as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.0.to_owned()));
                cursor.put_u32_be(u32::from(element.1.to_owned()));
            }
        }
        if let Some(value) = self.options.address_request {
            cursor.put_u8(OptionTag::AddressRequest as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(u32::from(value));
        }
        if let Some(value) = self.options.address_time {
            cursor.put_u8(OptionTag::AddressTime as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(value);
        }
        if let Some(value) = self.options.overload {
            cursor.put_u8(OptionTag::Overload as u8);
            cursor.put_u8(mem::size_of::<u8>() as u8);
            cursor.put_u8(value);
        }
        if let Some(value) = self.options.dhcp_message_type {
            cursor.put_u8(OptionTag::DhcpMessageType as u8);
            cursor.put_u8(mem::size_of::<u8>() as u8);
            cursor.put_u8(value as u8);
        }
        if let Some(value) = self.options.dhcp_server_id {
            cursor.put_u8(OptionTag::DhcpServerId as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(u32::from(value));
        }
        if let Some(ref value) = self.options.parameter_list {
            cursor.put_u8(OptionTag::ParameterList as u8);
            cursor.put_u8(value.len() as u8);
            cursor.put(value);
        }
        if let Some(ref value) = self.options.dhcp_message {
            cursor.put_u8(OptionTag::DhcpMessage as u8);
            cursor.put_u8(value.len() as u8);
            cursor.put(value);
        }
        if let Some(value) = self.options.dhcp_max_message_size {
            cursor.put_u8(OptionTag::DhcpMaxMessageSize as u8);
            cursor.put_u8(mem::size_of::<u16>() as u8);
            cursor.put_u16_be(value);
        }
        if let Some(value) = self.options.renewal_time {
            cursor.put_u8(OptionTag::RenewalTime as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(value);
        }
        if let Some(value) = self.options.rebinding_time {
            cursor.put_u8(OptionTag::RebindingTime as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(value);
        }
        if let Some(ref value) = self.options.client_id {
            cursor.put_u8(OptionTag::ClientId as u8);
            cursor.put_u8(value.len() as u8);
            cursor.put(value);
        }
        cursor.put_u8(OptionTag::End as u8);

        Ok(cursor.position() as usize)
    }

    /// DHCP message validation.
    ///
    /// Returns the DHCP message type on successful validation.
    ///
    /// # Errors
    /// Returns `Error::Validation` if any option is invalid.
    pub fn validate(&self) -> Result<MessageType, Error> {
        use Error::Validation;

        must_not_enum_equal!(self.hardware_type, HardwareType::Undefined);
        must_equal!(self.hardware_address_length, EUI48LEN as u8);
        must_equal!(self.hardware_options, 0u8);
        must_not_equal!(self.transaction_id, 0u32);

        must_set_option!(self.options.dhcp_message_type);
        let dhcp_message_type = self.options.dhcp_message_type.unwrap_or(MessageType::Undefined);
        must_not_enum_equal!(dhcp_message_type, MessageType::Undefined);

        match dhcp_message_type {
            // client generated packets section
            MessageType::DhcpDiscover => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest);
                must_not_set_ipv4!(self.client_ip_address);
                must_not_set_ipv4!(self.your_ip_address);
                must_not_set_ipv4!(self.server_ip_address);
                must_not_set_ipv4!(self.gateway_ip_address);
            },
            MessageType::DhcpRequest => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest);
                must_not_set_ipv4!(self.your_ip_address);
                must_not_set_ipv4!(self.server_ip_address);
                must_not_set_ipv4!(self.gateway_ip_address);
            },
            MessageType::DhcpInform => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest);
                must_set_ipv4!(self.client_ip_address);
                must_not_set_ipv4!(self.your_ip_address);
                must_not_set_ipv4!(self.server_ip_address);
                must_not_set_ipv4!(self.gateway_ip_address);

                must_not_set_option!(self.options.address_request);
                must_not_set_option!(self.options.address_time);
                must_not_set_option!(self.options.dhcp_server_id);
            },
            MessageType::DhcpRelease => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest);
                must_set_ipv4!(self.client_ip_address);
                must_not_set_ipv4!(self.your_ip_address);
                must_not_set_ipv4!(self.server_ip_address);
                must_not_set_ipv4!(self.gateway_ip_address);

                must_not_set_option!(self.options.address_request);
                must_not_set_option!(self.options.address_time);
                must_set_option!(self.options.dhcp_server_id);
            },
            MessageType::DhcpDecline => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest);
                must_not_set_ipv4!(self.client_ip_address);
                must_not_set_ipv4!(self.your_ip_address);
                must_not_set_ipv4!(self.server_ip_address);
                must_not_set_ipv4!(self.gateway_ip_address);

                must_set_option!(self.options.address_request);
                must_not_set_option!(self.options.address_time);
                must_set_option!(self.options.dhcp_server_id);
            },

            // server generated packets section
            MessageType::DhcpOffer => {
                must_enum_equal!(self.operation_code, OperationCode::BootReply);
                must_not_set_ipv4!(self.client_ip_address);
                must_set_ipv4!(self.your_ip_address);
                must_set_ipv4!(self.server_ip_address);

                must_not_set_option!(self.options.address_request);
                must_set_option!(self.options.address_time);
                must_set_option!(self.options.dhcp_server_id);
            },
            MessageType::DhcpAck => {
                must_enum_equal!(self.operation_code, OperationCode::BootReply);
                must_set_ipv4!(self.your_ip_address);
                must_set_ipv4!(self.server_ip_address);

                must_not_set_option!(self.options.address_request);
                must_set_option!(self.options.address_time);
                must_set_option!(self.options.dhcp_server_id);
            },
            MessageType::DhcpNak => {
                must_enum_equal!(self.operation_code, OperationCode::BootReply);
                must_not_set_ipv4!(self.client_ip_address);
                must_not_set_ipv4!(self.your_ip_address);
                must_not_set_ipv4!(self.server_ip_address);

                must_not_set_option!(self.options.address_request);
                must_not_set_option!(self.options.dhcp_server_id);
            },
            _ => return Err(Validation),
        }

        Ok(dhcp_message_type)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "_____________________________________________________________________HEADER")?;
        writeln!(f, "operation_code          : {:?}", self.operation_code)?;
        writeln!(f, "hardware_type           : {:?}", self.hardware_type)?;
        writeln!(f, "hardware_address_length : {:?}", self.hardware_address_length)?;
        writeln!(f, "hardware_options        : {:?}", self.hardware_options)?;
        writeln!(f, "transaction_id          : {:?}", self.transaction_id)?;
        writeln!(f, "seconds                 : {:?}", self.seconds)?;
        writeln!(f, "is_broadcast            : {:?}", self.is_broadcast)?;
        writeln!(f, "client_ip_address       : {:?}", self.client_ip_address)?;
        writeln!(f, "your_ip_address         : {:?}", self.your_ip_address)?;
        writeln!(f, "server_ip_address       : {:?}", self.server_ip_address)?;
        writeln!(f, "gateway_ip_address      : {:?}", self.gateway_ip_address)?;
        writeln!(f, "client_hardware_address : {:?}", self.client_hardware_address)?;
        writeln!(f, "server_name             : {}", self.server_name)?;
        writeln!(f, "boot_filename           : {}", self.boot_filename)?;

        writeln!(f, "____________________________________________________________________OPTIONS")?;
        if let Some(ref v) = self.options.subnet_mask           { writeln!(f, "subnet_mask             : {:?}", v)?; }
        if let Some(ref v) = self.options.routers               { writeln!(f, "routers                 : {:?}", v)?; }
        if let Some(ref v) = self.options.domain_name_servers   { writeln!(f, "domain_name_servers     : {:?}", v)?; }
        if let Some(ref v) = self.options.static_routes         { writeln!(f, "static_routes           : {:?}", v)?; }
        if let Some(ref v) = self.options.address_request       { writeln!(f, "address_request         : {:?}", v)?; }
        if let Some(ref v) = self.options.address_time          { writeln!(f, "address_time            : {:?}", v)?; }
        if let Some(ref v) = self.options.overload              { writeln!(f, "overload                : {:?}", v)?; }
        if let Some(ref v) = self.options.dhcp_message_type     { writeln!(f, "dhcp_message_type       : {:?}", v)?; }
        if let Some(ref v) = self.options.dhcp_server_id        { writeln!(f, "dhcp_server_id          : {:?}", v)?; }
        if let Some(ref v) = self.options.parameter_list        { writeln!(f, "parameter_list          : {:?}", v)?; }
        if let Some(ref v) = self.options.dhcp_message          { writeln!(f, "dhcp_message            : {:?}", v)?; }
        if let Some(ref v) = self.options.dhcp_max_message_size { writeln!(f, "dhcp_max_message_size   : {:?}", v)?; }
        if let Some(ref v) = self.options.renewal_time          { writeln!(f, "renewal_time            : {:?}", v)?; }
        if let Some(ref v) = self.options.rebinding_time        { writeln!(f, "rebinding_time          : {:?}", v)?; }
        if let Some(ref v) = self.options.client_id             { writeln!(f, "client_id               : {:?}", v)?; }

        Ok(())
    }
}