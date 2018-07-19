//! A builder for common DHCP client messages.

use std::{
    net::{
        Ipv4Addr,
    },
};

use eui48::{
    MacAddress,
    EUI48LEN,
};

use protocol::*;

/// Builds common client messages with some parameters.
pub struct MessageBuilder {
    /// Mandatory `MAC-48` address.
    client_hardware_address     : MacAddress,
    /// Is set explicitly by user or defaulted to `client_hardware_address` bytes.
    client_id                   : Vec<u8>,
    /// The optional machine hostname.
    hostname                    : Option<String>,
}

pub enum ClientId {
    Mac(MacAddress),
    Custom(Vec<u8>),
}

impl MessageBuilder {
    /// Creates a builder with message parameters which will not be changed.
    pub fn new(
        client_id               : ClientId,
        hostname                : Option<String>,
    ) -> Self {
        let client_hardware_address = match client_id {
            ClientId::Mac(mac) => mac,
            _ => MacAddress::new([0u8; EUI48LEN]),
        };

        let client_id = match client_id {
            ClientId::Custom(id) => id,
            _ => client_hardware_address.as_bytes().to_vec(),
        };

        MessageBuilder {
            client_hardware_address,
            client_id,
            hostname,
        }
    }

    /// Creates a general `DHCPDISCOVER` message.
    pub fn discover(
        &self,
        transaction_id                  : u32,
        is_broadcast                    : bool,
        address_request                 : Option<Ipv4Addr>,
        address_time                    : Option<u32>,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.address_request         = address_request;
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpDiscover);
        options.parameter_list          = Some(Self::parameter_list());
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `SELECTING` state.
    pub fn request_selecting(
        &self,
        transaction_id                  : u32,
        is_broadcast                    : bool,
        address_request                 : Ipv4Addr,
        address_time                    : Option<u32>,
        dhcp_server_id                  : Ipv4Addr,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.address_request         = Some(address_request);
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpRequest);
        options.dhcp_server_id          = Some(dhcp_server_id);
        options.parameter_list          = Some(Self::parameter_list());
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `INIT-REBOOT` state.
    pub fn request_init_reboot(
        &self,
        transaction_id                  : u32,
        is_broadcast                    : bool,
        address_request                 : Ipv4Addr,
        address_time                    : Option<u32>,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.address_request         = Some(address_request);
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpRequest);
        options.parameter_list          = Some(Self::parameter_list());
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `BOUND`, `RENEWING` or `REBINDING` state.
    pub fn request_bound_renewing_rebinding(
        &self,
        transaction_id                  : u32,
        is_broadcast                    : bool,
        client_ip_address               : Ipv4Addr,
        address_time                    : Option<u32>,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpRequest);
        options.parameter_list          = Some(Self::parameter_list());
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast,

            client_ip_address,
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    /// Creates a general `DHCPINFORM` message.
    pub fn inform(
        &self,
        transaction_id                  : u32,
        is_broadcast                    : bool,
        client_ip_address               : Ipv4Addr,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.dhcp_message_type       = Some(MessageType::DhcpInform);
        options.parameter_list          = Some(Self::parameter_list());
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast,

            client_ip_address,
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    /// Creates a general `DHCPRELEASE` message.
    pub fn release(
        &self,
        transaction_id                  : u32,
        client_ip_address               : Ipv4Addr,
        dhcp_server_id                  : Ipv4Addr,
        dhcp_message                    : Option<String>,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.dhcp_message_type       = Some(MessageType::DhcpRelease);
        options.dhcp_server_id          = Some(dhcp_server_id);
        options.dhcp_message            = dhcp_message;
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast                : false,

            client_ip_address,
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    /// Creates a general `DHCPDECLINE` message.
    pub fn decline(
        &self,
        transaction_id                  : u32,
        requested_address               : Ipv4Addr,
        dhcp_server_id                  : Ipv4Addr,
        dhcp_message                    : Option<String>,
    ) -> Message {
        let mut options = Options::new();
        options.hostname                = self.hostname.to_owned();
        options.address_request         = Some(requested_address);
        options.dhcp_message_type       = Some(MessageType::DhcpDecline);
        options.dhcp_server_id          = Some(dhcp_server_id);
        options.dhcp_message            = dhcp_message;
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast                : false,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    fn parameter_list() -> Vec<u8> {
        vec![
            OptionTag::SubnetMask as u8,
            OptionTag::Routers as u8,
            OptionTag::DomainNameServers as u8,
            OptionTag::StaticRoutes as u8,
        ]
    }
}