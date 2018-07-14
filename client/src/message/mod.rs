//! A builder for common DHCP client messages

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
}

impl MessageBuilder {
    /// Creates a builder with message parameters which will not be changed.
    pub fn new(
        client_hardware_address : MacAddress,
        client_id               : Vec<u8>,
    ) -> Self {
        MessageBuilder {
            client_hardware_address,
            client_id,
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
        options.address_request         = address_request;
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpDiscover);
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
        options.address_request         = Some(address_request);
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpRequest);
        options.dhcp_server_id          = Some(dhcp_server_id);
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
        options.address_request         = Some(address_request);
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpRequest);
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
        options.address_time            = address_time;
        options.dhcp_message_type       = Some(MessageType::DhcpRequest);
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
        options.dhcp_message_type       = Some(MessageType::DhcpInform);
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
        options.dhcp_message_type       = Some(MessageType::DhcpRelease);
        options.dhcp_server_id          = Some(dhcp_server_id);
        options.dhcp_message            = dhcp_message;
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
        options.address_request         = Some(requested_address);
        options.dhcp_message_type       = Some(MessageType::DhcpDecline);
        options.dhcp_server_id          = Some(dhcp_server_id);
        options.dhcp_message            = dhcp_message;
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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
}