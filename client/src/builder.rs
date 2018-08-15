//! A builder for common DHCP client messages.

use std::net::Ipv4Addr;

use eui48::{EUI48LEN, MacAddress};

use dhcp_protocol::*;

/// Builds common client messages with some parameters.
pub struct MessageBuilder {
    /// Mandatory `MAC-48` address.
    client_hardware_address: MacAddress,
    /// Is set explicitly by user or defaulted to `client_hardware_address` bytes.
    client_id: Vec<u8>,
    /// The optional machine hostname.
    hostname: Option<String>,
    /// The optional maximum DHCP message size the client will accept.
    max_message_size: Option<u16>,
}

impl MessageBuilder {
    /// Creates a builder with message parameters which will not be changed.
    pub fn new(
        client_hardware_address: MacAddress,
        client_id: Vec<u8>,
        hostname: Option<String>,
        max_message_size: Option<u16>,
    ) -> Self {
        MessageBuilder {
            client_hardware_address,
            client_id,
            hostname,
            max_message_size,
        }
    }

    /// Creates a general `DHCPDISCOVER` message.
    pub fn discover(
        &self,
        transaction_id: u32,
        is_broadcast: bool,
        address_request: Option<Ipv4Addr>,
        address_time: Option<u32>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpDiscover);
        options.dhcp_max_message_size = self.max_message_size;
        options.parameter_list = Some(Self::parameter_list());
        options.address_request = address_request;
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `SELECTING` state.
    pub fn request_selecting(
        &self,
        transaction_id: u32,
        is_broadcast: bool,
        address_request: Ipv4Addr,
        address_time: Option<u32>,
        dhcp_server_id: Ipv4Addr,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = self.max_message_size;
        options.dhcp_server_id = Some(dhcp_server_id);
        options.parameter_list = Some(Self::parameter_list());
        options.address_request = Some(address_request);
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `INIT-REBOOT` state.
    pub fn request_init_reboot(
        &self,
        transaction_id: u32,
        is_broadcast: bool,
        address_request: Ipv4Addr,
        address_time: Option<u32>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = self.max_message_size;
        options.parameter_list = Some(Self::parameter_list());
        options.address_request = Some(address_request);
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `BOUND`, `RENEWING` or `REBINDING` state.
    pub fn request_renew(
        &self,
        transaction_id: u32,
        is_broadcast: bool,
        client_ip_address: Ipv4Addr,
        address_time: Option<u32>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = self.max_message_size;
        options.parameter_list = Some(Self::parameter_list());
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast,

            client_ip_address,
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a general `DHCPINFORM` message.
    pub fn inform(
        &self,
        transaction_id: u32,
        is_broadcast: bool,
        client_ip_address: Ipv4Addr,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpInform);
        options.dhcp_max_message_size = self.max_message_size;
        options.parameter_list = Some(Self::parameter_list());

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast,

            client_ip_address,
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a general `DHCPRELEASE` message.
    pub fn release(
        &self,
        transaction_id: u32,
        client_ip_address: Ipv4Addr,
        dhcp_server_id: Ipv4Addr,
        dhcp_message: Option<String>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRelease);
        options.dhcp_server_id = Some(dhcp_server_id);
        options.dhcp_message = dhcp_message;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address,
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a general `DHCPDECLINE` message.
    pub fn decline(
        &self,
        transaction_id: u32,
        requested_address: Ipv4Addr,
        dhcp_server_id: Ipv4Addr,
        dhcp_message: Option<String>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpDecline);
        options.dhcp_server_id = Some(dhcp_server_id);
        options.dhcp_message = dhcp_message;
        options.address_request = Some(requested_address);

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    fn append_default_options(&self, options: &mut Options) {
        options.hostname = self.hostname.to_owned();
        options.client_id = Some(self.client_id.to_owned());
    }

    fn parameter_list() -> Vec<u8> {
        vec![
            OptionTag::SubnetMask as u8,
            OptionTag::DomainNameServers as u8,
            /*
            RFC 3442
            DHCP clients that support this option and send a parameter request
            list MAY also request the Static Routes option, for compatibility
            with older servers that don't support Classless Static Routes. The
            Classless Static Routes option code MUST appear in the parameter
            request list prior to both the Router option code and the Static
            Routes option code, if present.
            */
            OptionTag::ClasslessStaticRoutes as u8,
            OptionTag::Routers as u8,
            OptionTag::StaticRoutes as u8,
        ]
    }
}
