//! DHCP message validation module.

use eui48::EUI48LEN;

use message::{
    Message,
    options::MessageType,
    operation_code::OperationCode,
    hardware_type::HardwareType,
};

/// The error type returned by `Message::validate`.
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Validation error: {}", _0)]
    Validation(&'static str),
}

use self::Error::Validation;

macro_rules! must_equal (
    ($name:expr, $target:expr, $error:expr) => ( if $target != $name { return Err(Validation($error)); } )
);
macro_rules! must_enum_equal (
    ($name:expr, $target:pat, $error:expr) => (if let $target = $name {} else { return Err(Validation($error)); } )
);
macro_rules! must_set_option (
    ($name:expr, $error:expr) => ( if $name.is_none() { return Err(Validation($error)); } )
);
macro_rules! must_set_ipv4 (
    ($name:expr, $error:expr) => ( if $name.is_unspecified() { return Err(Validation($error)); } )
);
macro_rules! must_not_equal (
    ($name:expr, $target:expr, $error:expr) => ( if $target == $name { return Err(Validation($error)); } )
);
macro_rules! must_not_enum_equal (
    ($name:expr, $target:pat, $error:expr) => (if let $target = $name { return Err(Validation($error)); } )
);
macro_rules! must_not_set_option (
    ($name:expr, $error:expr) => ( if $name.is_some() { return Err(Validation($error)); } )
);
macro_rules! must_not_set_ipv4 (
    ($name:expr, $error:expr) => ( if !$name.is_unspecified() { return Err(Validation($error)); } )
);

impl Message {
    /// DHCP message validation.
    ///
    /// Returns the DHCP message type on successful validation.
    ///
    /// # Errors
    /// Returns `Error::Validation` if any option is invalid.
    pub fn validate(&self) -> Result<MessageType, Error> {
        must_not_enum_equal!(self.hardware_type, HardwareType::Undefined, "hardware_type");
        must_equal!(self.hardware_address_length, EUI48LEN as u8, "hardware_address_length");
        must_equal!(self.hardware_options, 0u8, "hardware_options");
        must_not_equal!(self.transaction_id, 0u32, "transaction_id");

        must_set_option!(self.options.dhcp_message_type, "dhcp_message_type");
        let dhcp_message_type = self.options.dhcp_message_type.unwrap_or(MessageType::Undefined);
        must_not_enum_equal!(dhcp_message_type, MessageType::Undefined, "dhcp_message_type");

        match dhcp_message_type {
            // client generated packets section
            MessageType::DhcpDiscover => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest, "operation_code");
                must_not_set_ipv4!(self.client_ip_address, "client_ip_address");
                must_not_set_ipv4!(self.your_ip_address, "your_ip_address");
                must_not_set_ipv4!(self.server_ip_address, "server_ip_address");
                must_not_set_ipv4!(self.gateway_ip_address, "gateway_ip_address");
            },
            MessageType::DhcpRequest => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest, "operation_code");
                must_not_set_ipv4!(self.your_ip_address, "your_ip_address");
                must_not_set_ipv4!(self.server_ip_address, "server_ip_address");
                must_not_set_ipv4!(self.gateway_ip_address, "gateway_ip_address");
                if self.options.dhcp_server_id.is_some() {
                    must_set_option!(self.options.address_request, "address_request");
                }
                if self.client_ip_address.is_unspecified() {
                    must_set_option!(self.options.address_request, "address_request");
                }
            },
            MessageType::DhcpInform => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest, "operation_code");
                must_set_ipv4!(self.client_ip_address, "client_ip_address");
                must_not_set_ipv4!(self.your_ip_address, "your_ip_address");
                must_not_set_ipv4!(self.server_ip_address, "server_ip_address");
                must_not_set_ipv4!(self.gateway_ip_address, "gateway_ip_address");

                must_not_set_option!(self.options.address_request, "address_request");
                must_not_set_option!(self.options.address_time, "address_time");
                must_not_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
            },
            MessageType::DhcpRelease => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest, "operation_code");
                must_set_ipv4!(self.client_ip_address, "client_ip_address");
                must_not_set_ipv4!(self.your_ip_address, "your_ip_address");
                must_not_set_ipv4!(self.server_ip_address, "server_ip_address");
                must_not_set_ipv4!(self.gateway_ip_address, "gateway_ip_address");

                must_not_set_option!(self.options.address_request, "address_request");
                must_not_set_option!(self.options.address_time, "address_time");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
                must_not_set_option!(self.options.parameter_list, "parameter_list");
            },
            MessageType::DhcpDecline => {
                must_enum_equal!(self.operation_code, OperationCode::BootRequest, "operation_code");
                must_not_set_ipv4!(self.client_ip_address, "client_ip_address");
                must_not_set_ipv4!(self.your_ip_address, "your_ip_address");
                must_not_set_ipv4!(self.server_ip_address, "server_ip_address");
                must_not_set_ipv4!(self.gateway_ip_address, "gateway_ip_address");

                must_set_option!(self.options.address_request, "address_request");
                must_not_set_option!(self.options.address_time, "address_time");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
                must_not_set_option!(self.options.parameter_list, "parameter_list");
            },

            // server generated packets section
            MessageType::DhcpOffer => {
                must_enum_equal!(self.operation_code, OperationCode::BootReply, "operation_code");
                must_not_set_ipv4!(self.client_ip_address, "client_ip_address");
                must_set_ipv4!(self.your_ip_address, "your_ip_address");

                must_not_set_option!(self.options.address_request, "address_request");
                must_set_option!(self.options.address_time, "address_time");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
                must_not_set_option!(self.options.parameter_list, "parameter_list");
            },
            MessageType::DhcpAck => {
                must_enum_equal!(self.operation_code, OperationCode::BootReply, "operation_code");
                must_set_ipv4!(self.your_ip_address, "your_ip_address");

                must_not_set_option!(self.options.address_request, "address_request");
                must_set_option!(self.options.address_time, "address_time");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
                must_not_set_option!(self.options.parameter_list, "parameter_list");
            },
            MessageType::DhcpNak => {
                must_enum_equal!(self.operation_code, OperationCode::BootReply, "operation_code");
                must_not_set_ipv4!(self.client_ip_address, "client_ip_address");
                must_not_set_ipv4!(self.your_ip_address, "your_ip_address");
                must_not_set_ipv4!(self.server_ip_address, "server_ip_address");

                must_not_set_option!(self.options.address_request, "address_request");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
                must_not_set_option!(self.options.parameter_list, "parameter_list");
            },
            _ => return Err(Validation("Unknown DHCP message type")),
        }

        Ok(dhcp_message_type)
    }
}