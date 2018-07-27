//! DHCP message validation module.

use super::{
    Message,
    options::MessageType,
};

/// The error type returned by `Message::validate`.
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Validation error: {}", _0)]
    Validation(&'static str),
}

macro_rules! must_set_option (
    ($name:expr, $error:expr) => ( if $name.is_none() { return Err(Error::Validation($error)); } );
);

impl Message {
    /// DHCP message validation.
    ///
    /// Returns the DHCP message type on successful validation.
    ///
    /// # Errors
    /// Returns `Error::Validation` if any option is invalid.
    pub fn validate(&self) -> Result<MessageType, Error> {
        let dhcp_message_type = match self.options.dhcp_message_type {
            Some(MessageType::Undefined) | None => return Err(Error::Validation("dhcp_message_type")),
            Some(dhcp_message_type) => dhcp_message_type,
        };

        match dhcp_message_type {
            // client generated packets section
            MessageType::DhcpDiscover => {},
            MessageType::DhcpRequest => {
                if self.options.dhcp_server_id.is_some() {
                    must_set_option!(self.options.address_request, "address_request");
                }
                if self.client_ip_address.is_unspecified() {
                    must_set_option!(self.options.address_request, "address_request");
                }
            },
            MessageType::DhcpInform => {},
            MessageType::DhcpRelease => {
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
            },
            MessageType::DhcpDecline => {
                must_set_option!(self.options.address_request, "address_request");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
            },

            // server generated packets section
            MessageType::DhcpOffer => {
                must_set_option!(self.options.address_time, "address_time");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
            },
            MessageType::DhcpAck => {
                must_set_option!(self.options.address_time, "address_time");
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
            },
            MessageType::DhcpNak => {
                must_set_option!(self.options.dhcp_server_id, "dhcp_server_id");
            },
            _ => return Err(Error::Validation("Unknown DHCP message type")),
        }

        Ok(dhcp_message_type)
    }
}