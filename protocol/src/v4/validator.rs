//! DHCP message validation module.

use super::{constants::SIZE_MESSAGE_MINIMAL, options::MessageType, Message};

/// The error type returned by `Message::validate`.
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Validation error: {}", _0)]
    Validation(&'static str),
}

/// Checks if required options are present for each message type.
macro_rules! must_set_option (
    ($name:expr) => (
        if $name.is_none() {
            return Err(Error::Validation(stringify!($name)));
        }
    );
);

impl Message {
    /// DHCP message validation.
    ///
    /// Returns the DHCP message type on successful validation.
    ///
    /// # Errors
    /// Returns `Error::Validation` if any option is invalid.
    pub fn validate(&self) -> Result<MessageType, Error> {
        let message = self; // for the stringify! macro above

        let dhcp_message_type = match message.options.dhcp_message_type {
            None | Some(MessageType::Undefined) => {
                return Err(Error::Validation("DHCP message type is absent or zero"));
            }
            Some(dhcp_message_type) => dhcp_message_type,
        };

        if let Some(dhcp_max_message_size) = message.options.dhcp_max_message_size {
            if (dhcp_max_message_size as usize) < SIZE_MESSAGE_MINIMAL {
                return Err(Error::Validation("DHCP maximal message size is too low"));
            }
        }

        match dhcp_message_type {
            // client generated packets section
            MessageType::DhcpDiscover => {}
            MessageType::DhcpRequest => if message.client_ip_address.is_unspecified()
                || message.options.dhcp_server_id.is_some()
            {
                must_set_option!(message.options.address_request);
            },
            MessageType::DhcpInform => {}
            MessageType::DhcpRelease => {
                must_set_option!(message.options.dhcp_server_id);
            }
            MessageType::DhcpDecline => {
                must_set_option!(message.options.address_request);
                must_set_option!(message.options.dhcp_server_id);
            }

            // server generated packets section
            MessageType::DhcpOffer => {
                must_set_option!(message.options.address_time);
                must_set_option!(message.options.dhcp_server_id);
            }
            MessageType::DhcpAck => {
                must_set_option!(message.options.address_time);
                must_set_option!(message.options.dhcp_server_id);
            }
            MessageType::DhcpNak => {
                must_set_option!(message.options.dhcp_server_id);
            }

            _ => return Err(Error::Validation("Unknown DHCP message type")),
        }

        Ok(dhcp_message_type)
    }
}
