//! DHCP message type module.

use std::fmt;

/// DHCP message type (RFC 2131 only).
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
    Undefined = 0,
    DhcpDiscover,
    DhcpOffer,
    DhcpRequest,
    DhcpDecline,
    DhcpAck,
    DhcpNak,
    DhcpRelease,
    DhcpInform,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MessageType::*;
        match self {
            DhcpDiscover => write!(f, "DHCPDISCOVER"),
            DhcpOffer => write!(f, "DHCPOFFER"),
            DhcpRequest => write!(f, "DHCPREQUEST"),
            DhcpDecline => write!(f, "DHCPDECLINE"),
            DhcpAck => write!(f, "DHCPACK"),
            DhcpNak => write!(f, "DHCPNAK"),
            DhcpRelease => write!(f, "DHCPRELEASE"),
            DhcpInform => write!(f, "DHCPINFORM"),

            Undefined => write!(f, "UNDEFINED"),
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        use self::MessageType::*;
        match value {
            1 => DhcpDiscover,
            2 => DhcpOffer,
            3 => DhcpRequest,
            4 => DhcpDecline,
            5 => DhcpAck,
            6 => DhcpNak,
            7 => DhcpRelease,
            8 => DhcpInform,

            _ => Undefined,
        }
    }
}
