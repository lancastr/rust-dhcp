//! DHCP message type module.

use std::fmt;

/// DHCP message type (RFC 2131 only).
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
    Undefined = 0,
    // RFC 2131
    DhcpDiscover,
    DhcpOffer,
    DhcpRequest,
    DhcpDecline,
    DhcpAck,
    DhcpNak,
    DhcpRelease,
    DhcpInform,
    // RFC 3203 (not implemented)
//    DhcpForceRenew,
    // RFC 4388 (not implemented)
//    DhcpLeaseQuery,
//    DhcpLeaseUnassigned,
//    DhcpLeaseUnknown,
//    DhcpLeaseActive,
    // RFC 6926 (not implemented)
//    DhcpBulkLeaseQuery,
//    DhcpLeaseQueryDone,
    // RFC 7724 (not implemented)
//    DhcpActiveLeaseQuery,
//    DhcpLeaseQueryStatus,
//    DhcpTls,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MessageType::*;
        match self {
            Undefined => write!(f, "UNDEFINED"),
            DhcpDiscover => write!(f, "DHCPDISCOVER"),
            DhcpOffer => write!(f, "DHCPOFFER"),
            DhcpRequest => write!(f, "DHCPREQUEST"),
            DhcpDecline => write!(f, "DHCPDECLINE"),
            DhcpAck => write!(f, "DHCPACK"),
            DhcpNak => write!(f, "DHCPNAK"),
            DhcpRelease => write!(f, "DHCPRELEASE"),
            DhcpInform => write!(f, "DHCPINFORM"),
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        use self::MessageType::*;
        match value {
            0 => Undefined,

            1 => DhcpDiscover,
            2 => DhcpOffer,
            3 => DhcpRequest,
            4 => DhcpDecline,
            5 => DhcpAck,
            6 => DhcpNak,
            7 => DhcpRelease,
            8 => DhcpInform,
//            9 => DhcpForceRenew,
//            10 => DhcpLeaseQuery,
//            11 => DhcpLeaseUnassigned,
//            12 => DhcpLeaseUnknown,
//            13 => DhcpLeaseActive,
//            14 => DhcpBulkLeaseQuery,
//            15 => DhcpLeaseQueryDone,
//            16 => DhcpActiveLeaseQuery,
//            17 => DhcpLeaseQueryStatus,
//            18 => DhcpTls,

            _ => Undefined,
        }
    }
}