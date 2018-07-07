#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
    Undefined = 0,
    // RFC2132
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    // RFC3203 (not implemented)
    ForceRenew,
    // RFC4388 (not implemented)
    LeaseQuery,
    LeaseUnassigned,
    LeaseUnknown,
    LeaseActive,
    // RFC6926 (not implemented)
    BulkLeaseQuery,
    LeaseQueryDone,
    // RFC7724 (not implemented)
    ActiveLeaseQuery,
    LeaseQueryStatus,
    Tls,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        use self::MessageType::*;
        match value {
            0 => Undefined,

            1 => Discover,
            2 => Offer,
            3 => Request,
            4 => Decline,
            5 => Ack,
            6 => Nak,
            7 => Release,
            8 => Inform,
            9 => ForceRenew,
            10 => LeaseQuery,
            11 => LeaseUnassigned,
            12 => LeaseUnknown,
            13 => LeaseActive,
            14 => BulkLeaseQuery,
            15 => LeaseQueryDone,
            16 => ActiveLeaseQuery,
            17 => LeaseQueryStatus,
            18 => Tls,

            _ => Undefined,
        }
    }
}