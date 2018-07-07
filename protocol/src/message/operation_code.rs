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