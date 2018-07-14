#[derive(Debug, Clone, Copy)]
pub enum HardwareType {
    Undefined,
    Mac48,
}

impl From<u8> for HardwareType {
    fn from(value: u8) -> Self {
        use self::HardwareType::*;
        match value {
            1 => Mac48,
            _ => Undefined,
        }
    }
}