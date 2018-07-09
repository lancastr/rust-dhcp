///
/// Defined means 'uses MAC-48',
/// because only MAC-48 is supported
///
#[derive(Debug, Clone, Copy)]
pub enum HardwareType {
    Undefined,
    Defined,
}

impl From<u8> for HardwareType {
    fn from(value: u8) -> Self {
        use self::HardwareType::*;
        match value {
            1 => Defined,
            _ => Undefined,
        }
    }
}