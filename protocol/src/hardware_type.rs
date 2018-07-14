//! HardwareType module

#[derive(Debug, Clone, Copy)]
/// DHCP hardware type.
///
/// Only MAC-48 is implemented.
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