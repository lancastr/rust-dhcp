//! DHCP message hardware type module.

/// DHCP hardware type.
///
/// Only MAC-48 is implemented.
#[derive(Debug, Clone, Copy)]
pub enum HardwareType {
    Undefined,
    Ethernet,
}

impl From<u8> for HardwareType {
    fn from(value: u8) -> Self {
        use self::HardwareType::*;
        match value {
            1 => Ethernet,
            _ => Undefined,
        }
    }
}