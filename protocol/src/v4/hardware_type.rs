//! DHCP message hardware type module.

use std::fmt;

/// DHCP hardware type.
///
/// Only MAC-48 is implemented.
#[derive(Clone, Copy)]
pub enum HardwareType {
    Undefined = 0,
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

impl fmt::Display for HardwareType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::HardwareType::*;
        match self {
            Ethernet => write!(f, "Ethernet"),

            Undefined => write!(f, "UNDEFINED"),
        }
    }
}
