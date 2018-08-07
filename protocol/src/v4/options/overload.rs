//! DHCP option overload module.

use std::fmt;

/// DHCP option overload values.
#[derive(Debug, Clone, Copy)]
pub enum Overload {
    Undefined = 0,
    File,
    Sname,
    Both,
}

impl fmt::Display for Overload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Overload::*;
        match self {
            File => write!(f, "FILE"),
            Sname => write!(f, "SNAME"),
            Both => write!(f, "BOTH"),

            Undefined => write!(f, "UNDEFINED"),
        }
    }
}

impl From<u8> for Overload {
    fn from(value: u8) -> Self {
        use self::Overload::*;
        match value {
            1 => File,
            2 => Sname,
            3 => Both,

            _ => Undefined,
        }
    }
}
