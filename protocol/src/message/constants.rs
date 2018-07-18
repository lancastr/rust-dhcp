//! DHCP message constants.

/// From the beginning to `MAGIC_COOKIE` inclusively.
pub const SIZE_HEADER_MINIMAL: usize = 240;

/// `flags` size in bytes.
pub const SIZE_FLAGS: usize = 2;

/// `client_hardware_address` size in bytes.
pub const SIZE_HARDWARE_ADDRESS: usize = 16;

/// `server_name` size in bytes.
pub const SIZE_SERVER_NAME: usize = 64;

/// `boot_filename` size in bytes.
pub const SIZE_BOOT_FILENAME: usize = 128;

/// 1 byte tag and 1 byte length before each DHCP option.
pub const SIZE_OPTION_PREFIX: usize = 2;

/// Only the first bit of the `flags` field in used in DHCP.
pub const FLAG_BROADCAST: u16 = 0x0001;

/// The magic number before the DHCP options.
pub const MAGIC_COOKIE: u32 = 0x63825363;