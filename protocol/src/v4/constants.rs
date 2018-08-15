//! DHCP message constants.

/// `client_hardware_address` size in bytes.
pub const SIZE_HARDWARE_ADDRESS: usize = 16;

/// `server_name` size in bytes.
pub const SIZE_SERVER_NAME: usize = 64;

/// `boot_filename` size in bytes.
pub const SIZE_BOOT_FILENAME: usize = 128;

/// The `server_name` field offset in bytes.
pub const OFFSET_SERVER_NAME: usize = 44;

/// The `boot_filename` field offset in bytes.
pub const OFFSET_BOOT_FILENAME: usize = OFFSET_SERVER_NAME + SIZE_SERVER_NAME;

/// DHCP options magic cookie offset in bytes.
pub const OFFSET_MAGIC_COOKIE: usize = OFFSET_SERVER_NAME + SIZE_SERVER_NAME + SIZE_BOOT_FILENAME;

/// DHCP options themselves offset in bytes.
pub const OFFSET_OPTIONS: usize = OFFSET_MAGIC_COOKIE + ::std::mem::size_of::<u32>();

/// Only the highest bit of the `flags` field is used in DHCP.
pub const FLAG_BROADCAST: u16 = 0b1000000000000000;

/// The magic number before the DHCP options.
pub const MAGIC_COOKIE: u32 = 0x63825363;

/// The size of the IP header the server uses.
pub const SIZE_HEADER_IP: usize = 20;

/// The size of the UDP header the server uses.
pub const SIZE_HEADER_UDP: usize = 8;

/// The minimal message size the client MUST be able to accept.
pub const SIZE_MESSAGE_MINIMAL: usize = 576;
