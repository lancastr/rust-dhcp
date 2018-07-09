mod option_tag;
mod dhcp_message_type;

pub use self::option_tag::OptionTag;
pub use self::dhcp_message_type::DhcpMessageType;

use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct Options {
    pub subnet_mask                 : Option<Ipv4Addr>,

    pub address_request             : Option<Ipv4Addr>,
    pub address_time                : Option<u32>,

    pub dhcp_message_type           : Option<DhcpMessageType>,
    pub dhcp_server_id              : Option<u32>,
    pub dhcp_message                : Option<String>,
}