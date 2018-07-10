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
    pub overload                    : Option<u8>,
    pub dhcp_message_type           : Option<DhcpMessageType>,
    pub dhcp_server_id              : Option<Ipv4Addr>,
    pub parameter_list              : Option<String>,
    pub dhcp_message                : Option<String>,
    pub dhcp_max_message_size       : Option<u16>,
}

impl Options {
    pub fn new() -> Self {
        Options {
            subnet_mask             : None,

            address_request         : None,
            address_time            : None,
            overload                : None,
            dhcp_message_type       : None,
            dhcp_server_id          : None,
            parameter_list          : None,
            dhcp_message            : None,
            dhcp_max_message_size   : None,
        }
    }
}