mod option_tag;
mod message_type;

pub use self::option_tag::OptionTag;
pub use self::message_type::MessageType;

//use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct Options {
//    pub subnet_mask                 : Option<Ipv4Addr>,
//    pub time_offset                 : Option<i32>,
//    pub routers                     : Option<Vec<Ipv4Addr>>,
//    pub time_servers                : Option<Vec<Ipv4Addr>>,
//    pub name_servers                : Option<Vec<Ipv4Addr>>,
//    pub domain_servers              : Option<Vec<Ipv4Addr>>,
//    pub log_servers                 : Option<Vec<Ipv4Addr>>,
//    pub quotes_servers              : Option<Vec<Ipv4Addr>>,
//    pub lpr_servers                 : Option<Vec<Ipv4Addr>>,
//    pub hostname                    : Option<String>,
//    pub boot_file_size              : Option<u16>,
//    pub merit_dump_file             : Option<String>,
//    pub domain_name                 : Option<String>,
//    pub swap_server                 : Option<Ipv4Addr>,
//    pub root_path                   : Option<String>,
//    pub extensions_path             : Option<String>,

    pub address_time                : Option<u32>,

    pub message_type                : Option<MessageType>,
}

impl Options {
    pub fn new() -> Self {
        Options {
//            subnet_mask                 : None,
//            time_offset                 : None,
//            routers                     : None,
//            time_servers                : None,
//            name_servers                : None,
//            domain_servers              : None,
//            log_servers                 : None,
//            quotes_servers              : None,
//            lpr_servers                 : None,
//            hostname                    : None,
//            boot_file_size              : None,
//            merit_dump_file             : None,
//            domain_name                 : None,
//            swap_server                 : None,
//            root_path                   : None,
//            extensions_path             : None,

            address_time                : None,

            message_type                : None,
        }
    }
}

