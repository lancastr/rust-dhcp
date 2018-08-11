//! DHCP options module.

mod message_type;
mod option_tag;
mod overload;

pub use self::{message_type::MessageType, option_tag::OptionTag, overload::Overload};

use std::net::Ipv4Addr;

/// DHCP options.
///
/// Implemented completely with `Option` for better flexibility and polymorphism.
///
/// [RFC 2132](https://tools.ietf.org/html/rfc2132)
/// [RFC 3442](https://tools.ietf.org/html/rfc3442)
#[derive(Default)]
pub struct Options {
    /*
    RFC 2132
    */
    // RFC 1497 Vendor Extensions (RFC 2132 §3)
    pub subnet_mask: Option<Ipv4Addr>,
    pub time_offset: Option<u32>,
    pub routers: Option<Vec<Ipv4Addr>>,
    pub time_servers: Option<Vec<Ipv4Addr>>,
    pub name_servers: Option<Vec<Ipv4Addr>>,
    pub domain_name_servers: Option<Vec<Ipv4Addr>>,
    pub log_servers: Option<Vec<Ipv4Addr>>,
    pub quotes_servers: Option<Vec<Ipv4Addr>>,
    pub lpr_servers: Option<Vec<Ipv4Addr>>,
    pub impress_servers: Option<Vec<Ipv4Addr>>,
    pub rlp_servers: Option<Vec<Ipv4Addr>>,
    pub hostname: Option<String>,
    pub boot_file_size: Option<u16>,
    pub merit_dump_file: Option<String>,
    pub domain_name: Option<String>,
    pub swap_server: Option<Ipv4Addr>,
    pub root_path: Option<String>,
    pub extensions_path: Option<String>,
    // IP Layer Parameters per Host (RFC 2132 §4)
    pub forward_on_off: Option<u8>,
    pub non_local_source_route_on_off: Option<u8>,
    pub policy_filters: Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
    pub max_datagram_reassembly_size: Option<u16>,
    pub default_ip_ttl: Option<u8>,
    pub mtu_timeout: Option<u32>,
    pub mtu_plateau: Option<Vec<u16>>,
    // IP Layer Parameters per Interface (RFC 2132 §5)
    pub mtu_interface: Option<u16>,
    pub mtu_subnet: Option<u8>,
    pub broadcast_address: Option<Ipv4Addr>,
    pub mask_recovery: Option<u8>,
    pub mask_supplier: Option<u8>,
    pub perform_router_discovery: Option<u8>,
    pub router_solicitation_address: Option<Ipv4Addr>,
    pub static_routes: Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
    // Link Layer Parameters per Interface (RFC 2132 §6)
    pub trailer_encapsulation: Option<u8>,
    pub arp_timeout: Option<u32>,
    pub ethernet_encapsulation: Option<u8>,
    // TCP Default TTL Option (RFC 2132 §7)
    pub default_tcp_ttl: Option<u8>,
    pub keepalive_time: Option<u32>,
    pub keepalive_data: Option<u8>,
    // Application and Service Parameters (RFC 2132 §8)
    pub nis_domain: Option<String>,
    pub nis_servers: Option<Vec<Ipv4Addr>>,
    pub ntp_servers: Option<Vec<Ipv4Addr>>,
    pub vendor_specific: Option<Vec<u8>>,
    pub netbios_name_servers: Option<Vec<Ipv4Addr>>,
    pub netbios_distribution_servers: Option<Vec<Ipv4Addr>>,
    pub netbios_node_type: Option<u8>,
    pub netbios_scope: Option<String>,
    pub x_window_font_servers: Option<Vec<Ipv4Addr>>,
    pub x_window_manager_servers: Option<Vec<Ipv4Addr>>,
    // DHCP Extensions (RFC 2132 §9)
    pub address_request: Option<Ipv4Addr>,
    pub address_time: Option<u32>,
    pub overload: Option<Overload>,
    pub dhcp_message_type: Option<MessageType>,
    pub dhcp_server_id: Option<Ipv4Addr>,
    pub parameter_list: Option<Vec<u8>>,
    pub dhcp_message: Option<String>,
    pub dhcp_max_message_size: Option<u16>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub class_id: Option<Vec<u8>>,
    pub client_id: Option<Vec<u8>>,

    /*
    RFC 2242 (just to fill gaps)
    */
    pub netware_ip_domain: Option<Vec<u8>>,
    pub netware_ip_option: Option<Vec<u8>>,

    /*
    RFC 2132 (continuation)
    */
    // Application and Service Parameters (RFC 2132 §8) (continuation)
    pub nis_v3_domain_name: Option<String>,
    pub nis_v3_servers: Option<Vec<Ipv4Addr>>,
    pub server_name: Option<String>,
    pub bootfile_name: Option<String>,
    pub home_agent_addresses: Option<Vec<Ipv4Addr>>,
    pub smtp_servers: Option<Vec<Ipv4Addr>>,
    pub pop3_servers: Option<Vec<Ipv4Addr>>,
    pub nntp_servers: Option<Vec<Ipv4Addr>>,
    pub www_servers: Option<Vec<Ipv4Addr>>,
    pub finger_servers: Option<Vec<Ipv4Addr>>,
    pub irc_servers: Option<Vec<Ipv4Addr>>,
    pub street_talk_servers: Option<Vec<Ipv4Addr>>,
    pub stda_servers: Option<Vec<Ipv4Addr>>,

    /*
    RFC 3442 (The Classless Static Route Option)
    */
    pub classless_static_routes: Option<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>>,
}
