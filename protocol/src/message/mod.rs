//! The main DHCP message module.
pub mod options;
pub mod constants;
pub mod operation_code;
pub mod hardware_type;

mod deserializer;
mod serializer;
mod validator;

use std::{
    fmt,
    net::Ipv4Addr,
};

use eui48::MacAddress;

pub use self::{
    options::{
        Options,
        OptionTag,
    },
    operation_code::OperationCode,
    hardware_type::HardwareType,
};

/// DHCP message.
pub struct Message {
    pub operation_code              : OperationCode,
    pub hardware_type               : HardwareType,
    pub hardware_address_length     : u8,
    pub hardware_options            : u8,
    pub transaction_id              : u32,
    pub seconds                     : u16,
    pub is_broadcast                : bool,
    pub client_ip_address           : Ipv4Addr,
    pub your_ip_address             : Ipv4Addr,
    pub server_ip_address           : Ipv4Addr,
    pub gateway_ip_address          : Ipv4Addr,
    pub client_hardware_address     : MacAddress,
    pub server_name                 : String,
    pub boot_filename               : String,
    pub options                     : Options,
}

macro_rules! write_opt(
    ($f:expr, $option:expr, $name:expr, $code_iter:expr) => (
        let code = $code_iter.next().unwrap_or(0);
        if let Some(ref v) = $option {
            writeln!($f, "[{:03}] {:027}| {:?}", code, $name, v)?;
        }
    )
);

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "______________________________HEADER_______________________________________")?;
        writeln!(f, "operation_code                   | {:?}", self.operation_code)?;
        writeln!(f, "hardware_type                    | {:?}", self.hardware_type)?;
        writeln!(f, "hardware_address_length          | {:?}", self.hardware_address_length)?;
        writeln!(f, "hardware_options                 | {:?}", self.hardware_options)?;
        writeln!(f, "transaction_id                   | {:?}", self.transaction_id)?;
        writeln!(f, "seconds                          | {:?}", self.seconds)?;
        writeln!(f, "is_broadcast                     | {:?}", self.is_broadcast)?;
        writeln!(f, "client_ip_address                | {:?}", self.client_ip_address)?;
        writeln!(f, "your_ip_address                  | {:?}", self.your_ip_address)?;
        writeln!(f, "server_ip_address                | {:?}", self.server_ip_address)?;
        writeln!(f, "gateway_ip_address               | {:?}", self.gateway_ip_address)?;
        writeln!(f, "client_hardware_address          | {:?}", self.client_hardware_address)?;
        writeln!(f, "server_name                      | {}", self.server_name)?;
        writeln!(f, "boot_filename                    | {}", self.boot_filename)?;
        writeln!(f, "______________________________OPTIONS______________________________________")?;
        let mut code_iter = (OptionTag::SubnetMask as u8)..=(OptionTag::StdaServers as u8);
        write_opt!(f, self.options.subnet_mask, "subnet_mask", code_iter);
        write_opt!(f, self.options.time_offset, "time_offset", code_iter);
        write_opt!(f, self.options.routers, "routers", code_iter);
        write_opt!(f, self.options.time_servers, "time_servers", code_iter);
        write_opt!(f, self.options.name_servers, "name_servers", code_iter);
        write_opt!(f, self.options.domain_name_servers, "domain_name_servers", code_iter);
        write_opt!(f, self.options.log_servers, "log_servers", code_iter);
        write_opt!(f, self.options.quotes_servers, "quotes_servers", code_iter);
        write_opt!(f, self.options.lpr_servers, "lpr_servers", code_iter);
        write_opt!(f, self.options.impress_servers, "impress_servers", code_iter);
        write_opt!(f, self.options.rlp_servers, "rlp_servers", code_iter);
        write_opt!(f, self.options.hostname, "hostname", code_iter);
        write_opt!(f, self.options.boot_file_size, "boot_file_size", code_iter);
        write_opt!(f, self.options.merit_dump_file, "merit_dump_file", code_iter);
        write_opt!(f, self.options.domain_name, "domain_name", code_iter);
        write_opt!(f, self.options.swap_server, "swap_server", code_iter);
        write_opt!(f, self.options.root_path, "root_path", code_iter);
        write_opt!(f, self.options.extensions_path, "extensions_path", code_iter);
        write_opt!(f, self.options.forward_on_off, "forward_on_off", code_iter);
        write_opt!(f, self.options.non_local_source_route_on_off, "non_local_source_route_on_off", code_iter);
        write_opt!(f, self.options.policy_filters, "policy_filters", code_iter);
        write_opt!(f, self.options.max_datagram_reassembly_size, "max_datagram_reassembly_size", code_iter);
        write_opt!(f, self.options.default_ip_ttl, "default_ip_ttl", code_iter);
        write_opt!(f, self.options.mtu_timeout, "mtu_timeout", code_iter);
        write_opt!(f, self.options.mtu_plateau, "mtu_plateau", code_iter);
        write_opt!(f, self.options.mtu_interface, "mtu_interface", code_iter);
        write_opt!(f, self.options.mtu_subnet, "mtu_subnet", code_iter);
        write_opt!(f, self.options.broadcast_address, "broadcast_address", code_iter);
        write_opt!(f, self.options.mask_recovery, "mask_recovery", code_iter);
        write_opt!(f, self.options.mask_supplier, "mask_supplier", code_iter);
        write_opt!(f, self.options.perform_router_discovery, "perform_router_discovery", code_iter);
        write_opt!(f, self.options.router_solicitation_address, "router_solicitation_address", code_iter);
        write_opt!(f, self.options.static_routes, "static_routes", code_iter);
        write_opt!(f, self.options.trailer_encapsulation, "trailer_encapsulation", code_iter);
        write_opt!(f, self.options.arp_timeout, "arp_timeout", code_iter);
        write_opt!(f, self.options.ethernet_encapsulation, "ethernet_encapsulation", code_iter);
        write_opt!(f, self.options.default_tcp_ttl, "default_tcp_ttl", code_iter);
        write_opt!(f, self.options.keepalive_time, "keepalive_time", code_iter);
        write_opt!(f, self.options.keepalive_data, "keepalive_data", code_iter);
        write_opt!(f, self.options.nis_domain, "nis_domain", code_iter);
        write_opt!(f, self.options.nis_servers, "nis_servers", code_iter);
        write_opt!(f, self.options.ntp_servers, "ntp_servers", code_iter);
        write_opt!(f, self.options.vendor_specific, "vendor_specific", code_iter);
        write_opt!(f, self.options.netbios_name_servers, "netbios_name_server", code_iter);
        write_opt!(f, self.options.netbios_distribution_servers, "netbios_distribution_server", code_iter);
        write_opt!(f, self.options.netbios_node_type, "netbios_node_type", code_iter);
        write_opt!(f, self.options.netbios_scope, "netbios_scope", code_iter);
        write_opt!(f, self.options.x_window_font_servers, "x_window_font_servers", code_iter);
        write_opt!(f, self.options.x_window_manager_servers, "x_window_manager_servers", code_iter);
        write_opt!(f, self.options.address_request, "address_request", code_iter);
        write_opt!(f, self.options.address_time, "address_time", code_iter);
        write_opt!(f, self.options.overload, "overload", code_iter);
        write_opt!(f, self.options.dhcp_message_type, "dhcp_message_type", code_iter);
        write_opt!(f, self.options.dhcp_server_id, "dhcp_server_id", code_iter);
        write_opt!(f, self.options.parameter_list, "parameter_list", code_iter);
        write_opt!(f, self.options.dhcp_message, "dhcp_message", code_iter);
        write_opt!(f, self.options.dhcp_max_message_size, "dhcp_max_message_size", code_iter);
        write_opt!(f, self.options.renewal_time, "renewal_time", code_iter);
        write_opt!(f, self.options.rebinding_time, "rebinding_time", code_iter);
        write_opt!(f, self.options.class_id, "class_id", code_iter);
        write_opt!(f, self.options.client_id, "client_id", code_iter);
        write_opt!(f, self.options.netware_ip_domain, "netware_ip_domain", code_iter);
        write_opt!(f, self.options.netware_ip_option, "netware_ip_option", code_iter);
        write_opt!(f, self.options.nis_v3_domain_name, "nis_v3_domain_name", code_iter);
        write_opt!(f, self.options.nis_v3_servers, "nis_v3_servers", code_iter);
        write_opt!(f, self.options.server_name, "server_name", code_iter);
        write_opt!(f, self.options.bootfile_name, "bootfile_name", code_iter);
        write_opt!(f, self.options.home_agent_addresses, "home_agent_addresses", code_iter);
        write_opt!(f, self.options.smtp_servers, "smtp_servers", code_iter);
        write_opt!(f, self.options.pop3_servers, "pop3_servers", code_iter);
        write_opt!(f, self.options.nntp_servers, "nntp_servers", code_iter);
        write_opt!(f, self.options.www_servers, "www_servers", code_iter);
        write_opt!(f, self.options.finger_servers, "finger_servers", code_iter);
        write_opt!(f, self.options.irc_servers, "irc_servers", code_iter);
        write_opt!(f, self.options.street_talk_servers, "street_talk_servers", code_iter);
        write_opt!(f, self.options.stda_servers, "stda_servers", code_iter);
        writeln!(f, "___________________________________________________________________________")?;
        Ok(())
    }
}