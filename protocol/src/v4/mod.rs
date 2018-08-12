//! The main DHCP message module.
pub mod constants;
pub mod hardware_type;
pub mod operation_code;
pub mod options;

mod deserializer;
mod serializer;
mod validator;

use std::{fmt, net::Ipv4Addr};

use eui48::MacAddress;

pub use self::{
    hardware_type::HardwareType,
    operation_code::OperationCode,
    options::{OptionTag, Options},
};

/// DHCP message.
pub struct Message {
    pub operation_code: OperationCode,
    pub hardware_type: HardwareType,
    pub hardware_address_length: u8,
    pub hardware_options: u8,
    pub transaction_id: u32,
    pub seconds: u16,
    pub is_broadcast: bool,
    pub client_ip_address: Ipv4Addr,
    pub your_ip_address: Ipv4Addr,
    pub server_ip_address: Ipv4Addr,
    pub gateway_ip_address: Ipv4Addr,
    pub client_hardware_address: MacAddress,
    pub server_name: Vec<u8>,
    pub boot_filename: Vec<u8>,
    pub options: Options,
}

/// Prints an option with `Debug`.
macro_rules! dbg_opt (
    ($f:expr, $option:expr, $iter:expr) => (
        let code = $iter.next().unwrap_or(0);
        let name = stringify!($option).split(".").collect::<Vec<&str>>().last().cloned().unwrap();
        if let Some(ref v) = $option {
            writeln!($f, "[{:03}] {:027}| {:?}", code, name, v)?;
        }
    );
);

/// Prints an option with `Display`.
macro_rules! dsp_opt (
    ($f:expr, $option:expr, $iter:expr) => (
        let code = $iter.next().unwrap_or(0);
        let name = stringify!($option).split(".").collect::<Vec<&str>>().last().cloned().unwrap();
        if let Some(ref v) = $option {
            writeln!($f, "[{:03}] {:027}| {}", code, name, v)?;
        }
    );
);

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f)?;

        let mut server_name_last = self.server_name.len();
        for i in (0..self.server_name.len()).rev() {
            if self.server_name.get(i).cloned().unwrap() == 0 {
                server_name_last -= 1;
            } else {
                break;
            }
        }

        let mut boot_filename_last = self.boot_filename.len();
        for i in (0..self.boot_filename.len()).rev() {
            if self.boot_filename.get(i).cloned().unwrap() == 0 {
                boot_filename_last -= 1;
            } else {
                break;
            }
        }

        writeln!(f, "{}HEADER{}", "_".repeat(30), "_".repeat(39))?;
        writeln!(f, "{:32} | {}", "Operation code", self.operation_code)?;
        writeln!(f, "{:32} | {}", "Hardware type", self.hardware_type)?;
        writeln!(
            f,
            "{:32} | {}",
            "Hardware address length", self.hardware_address_length
        )?;
        writeln!(f, "{:32} | {}", "Hardware options", self.hardware_options)?;
        writeln!(f, "{:32} | {}", "Transaction ID", self.transaction_id)?;
        writeln!(f, "{:32} | {}", "Seconds", self.seconds)?;
        writeln!(f, "{:32} | {}", "Broadcast flag", self.is_broadcast)?;
        writeln!(f, "{:32} | {}", "Client IP address", self.client_ip_address)?;
        writeln!(f, "{:32} | {}", "Your IP address", self.your_ip_address)?;
        writeln!(f, "{:32} | {}", "Server IP address", self.server_ip_address)?;
        writeln!(
            f,
            "{:32} | {}",
            "Gateway IP address", self.gateway_ip_address
        )?;
        writeln!(
            f,
            "{:32} | {}",
            "Client hardware address", self.client_hardware_address
        )?;
        writeln!(
            f,
            "{:32} | {:?}",
            "Server name",
            &self.server_name[0..server_name_last]
        )?;
        writeln!(
            f,
            "{:32} | {:?}",
            "Boot filename",
            &self.boot_filename[0..boot_filename_last]
        )?;

        writeln!(f, "{}OPTIONS{}", "_".repeat(30), "_".repeat(38))?;
        let mut iter = (OptionTag::SubnetMask as u8)..=(OptionTag::StdaServers as u8);
        dbg_opt!(f, self.options.subnet_mask, iter);
        dbg_opt!(f, self.options.time_offset, iter);
        dbg_opt!(f, self.options.routers, iter);
        dbg_opt!(f, self.options.time_servers, iter);
        dbg_opt!(f, self.options.name_servers, iter);
        dbg_opt!(f, self.options.domain_name_servers, iter);
        dbg_opt!(f, self.options.log_servers, iter);
        dbg_opt!(f, self.options.quotes_servers, iter);
        dbg_opt!(f, self.options.lpr_servers, iter);
        dbg_opt!(f, self.options.impress_servers, iter);
        dbg_opt!(f, self.options.rlp_servers, iter);
        dbg_opt!(f, self.options.hostname, iter);
        dbg_opt!(f, self.options.boot_file_size, iter);
        dbg_opt!(f, self.options.merit_dump_file, iter);
        dbg_opt!(f, self.options.domain_name, iter);
        dbg_opt!(f, self.options.swap_server, iter);
        dbg_opt!(f, self.options.root_path, iter);
        dbg_opt!(f, self.options.extensions_path, iter);
        dbg_opt!(f, self.options.forward_on_off, iter);
        dbg_opt!(f, self.options.non_local_source_route_on_off, iter);
        dbg_opt!(f, self.options.policy_filters, iter);
        dbg_opt!(f, self.options.max_datagram_reassembly_size, iter);
        dbg_opt!(f, self.options.default_ip_ttl, iter);
        dbg_opt!(f, self.options.mtu_timeout, iter);
        dbg_opt!(f, self.options.mtu_plateau, iter);
        dbg_opt!(f, self.options.mtu_interface, iter);
        dbg_opt!(f, self.options.mtu_subnet, iter);
        dbg_opt!(f, self.options.broadcast_address, iter);
        dbg_opt!(f, self.options.mask_recovery, iter);
        dbg_opt!(f, self.options.mask_supplier, iter);
        dbg_opt!(f, self.options.perform_router_discovery, iter);
        dbg_opt!(f, self.options.router_solicitation_address, iter);
        dbg_opt!(f, self.options.static_routes, iter);
        dbg_opt!(f, self.options.trailer_encapsulation, iter);
        dbg_opt!(f, self.options.arp_timeout, iter);
        dbg_opt!(f, self.options.ethernet_encapsulation, iter);
        dbg_opt!(f, self.options.default_tcp_ttl, iter);
        dbg_opt!(f, self.options.keepalive_time, iter);
        dbg_opt!(f, self.options.keepalive_data, iter);
        dbg_opt!(f, self.options.nis_domain, iter);
        dbg_opt!(f, self.options.nis_servers, iter);
        dbg_opt!(f, self.options.ntp_servers, iter);
        dbg_opt!(f, self.options.vendor_specific, iter);
        dbg_opt!(f, self.options.netbios_name_servers, iter);
        dbg_opt!(f, self.options.netbios_distribution_servers, iter);
        dbg_opt!(f, self.options.netbios_node_type, iter);
        dbg_opt!(f, self.options.netbios_scope, iter);
        dbg_opt!(f, self.options.x_window_font_servers, iter);
        dbg_opt!(f, self.options.x_window_manager_servers, iter);
        dbg_opt!(f, self.options.address_request, iter);
        dbg_opt!(f, self.options.address_time, iter);
        dsp_opt!(f, self.options.overload, iter);
        dsp_opt!(f, self.options.dhcp_message_type, iter);
        dbg_opt!(f, self.options.dhcp_server_id, iter);
        dbg_opt!(f, self.options.parameter_list, iter);
        dbg_opt!(f, self.options.dhcp_message, iter);
        dbg_opt!(f, self.options.dhcp_max_message_size, iter);
        dbg_opt!(f, self.options.renewal_time, iter);
        dbg_opt!(f, self.options.rebinding_time, iter);
        dbg_opt!(f, self.options.class_id, iter);
        dbg_opt!(f, self.options.client_id, iter);
        dbg_opt!(f, self.options.netware_ip_domain, iter);
        dbg_opt!(f, self.options.netware_ip_option, iter);
        dbg_opt!(f, self.options.nis_v3_domain_name, iter);
        dbg_opt!(f, self.options.nis_v3_servers, iter);
        dbg_opt!(f, self.options.server_name, iter);
        dbg_opt!(f, self.options.bootfile_name, iter);
        dbg_opt!(f, self.options.home_agent_addresses, iter);
        dbg_opt!(f, self.options.smtp_servers, iter);
        dbg_opt!(f, self.options.pop3_servers, iter);
        dbg_opt!(f, self.options.nntp_servers, iter);
        dbg_opt!(f, self.options.www_servers, iter);
        dbg_opt!(f, self.options.finger_servers, iter);
        dbg_opt!(f, self.options.irc_servers, iter);
        dbg_opt!(f, self.options.street_talk_servers, iter);
        dbg_opt!(f, self.options.stda_servers, iter);

        let mut iter =
            (OptionTag::ClasslessStaticRoutes as u8)..=(OptionTag::ClasslessStaticRoutes as u8);
        dbg_opt!(f, self.options.classless_static_routes, iter);

        writeln!(f, "{}", "_".repeat(75))?;
        Ok(())
    }
}
