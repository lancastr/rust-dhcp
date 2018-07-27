//! DHCP message serialization module.

use std::{
    io,
    mem,
    net::Ipv4Addr,
};

use bytes::{
    Buf,
    BufMut,
};

use super::{
    Message,
    options::{
        MessageType,
        OptionTag,
    },
    constants::*,
};

/// Checks if there is enough space in buffer to put a value.
macro_rules! check_remaining(
    ($cursor:expr, $distance:expr) => (
        if $cursor.remaining() < $distance {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer is too small"));
        }
    )
);

impl Message {
    /// DHCP message serialization.
    ///
    /// # Errors
    /// `io::Error` if the buffer is too small.
    pub fn to_bytes(&self, dst: &mut [u8]) -> io::Result<usize> {
        use OptionTag::*;

        let mut cursor = io::Cursor::new(dst);
        check_remaining!(cursor, SIZE_HEADER_MINIMAL);
        cursor.put_u8(self.operation_code as u8);
        cursor.put_u8(self.hardware_type as u8);
        cursor.put_u8(self.hardware_address_length);
        cursor.put_u8(self.hardware_options);
        cursor.put_u32_be(self.transaction_id);
        cursor.put_u16_be(self.seconds);
        cursor.put_u16_be(if self.is_broadcast {0x0001} else {0x0000});
        cursor.put_u32_be(u32::from(self.client_ip_address));
        cursor.put_u32_be(u32::from(self.your_ip_address));
        cursor.put_u32_be(u32::from(self.server_ip_address));
        cursor.put_u32_be(u32::from(self.gateway_ip_address));
        cursor.put(self.client_hardware_address.as_bytes()); // 6 byte MAC-48
        cursor.put(vec![0u8; SIZE_HARDWARE_ADDRESS - self.client_hardware_address.as_bytes().len()]); // 10 byte padding
        cursor.put(self.server_name.as_bytes());
        cursor.put(vec![0u8; SIZE_SERVER_NAME - self.server_name.len()]); // (64 - length) byte padding
        cursor.put(self.boot_filename.as_bytes());
        cursor.put(vec![0u8; SIZE_BOOT_FILENAME - self.boot_filename.len()]); // (128 - length) byte padding
        cursor.put_u32_be(MAGIC_COOKIE);
        
        Self::put_ipv4(&mut cursor, SubnetMask, &self.options.subnet_mask)?;
        Self::put_u32(&mut cursor, TimeOffset, &self.options.time_offset)?;
        Self::put_vec_ipv4(&mut cursor, Routers, &self.options.routers)?;
        Self::put_vec_ipv4(&mut cursor, TimeServers, &self.options.time_servers)?;
        Self::put_vec_ipv4(&mut cursor, NameServers, &self.options.name_servers)?;
        Self::put_vec_ipv4(&mut cursor, DomainNameServers, &self.options.domain_name_servers)?;
        Self::put_vec_ipv4(&mut cursor, LogServers, &self.options.log_servers)?;
        Self::put_vec_ipv4(&mut cursor, QuotesServers, &self.options.quotes_servers)?;
        Self::put_vec_ipv4(&mut cursor, LprServers, &self.options.lpr_servers)?;
        Self::put_vec_ipv4(&mut cursor, ImpressServers, &self.options.impress_servers)?;
        Self::put_vec_ipv4(&mut cursor, RlpServers, &self.options.rlp_servers)?;
        Self::put_string(&mut cursor, Hostname, &self.options.hostname)?;
        Self::put_u16(&mut cursor, BootFileSize, &self.options.boot_file_size)?;
        Self::put_string(&mut cursor, MeritDumpFile, &self.options.merit_dump_file)?;
        Self::put_string(&mut cursor, DomainName, &self.options.domain_name)?;
        Self::put_ipv4(&mut cursor, SwapServer, &self.options.swap_server)?;
        Self::put_string(&mut cursor, RootPath, &self.options.root_path)?;
        Self::put_string(&mut cursor, ExtensionsPath, &self.options.extensions_path)?;
        Self::put_u8(&mut cursor, ForwardOnOff, &self.options.forward_on_off)?;
        Self::put_u8(&mut cursor, NonLocalSourceRouteOnOff, &self.options.non_local_source_route_on_off)?;
        Self::put_vec_ipv4_pairs(&mut cursor, PolicyFilters, &self.options.policy_filters)?;
        Self::put_u16(&mut cursor, MaxDatagramReassemblySize, &self.options.max_datagram_reassembly_size)?;
        Self::put_u8(&mut cursor, DefaultIpTtl, &self.options.default_ip_ttl)?;
        Self::put_u32(&mut cursor, MtuTimeout, &self.options.mtu_timeout)?;
        Self::put_vec_u16(&mut cursor, MtuPlateau, &self.options.mtu_plateau)?;
        Self::put_u16(&mut cursor, MtuInterface, &self.options.mtu_interface)?;
        Self::put_u8(&mut cursor, MtuSubnet, &self.options.mtu_subnet)?;
        Self::put_ipv4(&mut cursor, BroadcastAddress, &self.options.broadcast_address)?;
        Self::put_u8(&mut cursor, MaskRecovery, &self.options.mask_recovery)?;
        Self::put_u8(&mut cursor, MaskSupplier, &self.options.mask_supplier)?;
        Self::put_u8(&mut cursor, PerformRouterDiscovery, &self.options.perform_router_discovery)?;
        Self::put_ipv4(&mut cursor, RouterSolicitationAddress, &self.options.router_solicitation_address)?;
        Self::put_vec_ipv4_pairs(&mut cursor, StaticRoutes, &self.options.static_routes)?;
        Self::put_u8(&mut cursor, TrailerEncapsulation, &self.options.trailer_encapsulation)?;
        Self::put_u32(&mut cursor, ArpTimeout, &self.options.arp_timeout)?;
        Self::put_u8(&mut cursor, EthernetEncapsulation, &self.options.ethernet_encapsulation)?;
        Self::put_u8(&mut cursor, DefaultTcpTtl, &self.options.default_tcp_ttl)?;
        Self::put_u32(&mut cursor, KeepaliveTime, &self.options.keepalive_time)?;
        Self::put_u8(&mut cursor, KeepaliveData, &self.options.keepalive_data)?;
        Self::put_string(&mut cursor, NisDomain, &self.options.nis_domain)?;
        Self::put_vec_ipv4(&mut cursor, NisServers, &self.options.nis_servers)?;
        Self::put_vec_ipv4(&mut cursor, NtpServers, &self.options.ntp_servers)?;
        Self::put_vec(&mut cursor, VendorSpecific, &self.options.vendor_specific)?;
        Self::put_vec_ipv4(&mut cursor, NetbiosNameServers, &self.options.netbios_name_servers)?;
        Self::put_vec_ipv4(&mut cursor, NetbiosDistributionServers, &self.options.netbios_distribution_servers)?;
        Self::put_u8(&mut cursor, NetbiosNodeType, &self.options.netbios_node_type)?;
        Self::put_string(&mut cursor, NetbiosScope, &self.options.netbios_scope)?;
        Self::put_vec_ipv4(&mut cursor, XWindowFontServers, &self.options.x_window_font_servers)?;
        Self::put_vec_ipv4(&mut cursor, XWindowManagerServers, &self.options.x_window_manager_servers)?;
        Self::put_ipv4(&mut cursor, AddressRequest, &self.options.address_request)?;
        Self::put_u32(&mut cursor, AddressTime, &self.options.address_time)?;
        Self::put_u8(&mut cursor, Overload, &self.options.overload)?;
        Self::put_message_type(&mut cursor, DhcpMessageType, &self.options.dhcp_message_type)?;
        Self::put_ipv4(&mut cursor, DhcpServerId, &self.options.dhcp_server_id)?;
        Self::put_vec(&mut cursor, ParameterList, &self.options.parameter_list)?;
        Self::put_string(&mut cursor, DhcpMessage, &self.options.dhcp_message)?;
        Self::put_u16(&mut cursor, DhcpMaxMessageSize, &self.options.dhcp_max_message_size)?;
        Self::put_u32(&mut cursor, RenewalTime, &self.options.renewal_time)?;
        Self::put_u32(&mut cursor, RebindingTime, &self.options.rebinding_time)?;
        Self::put_vec(&mut cursor, ClassId, &self.options.class_id)?;
        Self::put_vec(&mut cursor, ClientId, &self.options.client_id)?;
        Self::put_vec(&mut cursor, NetwareIpDomain, &self.options.netware_ip_domain)?;
        Self::put_vec(&mut cursor, NetwareIpOption, &self.options.netware_ip_option)?;
        Self::put_string(&mut cursor, NisDomainName, &self.options.nis_v3_domain_name)?;
        Self::put_vec_ipv4(&mut cursor, NisServerAddress, &self.options.nis_v3_servers)?;
        Self::put_string(&mut cursor, ServerName, &self.options.server_name)?;
        Self::put_string(&mut cursor, BootfileName, &self.options.bootfile_name)?;
        Self::put_vec_ipv4(&mut cursor, HomeAgentAddresses, &self.options.home_agent_addresses)?;
        Self::put_vec_ipv4(&mut cursor, SmtpServers, &self.options.smtp_servers)?;
        Self::put_vec_ipv4(&mut cursor, Pop3Servers, &self.options.pop3_servers)?;
        Self::put_vec_ipv4(&mut cursor, NntpServers, &self.options.nntp_servers)?;
        Self::put_vec_ipv4(&mut cursor, WwwServers, &self.options.www_servers)?;
        Self::put_vec_ipv4(&mut cursor, FingerServers, &self.options.finger_servers)?;
        Self::put_vec_ipv4(&mut cursor, IrcServers, &self.options.irc_servers)?;
        Self::put_vec_ipv4(&mut cursor, StreetTalkServers, &self.options.street_talk_servers)?;
        Self::put_vec_ipv4(&mut cursor, StdaServers, &self.options.stda_servers)?;

        check_remaining!(cursor, mem::size_of::<u8>());
        cursor.put_u8(End as u8);
        Ok(cursor.position() as usize)
    }

    fn put_message_type(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<MessageType>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u8>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u8(*value as u8);
        }
        Ok(())
    }

    fn put_u8(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<u8>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u8>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u8(*value);
        }
        Ok(())
    }

    fn put_u16(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<u16>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u16>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u16_be(*value);
        }
        Ok(())
    }

    fn put_u32(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<u32>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u32_be(*value);
        }
        Ok(())
    }

    fn put_ipv4(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<Ipv4Addr>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u32_be(u32::from(*value));
        }
        Ok(())
    }

    fn put_string(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<String>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = value.len();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put(value);
        }
        Ok(())
    }

    fn put_vec(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<Vec<u8>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = value.len();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put(value);
        }
        Ok(())
    }

    fn put_vec_u16(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<Vec<u16>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = value.len() * mem::size_of::<u16>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u16_be(*element);
            }
        }
        Ok(())
    }

    fn put_vec_ipv4(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<Vec<Ipv4Addr>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = value.len() * mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.to_owned()));
            }
        }
        Ok(())
    }

    fn put_vec_ipv4_pairs(
        cursor      : &mut io::Cursor<&mut [u8]>,
        tag         : OptionTag,
        value       : &Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = value.len() * mem::size_of::<u32>() * 2;
            check_remaining!(cursor, SIZE_OPTION_PREFIX + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.0.to_owned()));
                cursor.put_u32_be(u32::from(element.1.to_owned()));
            }
        }
        Ok(())
    }
}