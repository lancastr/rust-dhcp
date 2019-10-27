//! DHCP message serialization module.

use std::{io, mem, net::Ipv4Addr};

use bytes::{Buf, BufMut};

use super::{
    constants::*,
    options::{OptionTag, Overload as OverloadEnum},
    Message,
};

/// Checks if there is enough space in buffer to put a value.
macro_rules! check_remaining(
    ($cursor:expr, $distance:expr) => (
        if $cursor.remaining() < $distance {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "No more space left"));
        }
    )
);

/// The tag octet and the length octet.
const SIZE_OPTION_PREFIX: usize = 2;
/// The end octet which may occur after any option.
const SIZE_OPTION_SUFFIX: usize = 1;
/// Both of the above.
const SIZE_OPTION_AFFIXES: usize = SIZE_OPTION_PREFIX + SIZE_OPTION_SUFFIX;

/// The overload option which is written last by the main cursor.
const SIZE_OPTION_OVERLOAD: usize = mem::size_of::<u8>() * 3;
/// The above and the required space for the `overload` option, which is written last.
const SIZE_OPTION_MAIN_AFFIXES: usize = SIZE_OPTION_AFFIXES + SIZE_OPTION_OVERLOAD;

/// The maximal option size.
const SIZE_OPTION_MAX: usize = 255;

/// The boot filename cursor position in the cursors array.
const CURSOR_INDEX_FILE: usize = 0;
/// The server name cursor position in the cursors array.
const CURSOR_INDEX_SNAME: usize = 1;
/// The main cursor position in the cursors array.
const CURSOR_INDEX_MAIN: usize = 2;
/// The cursors array size.
const CURSOR_INDEX_TOTAL: usize = 3;

impl Message {
    /// DHCP message serialization.
    ///
    /// Options encoded with `put_opt_*` methods called with the `?`
    /// operator are mandatory and throw an error on unsuccessful write.
    /// Options encoded with `put_opt_*` methods called without the `?` operator are optional
    /// and are written to the packet only if there is enough space left.
    /// The order of options and behavior of the encoder may be changed in the future.
    ///
    /// If `max_size` is specified, `dst` is truncated to it.
    ///
    /// # Errors
    /// `io::Error` if the buffer is too small.
    pub fn to_bytes(&self, dst: &mut [u8], max_size: Option<u16>) -> io::Result<usize> {
        use OptionTag::*;

        // the slice is truncated to the maximal client message size
        let dst = if let Some(max_size) = max_size {
            &mut dst[..((max_size as usize) - SIZE_HEADER_IP - SIZE_HEADER_UDP)]
        } else {
            dst
        };

        // cursors are initialized in the way they must be filled
        let mut cursors: [io::Cursor<&mut [u8]>; CURSOR_INDEX_TOTAL] = [
            io::Cursor::new(unsafe {
                &mut *(&mut dst[OFFSET_BOOT_FILENAME..OFFSET_MAGIC_COOKIE] as *mut [u8])
            }),
            io::Cursor::new(unsafe {
                &mut *(&mut dst[OFFSET_SERVER_NAME..OFFSET_BOOT_FILENAME] as *mut [u8])
            }),
            io::Cursor::new(unsafe { &mut *(dst as *mut [u8]) }),
        ];

        check_remaining!(cursors[CURSOR_INDEX_MAIN], OFFSET_OPTIONS);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.operation_code as u8);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.hardware_type as u8);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.hardware_address_length);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.hardware_options);
        cursors[CURSOR_INDEX_MAIN].put_u32_be(self.transaction_id);
        cursors[CURSOR_INDEX_MAIN].put_u16_be(self.seconds);
        // https://tools.ietf.org/html/rfc2131#section-2
        // https://tools.ietf.org/html/rfc1700#page-3
        // Leftmost bit (0 bit) is most significant
        cursors[CURSOR_INDEX_MAIN].put_u16_be(if self.is_broadcast { 0x8000 } else { 0x0000 });
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.client_ip_address));
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.your_ip_address));
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.server_ip_address));
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.gateway_ip_address));
        cursors[CURSOR_INDEX_MAIN].put(self.client_hardware_address.as_bytes()); // 6 byte MAC-48
        cursors[CURSOR_INDEX_MAIN].put(vec![
            0u8;
            SIZE_HARDWARE_ADDRESS
                - self.client_hardware_address.as_bytes().len()
        ]); // 10 byte padding
        cursors[CURSOR_INDEX_MAIN].put(&self.server_name);
        cursors[CURSOR_INDEX_MAIN].put(vec![0u8; SIZE_SERVER_NAME - self.server_name.len()]); // (64 - length) byte padding
        cursors[CURSOR_INDEX_MAIN].put(&self.boot_filename);
        cursors[CURSOR_INDEX_MAIN].put(vec![0u8; SIZE_BOOT_FILENAME - self.boot_filename.len()]); // (128 - length) byte padding
        cursors[CURSOR_INDEX_MAIN].put_u32_be(MAGIC_COOKIE);

        // the most important and required options are encoded first
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            DhcpMessageType,
            &self.options.dhcp_message_type.to_owned().map(|v| v as u8),
        )?;
        Self::put_opt_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            DhcpMaxMessageSize,
            &self.options.dhcp_max_message_size,
        )?;
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            DhcpServerId,
            &self.options.dhcp_server_id,
        )?;
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            AddressRequest,
            &self.options.address_request,
        )?;
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            AddressTime,
            &self.options.address_time,
        )?;
        Self::put_opt_vec(
            &mut cursors[CURSOR_INDEX_MAIN],
            ParameterList,
            &self.options.parameter_list,
        )?;
        Self::put_opt_vec(
            &mut cursors[CURSOR_INDEX_MAIN],
            ClientId,
            &self.options.client_id,
        )?;

        // the mandatory implemented network configuration options are encoded next
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            SubnetMask,
            &self.options.subnet_mask,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            DomainNameServers,
            &self.options.domain_name_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            Routers,
            &self.options.routers,
        )?;
        Self::put_opt_vec_ipv4_pairs(
            &mut cursors[CURSOR_INDEX_MAIN],
            StaticRoutes,
            &self.options.static_routes,
        )?;

        // the splittable options are encoded after, leaving space for the 'overload' option
        Self::put_opt_classless_static_routes(
            &mut cursors,
            ClasslessStaticRoutes,
            &self.options.classless_static_routes,
        )?;

        // the overload options is written last by the main cursor
        let overload = if cursors[CURSOR_INDEX_FILE].position() > 0
            && cursors[CURSOR_INDEX_SNAME].position() > 0
        {
            Some(OverloadEnum::Both)
        } else if cursors[CURSOR_INDEX_FILE].position() > 0 {
            Some(OverloadEnum::File)
        } else if cursors[CURSOR_INDEX_SNAME].position() > 0 {
            Some(OverloadEnum::Sname)
        } else {
            None
        };
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            Overload,
            &overload.map(|v| v as u8),
        )?;

        // some helpful and optional options are encoded next
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            RenewalTime,
            &self.options.renewal_time,
        )?;
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            RebindingTime,
            &self.options.rebinding_time,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            Hostname,
            &self.options.hostname,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            DhcpMessage,
            &self.options.dhcp_message,
        )?;

        // unimplemented options are encoded next
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            TimeOffset,
            &self.options.time_offset,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            TimeServers,
            &self.options.time_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NameServers,
            &self.options.name_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            LogServers,
            &self.options.log_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            QuotesServers,
            &self.options.quotes_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            LprServers,
            &self.options.lpr_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            ImpressServers,
            &self.options.impress_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            RlpServers,
            &self.options.rlp_servers,
        )?;
        Self::put_opt_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            BootFileSize,
            &self.options.boot_file_size,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            MeritDumpFile,
            &self.options.merit_dump_file,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            DomainName,
            &self.options.domain_name,
        )?;
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            SwapServer,
            &self.options.swap_server,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            RootPath,
            &self.options.root_path,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            ExtensionsPath,
            &self.options.extensions_path,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            ForwardOnOff,
            &self.options.forward_on_off,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            NonLocalSourceRouteOnOff,
            &self.options.non_local_source_route_on_off,
        )?;
        Self::put_opt_vec_ipv4_pairs(
            &mut cursors[CURSOR_INDEX_MAIN],
            PolicyFilters,
            &self.options.policy_filters,
        )?;
        Self::put_opt_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            MaxDatagramReassemblySize,
            &self.options.max_datagram_reassembly_size,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            DefaultIpTtl,
            &self.options.default_ip_ttl,
        )?;
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            MtuTimeout,
            &self.options.mtu_timeout,
        )?;
        Self::put_opt_vec_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            MtuPlateau,
            &self.options.mtu_plateau,
        )?;
        Self::put_opt_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            MtuInterface,
            &self.options.mtu_interface,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            MtuSubnet,
            &self.options.mtu_subnet,
        )?;
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            BroadcastAddress,
            &self.options.broadcast_address,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            MaskRecovery,
            &self.options.mask_recovery,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            MaskSupplier,
            &self.options.mask_supplier,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            PerformRouterDiscovery,
            &self.options.perform_router_discovery,
        )?;
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            RouterSolicitationAddress,
            &self.options.router_solicitation_address,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            TrailerEncapsulation,
            &self.options.trailer_encapsulation,
        )?;
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            ArpTimeout,
            &self.options.arp_timeout,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            EthernetEncapsulation,
            &self.options.ethernet_encapsulation,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            DefaultTcpTtl,
            &self.options.default_tcp_ttl,
        )?;
        Self::put_opt_u32(
            &mut cursors[CURSOR_INDEX_MAIN],
            KeepaliveTime,
            &self.options.keepalive_time,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            KeepaliveData,
            &self.options.keepalive_data,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            NisDomain,
            &self.options.nis_domain,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NisServers,
            &self.options.nis_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NtpServers,
            &self.options.ntp_servers,
        )?;
        Self::put_opt_vec(
            &mut cursors[CURSOR_INDEX_MAIN],
            VendorSpecific,
            &self.options.vendor_specific,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetbiosNameServers,
            &self.options.netbios_name_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetbiosDistributionServers,
            &self.options.netbios_distribution_servers,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetbiosNodeType,
            &self.options.netbios_node_type,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetbiosScope,
            &self.options.netbios_scope,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            XWindowFontServers,
            &self.options.x_window_font_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            XWindowManagerServers,
            &self.options.x_window_manager_servers,
        )?;
        Self::put_opt_vec(
            &mut cursors[CURSOR_INDEX_MAIN],
            ClassId,
            &self.options.class_id,
        )?;
        Self::put_opt_vec(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetwareIpDomain,
            &self.options.netware_ip_domain,
        )?;
        Self::put_opt_vec(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetwareIpOption,
            &self.options.netware_ip_option,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            NisDomainName,
            &self.options.nis_v3_domain_name,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NisServerAddress,
            &self.options.nis_v3_servers,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            ServerName,
            &self.options.server_name,
        )?;
        Self::put_opt_string(
            &mut cursors[CURSOR_INDEX_MAIN],
            BootfileName,
            &self.options.bootfile_name,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            HomeAgentAddresses,
            &self.options.home_agent_addresses,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            SmtpServers,
            &self.options.smtp_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            Pop3Servers,
            &self.options.pop3_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NntpServers,
            &self.options.nntp_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            WwwServers,
            &self.options.www_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            FingerServers,
            &self.options.finger_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            IrcServers,
            &self.options.irc_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            StreetTalkServers,
            &self.options.street_talk_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            StdaServers,
            &self.options.stda_servers,
        )?;

        check_remaining!(cursors[CURSOR_INDEX_MAIN], mem::size_of::<u8>());
        cursors[CURSOR_INDEX_MAIN].put_u8(End as u8);
        if cursors[CURSOR_INDEX_FILE].position() > 0 {
            cursors[CURSOR_INDEX_FILE].put_u8(End as u8);
        }
        if cursors[CURSOR_INDEX_SNAME].position() > 0 {
            cursors[CURSOR_INDEX_SNAME].put_u8(End as u8);
        }
        Ok(cursors[CURSOR_INDEX_MAIN].position() as usize)
    }

    /// Cannot be splitted.
    fn put_opt_u8(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<u8>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u8>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u8(*value);
        }
        Ok(())
    }

    /// Cannot be splitted.
    fn put_opt_u16(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<u16>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u16>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u16_be(*value);
        }
        Ok(())
    }

    /// Cannot be splitted.
    fn put_opt_u32(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<u32>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u32_be(*value);
        }
        Ok(())
    }

    /// Cannot be splitted.
    fn put_opt_ipv4(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<Ipv4Addr>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u32_be(u32::from(*value));
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_string(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<String>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put(value);
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<Vec<u8>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put(value);
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec_u16(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<Vec<u16>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len() * mem::size_of::<u16>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u16_be(*element);
            }
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec_ipv4(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<Vec<Ipv4Addr>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len() * mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.to_owned()));
            }
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec_ipv4_pairs(
        cursor: &mut io::Cursor<&mut [u8]>,
        tag: OptionTag,
        value: &Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len() * mem::size_of::<u32>() * 2;
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.0.to_owned()));
                cursor.put_u32_be(u32::from(element.1.to_owned()));
            }
        }
        Ok(())
    }

    /// Can be splitted.
    /// The encoding algorithm explained at [RFC 3442](https://tools.ietf.org/html/rfc3442).
    ///
    /// The option is splitted by default.
    fn put_opt_classless_static_routes(
        cursors: &mut [io::Cursor<&mut [u8]>; CURSOR_INDEX_TOTAL],
        tag: OptionTag,
        value: &Option<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }

            const BITS_IN_BYTE: usize = 8;
            const IPV4_BITSIZE: usize = mem::size_of::<u32>() * BITS_IN_BYTE;
            const MAX_DESCRIPTOR_SIZE: usize = 1 + mem::size_of::<u32>();

            let mut descriptors = Vec::<Vec<u8>>::with_capacity(value.len());
            for element in value.iter() {
                let subnet_number = element.0;
                let i_subnet_mask = u32::from(element.1);
                let mut subnet_mask_size = 0;

                for i in 0..IPV4_BITSIZE {
                    if i_subnet_mask & (1 << i) != 0 {
                        subnet_mask_size = 32 - i;
                        break;
                    }
                }
                let mut descriptor = Vec::<u8>::with_capacity(MAX_DESCRIPTOR_SIZE);
                descriptor.push(subnet_mask_size as u8);
                for i in 0..mem::size_of::<u32>() {
                    if subnet_mask_size > i * BITS_IN_BYTE {
                        descriptor.push(subnet_number.octets()[i]);
                    }
                }
                descriptors.push(descriptor);
            }

            let (mut i, mut j, mut c) = (0, 0, 0); // iterators
            while c < cursors.len() {
                let mut cursor = &mut cursors[c];
                let affix_len = if c != CURSOR_INDEX_MAIN {
                    SIZE_OPTION_AFFIXES // only the tag, the length and the END
                } else {
                    SIZE_OPTION_MAIN_AFFIXES // also some space for the 'overload' option
                };

                let mut len: usize = 0; // the length to be written by each cursor
                let mut repeat = false;
                while j < descriptors.len() {
                    let size = descriptors.get(j).unwrap().len() + mem::size_of::<u32>();

                    // find the range that can be written to the current buffer and the current option instance
                    if cursor.remaining() >= affix_len + len + size && len + size <= SIZE_OPTION_MAX
                    {
                        len += size;
                        j += 1;
                    } else {
                        repeat = len + size > SIZE_OPTION_MAX;
                        break;
                    }
                }

                if len > 0 {
                    cursor.put_u8(tag as u8);
                    cursor.put_u8(len as u8);
                    for k in i..j {
                        cursor.put(descriptors.get(k).unwrap());
                        cursor.put_u32_be(u32::from(value.get(k).unwrap().2.to_owned()));
                    }
                    i = j;
                    if !repeat {
                        c += 1;
                    }
                }

                if j >= descriptors.len() {
                    break;
                }
            }
            if j < descriptors.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "No more space left",
                ));
            }
        }
        Ok(())
    }
}
