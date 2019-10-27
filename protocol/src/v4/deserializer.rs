//! DHCP message deserialization module.

use std::{io, mem, net::Ipv4Addr};

use bytes::Buf;
use eui48::{EUI48LEN, MacAddress};

use super::{
    constants::*,
    options::{OptionTag::*, Options, Overload},
    Message,
};

/// Checks if there is enough space in buffer to get a value.
macro_rules! check_remaining(
    ($cursor:expr, $length:expr) => (
        if $cursor.remaining() < $length {
            return Err(
                io::Error::new(io::ErrorKind::UnexpectedEof,
                "Buffer is too small or packet has invalid length octets",
            ));
        }
    );
);

/// Checks if the length octet contains correct length for each type and is not zero.
macro_rules! check_length(
    ($len:expr) => (
        if $len == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Length octet is zero"));
        }
    );
    ($len:expr, $correct:expr) => (
        if $len != $correct {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Length octet is invalid"));
        }
    );
);

/// Checks if the vector size in bytes is divisible by the length of its element.
macro_rules! check_divisibility(
    ($len:expr, $divider:expr) => (
        if $len % $divider != 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Divisibility check failed"));
        }
    );
);

/// A range from the current cursor position to the specified distance.
macro_rules! distance(
    ($cursor:expr, $distance:expr) => (
        ($cursor.position() as usize)..(($cursor.position() as usize) + $distance)
    );
);

impl Message {
    /// DHCP message deserialization.
    ///
    /// # Errors
    /// `io::Error` if the packet is abrupted, too small or contains invalid length octets.
    pub fn from_bytes(src: &[u8]) -> io::Result<Self> {
        let mut cursor = ::std::io::Cursor::new(src.as_ref());
        check_remaining!(cursor, OFFSET_OPTIONS);

        let mut message = Message {
            operation_code: cursor.get_u8().into(),
            hardware_type: cursor.get_u8().into(),
            hardware_address_length: cursor.get_u8(),
            hardware_options: cursor.get_u8(),
            transaction_id: cursor.get_u32_be(),
            seconds: cursor.get_u16_be(),
            // https://tools.ietf.org/html/rfc2131#section-2
            // https://tools.ietf.org/html/rfc1700#page-3
            // Leftmost bit (0 bit) is most significant
            is_broadcast: cursor.get_u16_be() & 0x8000 != 0,
            client_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            your_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            server_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            gateway_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            client_hardware_address: match MacAddress::from_bytes(&src[distance!(cursor, EUI48LEN)])
            {
                Ok(address) => {
                    cursor.advance(SIZE_HARDWARE_ADDRESS);
                    address
                }
                Err(_) => panic!("MacAddress::from_bytes must always succeed"),
            },
            server_name: {
                let vec = Vec::from(&src[distance!(cursor, SIZE_SERVER_NAME)]);
                cursor.advance(SIZE_SERVER_NAME);
                vec
            },
            boot_filename: {
                let vec = Vec::from(&src[distance!(cursor, SIZE_BOOT_FILENAME)]);
                cursor.advance(SIZE_BOOT_FILENAME);
                vec
            },
            options: Options::default(),
        };

        if cursor.get_u32_be() != MAGIC_COOKIE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "MAGIC_COOKIE"));
        }

        Self::append_options(&mut cursor, &mut message.options)?;
        match message.options.overload {
            Some(Overload::File) => {
                let mut cursor =
                    ::std::io::Cursor::new(&src[OFFSET_BOOT_FILENAME..OFFSET_MAGIC_COOKIE]);
                Self::append_options(&mut cursor, &mut message.options)?;
            }
            Some(Overload::Sname) => {
                let mut cursor =
                    ::std::io::Cursor::new(&src[OFFSET_SERVER_NAME..OFFSET_BOOT_FILENAME]);
                Self::append_options(&mut cursor, &mut message.options)?;
            }
            Some(Overload::Both) => {
                let mut cursor =
                    ::std::io::Cursor::new(&src[OFFSET_BOOT_FILENAME..OFFSET_MAGIC_COOKIE]);
                Self::append_options(&mut cursor, &mut message.options)?;
                let mut cursor =
                    ::std::io::Cursor::new(&src[OFFSET_SERVER_NAME..OFFSET_BOOT_FILENAME]);
                Self::append_options(&mut cursor, &mut message.options)?;
            }
            _ => {}
        }

        Ok(message)
    }

    fn append_options(mut cursor: &mut io::Cursor<&[u8]>, options: &mut Options) -> io::Result<()> {
        while cursor.remaining() > 0 {
            check_remaining!(cursor, mem::size_of::<u8>());
            let tag = cursor.get_u8();
            match tag.into() {
                // unsplittable options
                TimeOffset => options.time_offset = Some(Self::get_opt_u32(&mut cursor)?),
                SubnetMask => options.subnet_mask = Some(Self::get_opt_ipv4(&mut cursor)?),
                BootFileSize => options.boot_file_size = Some(Self::get_opt_u16(&mut cursor)?),
                SwapServer => options.swap_server = Some(Self::get_opt_ipv4(&mut cursor)?),
                ForwardOnOff => options.forward_on_off = Some(Self::get_opt_u8(&mut cursor)?),
                NonLocalSourceRouteOnOff => {
                    options.non_local_source_route_on_off = Some(Self::get_opt_u8(&mut cursor)?)
                }
                MaxDatagramReassemblySize => {
                    options.max_datagram_reassembly_size = Some(Self::get_opt_u16(&mut cursor)?)
                }
                DefaultIpTtl => options.default_ip_ttl = Some(Self::get_opt_u8(&mut cursor)?),
                MtuTimeout => options.mtu_timeout = Some(Self::get_opt_u32(&mut cursor)?),
                MtuInterface => options.mtu_interface = Some(Self::get_opt_u16(&mut cursor)?),
                MtuSubnet => options.mtu_subnet = Some(Self::get_opt_u8(&mut cursor)?),
                BroadcastAddress => {
                    options.broadcast_address = Some(Self::get_opt_ipv4(&mut cursor)?)
                }
                MaskRecovery => options.mask_recovery = Some(Self::get_opt_u8(&mut cursor)?),
                MaskSupplier => options.mask_supplier = Some(Self::get_opt_u8(&mut cursor)?),
                PerformRouterDiscovery => {
                    options.perform_router_discovery = Some(Self::get_opt_u8(&mut cursor)?)
                }
                RouterSolicitationAddress => {
                    options.router_solicitation_address = Some(Self::get_opt_ipv4(&mut cursor)?)
                }
                TrailerEncapsulation => {
                    options.trailer_encapsulation = Some(Self::get_opt_u8(&mut cursor)?)
                }
                ArpTimeout => options.arp_timeout = Some(Self::get_opt_u32(&mut cursor)?),
                EthernetEncapsulation => {
                    options.ethernet_encapsulation = Some(Self::get_opt_u8(&mut cursor)?)
                }
                DefaultTcpTtl => options.default_tcp_ttl = Some(Self::get_opt_u8(&mut cursor)?),
                KeepaliveTime => options.keepalive_time = Some(Self::get_opt_u32(&mut cursor)?),
                KeepaliveData => options.keepalive_data = Some(Self::get_opt_u8(&mut cursor)?),
                NetbiosNodeType => options.netbios_node_type = Some(Self::get_opt_u8(&mut cursor)?),
                AddressRequest => options.address_request = Some(Self::get_opt_ipv4(&mut cursor)?),
                AddressTime => options.address_time = Some(Self::get_opt_u32(&mut cursor)?),
                Overload => options.overload = Some(Self::get_opt_u8(&mut cursor)?.into()),
                DhcpMessageType => {
                    options.dhcp_message_type = Some(Self::get_opt_u8(&mut cursor)?.into())
                }
                DhcpServerId => options.dhcp_server_id = Some(Self::get_opt_ipv4(&mut cursor)?),
                DhcpMaxMessageSize => {
                    options.dhcp_max_message_size = Some(Self::get_opt_u16(&mut cursor)?)
                }
                RenewalTime => options.renewal_time = Some(Self::get_opt_u32(&mut cursor)?),
                RebindingTime => options.rebinding_time = Some(Self::get_opt_u32(&mut cursor)?),

                // splittable options
                Routers => {
                    options.routers =
                        Some(Self::get_opt_vec_ipv4(&mut cursor, &mut options.routers)?)
                }
                TimeServers => {
                    options.time_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.time_servers,
                    )?)
                }
                NameServers => {
                    options.name_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.name_servers,
                    )?)
                }
                DomainNameServers => {
                    options.domain_name_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.domain_name_servers,
                    )?)
                }
                LogServers => {
                    options.log_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.log_servers,
                    )?)
                }
                QuotesServers => {
                    options.quotes_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.quotes_servers,
                    )?)
                }
                LprServers => {
                    options.lpr_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.lpr_servers,
                    )?)
                }
                ImpressServers => {
                    options.impress_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.impress_servers,
                    )?)
                }
                RlpServers => {
                    options.rlp_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.rlp_servers,
                    )?)
                }
                Hostname => {
                    options.hostname =
                        Some(Self::get_opt_string(&mut cursor, &mut options.hostname)?)
                }
                MeritDumpFile => {
                    options.merit_dump_file = Some(Self::get_opt_string(
                        &mut cursor,
                        &mut options.merit_dump_file,
                    )?)
                }
                DomainName => {
                    options.domain_name =
                        Some(Self::get_opt_string(&mut cursor, &mut options.domain_name)?)
                }
                RootPath => {
                    options.root_path =
                        Some(Self::get_opt_string(&mut cursor, &mut options.root_path)?)
                }
                ExtensionsPath => {
                    options.extensions_path = Some(Self::get_opt_string(
                        &mut cursor,
                        &mut options.extensions_path,
                    )?)
                }
                PolicyFilters => {
                    options.policy_filters = Some(Self::get_opt_vec_ipv4_pairs(
                        &mut cursor,
                        &mut options.policy_filters,
                    )?)
                }
                MtuPlateau => {
                    options.mtu_plateau = Some(Self::get_opt_vec_u16(
                        &mut cursor,
                        &mut options.mtu_plateau,
                    )?)
                }
                StaticRoutes => {
                    options.static_routes = Some(Self::get_opt_vec_ipv4_pairs(
                        &mut cursor,
                        &mut options.static_routes,
                    )?)
                }
                NisDomain => {
                    options.nis_domain =
                        Some(Self::get_opt_string(&mut cursor, &mut options.nis_domain)?)
                }
                NisServers => {
                    options.nis_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.nis_servers,
                    )?)
                }
                NtpServers => {
                    options.ntp_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.ntp_servers,
                    )?)
                }
                VendorSpecific => {
                    options.vendor_specific = Some(Self::get_opt_vec(
                        &mut cursor,
                        &mut options.vendor_specific,
                    )?)
                }
                NetbiosNameServers => {
                    options.netbios_name_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.netbios_name_servers,
                    )?)
                }
                NetbiosDistributionServers => {
                    options.netbios_distribution_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.netbios_distribution_servers,
                    )?)
                }
                NetbiosScope => {
                    options.netbios_scope = Some(Self::get_opt_string(
                        &mut cursor,
                        &mut options.netbios_scope,
                    )?)
                }
                XWindowFontServers => {
                    options.x_window_font_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.x_window_font_servers,
                    )?)
                }
                XWindowManagerServers => {
                    options.x_window_manager_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.x_window_manager_servers,
                    )?)
                }
                ParameterList => {
                    options.parameter_list =
                        Some(Self::get_opt_vec(&mut cursor, &mut options.parameter_list)?)
                }
                DhcpMessage => {
                    options.dhcp_message = Some(Self::get_opt_string(
                        &mut cursor,
                        &mut options.dhcp_message,
                    )?)
                }
                ClassId => {
                    options.class_id = Some(Self::get_opt_vec(&mut cursor, &mut options.class_id)?)
                }
                ClientId => {
                    options.client_id =
                        Some(Self::get_opt_vec(&mut cursor, &mut options.client_id)?)
                }
                NetwareIpDomain => {
                    options.netware_ip_domain = Some(Self::get_opt_vec(
                        &mut cursor,
                        &mut options.netware_ip_domain,
                    )?)
                }
                NetwareIpOption => {
                    options.netware_ip_option = Some(Self::get_opt_vec(
                        &mut cursor,
                        &mut options.netware_ip_option,
                    )?)
                }
                NisDomainName => {
                    options.nis_v3_domain_name = Some(Self::get_opt_string(
                        &mut cursor,
                        &mut options.nis_v3_domain_name,
                    )?)
                }
                NisServerAddress => {
                    options.nis_v3_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.nis_v3_servers,
                    )?)
                }
                ServerName => {
                    options.server_name =
                        Some(Self::get_opt_string(&mut cursor, &mut options.server_name)?)
                }
                BootfileName => {
                    options.bootfile_name = Some(Self::get_opt_string(
                        &mut cursor,
                        &mut options.bootfile_name,
                    )?)
                }
                HomeAgentAddresses => {
                    options.home_agent_addresses = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.home_agent_addresses,
                    )?)
                }
                SmtpServers => {
                    options.smtp_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.smtp_servers,
                    )?)
                }
                Pop3Servers => {
                    options.pop3_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.pop3_servers,
                    )?)
                }
                NntpServers => {
                    options.nntp_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.nntp_servers,
                    )?)
                }
                WwwServers => {
                    options.www_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.www_servers,
                    )?)
                }
                FingerServers => {
                    options.finger_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.finger_servers,
                    )?)
                }
                IrcServers => {
                    options.irc_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.irc_servers,
                    )?)
                }
                StreetTalkServers => {
                    options.street_talk_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.street_talk_servers,
                    )?)
                }
                StdaServers => {
                    options.stda_servers = Some(Self::get_opt_vec_ipv4(
                        &mut cursor,
                        &mut options.stda_servers,
                    )?)
                }
                ClasslessStaticRoutes => {
                    options.classless_static_routes = Some(Self::get_opt_classless_static_routes(
                        &mut cursor,
                        &mut options.classless_static_routes,
                    )?)
                }

                End => break,
                Pad => continue,
                Unknown => Self::skip(&mut cursor)?,
            }
        }
        Ok(())
    }

    /// Cannot be splitted so reassembling not required.
    fn get_opt_u8(cursor: &mut io::Cursor<&[u8]>) -> io::Result<u8> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len, mem::size_of::<u8>());
        check_remaining!(cursor, len);
        let value = cursor.get_u8();
        Ok(value)
    }

    /// Cannot be splitted so reassembling not required.
    fn get_opt_u16(cursor: &mut io::Cursor<&[u8]>) -> io::Result<u16> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len, mem::size_of::<u16>());
        check_remaining!(cursor, len);
        let value = cursor.get_u16_be();
        Ok(value)
    }

    /// Cannot be splitted so reassembling not required.
    fn get_opt_u32(cursor: &mut io::Cursor<&[u8]>) -> io::Result<u32> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len, mem::size_of::<u32>());
        check_remaining!(cursor, len);
        let value = cursor.get_u32_be();
        Ok(value)
    }

    /// Cannot be splitted so reassembling not required.
    fn get_opt_ipv4(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Ipv4Addr> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len, mem::size_of::<u32>());
        check_remaining!(cursor, len);
        let value = cursor.get_u32_be();
        Ok(Ipv4Addr::from(value))
    }

    /// Can be splitted so values are appended if an option already contains some data.
    fn get_opt_string(
        cursor: &mut io::Cursor<&[u8]>,
        option: &mut Option<String>,
    ) -> io::Result<String> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len);
        check_remaining!(cursor, len);
        let value = String::from_utf8_lossy(&cursor.bytes()[..len]).to_string();
        cursor.advance(len);
        if let Some(ref mut data) = option {
            Ok(data.to_owned() + value.as_ref())
        } else {
            Ok(value)
        }
    }

    /// Can be splitted so values are appended if an option already contains some data.
    fn get_opt_vec(
        cursor: &mut io::Cursor<&[u8]>,
        option: &mut Option<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len);
        check_remaining!(cursor, len);
        let mut value: Vec<u8> = cursor.bytes()[..len].to_vec();
        cursor.advance(len);
        if let Some(ref mut data) = option {
            data.append(value.as_mut());
            Ok(data.to_owned())
        } else {
            Ok(value)
        }
    }

    /// Can be splitted so values are appended if an option already contains some data.
    fn get_opt_vec_u16(
        cursor: &mut io::Cursor<&[u8]>,
        option: &mut Option<Vec<u16>>,
    ) -> io::Result<Vec<u16>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len);
        let element_size = mem::size_of::<u16>();
        check_divisibility!(len, element_size);
        check_remaining!(cursor, len);
        let amount = len / element_size;
        let mut value = Vec::with_capacity(amount);
        for _ in 0..amount {
            check_remaining!(cursor, element_size);
            value.push(cursor.get_u16_be());
        }
        if let Some(ref mut data) = option {
            data.append(value.as_mut());
            Ok(data.to_owned())
        } else {
            Ok(value)
        }
    }

    /// Can be splitted so values are appended if an option already contains some data.
    fn get_opt_vec_ipv4(
        cursor: &mut io::Cursor<&[u8]>,
        option: &mut Option<Vec<Ipv4Addr>>,
    ) -> io::Result<Vec<Ipv4Addr>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len);
        let element_size = mem::size_of::<u32>();
        check_divisibility!(len, element_size);
        check_remaining!(cursor, len);
        let amount = len / element_size;
        let mut value = Vec::with_capacity(amount);
        for _ in 0..amount {
            check_remaining!(cursor, element_size);
            value.push(Ipv4Addr::from(cursor.get_u32_be()))
        }
        if let Some(ref mut data) = option {
            data.append(value.as_mut());
            Ok(data.to_owned())
        } else {
            Ok(value)
        }
    }

    /// Can be splitted so values are appended if an option already contains some data.
    fn get_opt_vec_ipv4_pairs(
        cursor: &mut io::Cursor<&[u8]>,
        option: &mut Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len);
        let element_size = mem::size_of::<u32>() * 2;
        check_divisibility!(len, element_size);
        check_remaining!(cursor, len);
        let amount = len / element_size;
        let mut value = Vec::with_capacity(amount);
        for _ in 0..amount {
            check_remaining!(cursor, element_size);
            value.push((
                Ipv4Addr::from(cursor.get_u32_be()),
                Ipv4Addr::from(cursor.get_u32_be()),
            ))
        }
        if let Some(ref mut data) = option {
            data.append(value.as_mut());
            Ok(data.to_owned())
        } else {
            Ok(value)
        }
    }

    /// Can be splitted so values are appended if an option already contains some data.
    /// The encoding algorithm explained at [RFC 3442](https://tools.ietf.org/html/rfc3442).
    fn get_opt_classless_static_routes(
        cursor: &mut io::Cursor<&[u8]>,
        option: &mut Option<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>> {
        const BITS_IN_BYTE: usize = 8;
        const IPV4_BYTESIZE: usize = mem::size_of::<u32>();
        const IPV4_BITSIZE: usize = IPV4_BYTESIZE * BITS_IN_BYTE;
        const MIN_ELEMENT_SIZE: usize = 1 + IPV4_BYTESIZE;

        check_remaining!(cursor, mem::size_of::<u8>());
        let mut len = cursor.get_u8() as usize;
        check_length!(len);
        check_remaining!(cursor, len);
        let mut value = Vec::with_capacity(len / MIN_ELEMENT_SIZE);
        while len > 0 {
            let subnet_mask_len = cursor.get_u8() as usize;
            let subnet_mask_i =
                (<u32>::max_value() as u64 + 1) - 2u64.pow((IPV4_BITSIZE - subnet_mask_len) as u32);

            let mut subnet_number_len = 0;
            let mut subnet_number_a: [u8; IPV4_BYTESIZE] = [0u8; IPV4_BYTESIZE];
            for i in 0..4 {
                if subnet_mask_len > i * BITS_IN_BYTE {
                    subnet_number_len += 1;
                    subnet_number_a[i] = cursor.get_u8();
                }
            }
            len -= MIN_ELEMENT_SIZE + subnet_number_len;

            let subnet_number = Ipv4Addr::from(subnet_number_a);
            let subnet_mask = Ipv4Addr::from(subnet_mask_i as u32);
            let router = Ipv4Addr::from(cursor.get_u32_be());
            value.push((subnet_number, subnet_mask, router));
        }
        if let Some(ref mut data) = option {
            data.append(value.as_mut());
            Ok(data.to_owned())
        } else {
            Ok(value)
        }
    }

    fn skip(cursor: &mut io::Cursor<&[u8]>) -> io::Result<()> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_length!(len);
        check_remaining!(cursor, len);
        cursor.advance(len);
        Ok(())
    }
}
