//! DHCP message deserialization module.

use std::{
    io,
    mem,
    net::Ipv4Addr,
};

use bytes::Buf;
use eui48::{
    MacAddress,
    EUI48LEN,
};

use super::{
    Message,
    options::{
        Options,
        Overload,
        OptionTag::*,
    },
    constants::*,
};

/// Checks if there is enough space in buffer to get a value.
macro_rules! check_remaining(
    ($cursor:expr, $length:expr) => (
        if $cursor.remaining() < $length {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Packet is too small"));
        }
    )
);

/// Checks if the vector size in bytes is divisible by the length of its element.
macro_rules! check_divisibility(
    ($len:expr, $divider:expr) => (
        if $len % $divider != 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Divisibility check failed"));
        }
    )
);

/// A range from the current cursor position to the specified distance.
macro_rules! distance(
    ($cursor:expr, $distance:expr) => (
        ($cursor.position() as usize)..(($cursor.position() as usize) + $distance)
    )
);

impl Message {
    /// DHCP message deserialization.
    ///
    /// # Errors
    /// `io::Error` if the packet is abrupted, too small or contains invalid length octets.
    pub fn from_bytes(src: &[u8]) -> io::Result<Self> {
        let mut cursor = ::std::io::Cursor::new(src.as_ref());
        check_remaining!(cursor, OFFSET_OPTIONS);

        let mut message = Message{
            operation_code: cursor.get_u8().into(),
            hardware_type: cursor.get_u8().into(),
            hardware_address_length: cursor.get_u8(),
            hardware_options: cursor.get_u8(),
            transaction_id: cursor.get_u32_be(),
            seconds: cursor.get_u16_be(),
            is_broadcast: cursor.get_u16_be() & 0x0001 == 1,
            client_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            your_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            server_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            gateway_ip_address: Ipv4Addr::from(cursor.get_u32_be()),
            client_hardware_address: match MacAddress::from_bytes(&src[distance!(cursor, EUI48LEN)]) {
                Ok(address) => {
                    cursor.advance(SIZE_HARDWARE_ADDRESS);
                    address
                },
                Err(_) => panic!("MacAddress::from_bytes must always succeed"),
            },
            server_name: {
                let string = String::from_utf8_lossy(&src[distance!(cursor, SIZE_SERVER_NAME)]).into();
                cursor.advance(SIZE_SERVER_NAME);
                string
            },
            boot_filename: {
                let string = String::from_utf8_lossy(&src[distance!(cursor, SIZE_BOOT_FILENAME)]).into();
                cursor.advance(SIZE_BOOT_FILENAME);
                string
            },
            options: Options::default(),
        };

        if cursor.get_u32_be() != MAGIC_COOKIE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "MAGIC_COOKIE"));
        }

        Self::append_options(&mut cursor, &mut message.options)?;
        match message.options.overload {
            Some(Overload::File) => {
                let mut cursor = ::std::io::Cursor::new(&src[OFFSET_BOOT_FILENAME..SIZE_BOOT_FILENAME]);
                Self::append_options(&mut cursor, &mut message.options)?;
            },
            Some(Overload::Sname) => {
                let mut cursor = ::std::io::Cursor::new(&src[OFFSET_SERVER_NAME..SIZE_SERVER_NAME]);
                Self::append_options(&mut cursor, &mut message.options)?;
            },
            Some(Overload::Both) => {
                let mut cursor = ::std::io::Cursor::new(&src[OFFSET_BOOT_FILENAME..SIZE_BOOT_FILENAME]);
                Self::append_options(&mut cursor, &mut message.options)?;
                let mut cursor = ::std::io::Cursor::new(&src[OFFSET_SERVER_NAME..SIZE_SERVER_NAME]);
                Self::append_options(&mut cursor, &mut message.options)?;
            },
            _ => {},
        }

        Ok(message)
    }

    fn append_options(mut cursor: &mut io::Cursor<&[u8]>, options: &mut Options) -> io::Result<()> {
        while cursor.remaining() > 0 {
            check_remaining!(cursor, mem::size_of::<u8>());
            let tag = cursor.get_u8();
            match tag.into() {
                SubnetMask                  => options.subnet_mask = Some(Self::get_ipv4(&mut cursor)?),
                TimeOffset                  => options.time_offset = Some(Self::get_u32(&mut cursor)?),
                Routers                     => options.routers = Some(Self::get_vec_ipv4(&mut cursor)?),
                TimeServers                 => options.time_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NameServers                 => options.name_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                DomainNameServers           => options.domain_name_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                LogServers                  => options.log_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                QuotesServers               => options.quotes_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                LprServers                  => options.lpr_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                ImpressServers              => options.impress_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                RlpServers                  => options.rlp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                Hostname                    => options.hostname = Some(Self::get_string(&mut cursor)?),
                BootFileSize                => options.boot_file_size = Some(Self::get_u16(&mut cursor)?),
                MeritDumpFile               => options.merit_dump_file = Some(Self::get_string(&mut cursor)?),
                DomainName                  => options.domain_name = Some(Self::get_string(&mut cursor)?),
                SwapServer                  => options.swap_server = Some(Self::get_ipv4(&mut cursor)?),
                RootPath                    => options.root_path = Some(Self::get_string(&mut cursor)?),
                ExtensionsPath              => options.extensions_path = Some(Self::get_string(&mut cursor)?),
                ForwardOnOff                => options.forward_on_off = Some(Self::get_u8(&mut cursor)?),
                NonLocalSourceRouteOnOff    => options.non_local_source_route_on_off = Some(Self::get_u8(&mut cursor)?),
                PolicyFilters               => options.policy_filters = Some(Self::get_vec_ipv4_pairs(&mut cursor)?),
                MaxDatagramReassemblySize   => options.max_datagram_reassembly_size = Some(Self::get_u16(&mut cursor)?),
                DefaultIpTtl                => options.default_ip_ttl = Some(Self::get_u8(&mut cursor)?),
                MtuTimeout                  => options.mtu_timeout = Some(Self::get_u32(&mut cursor)?),
                MtuPlateau                  => options.mtu_plateau = Some(Self::get_vec_u16(&mut cursor)?),
                MtuInterface                => options.mtu_interface = Some(Self::get_u16(&mut cursor)?),
                MtuSubnet                   => options.mtu_subnet = Some(Self::get_u8(&mut cursor)?),
                BroadcastAddress            => options.broadcast_address = Some(Self::get_ipv4(&mut cursor)?),
                MaskRecovery                => options.mask_recovery = Some(Self::get_u8(&mut cursor)?),
                MaskSupplier                => options.mask_supplier = Some(Self::get_u8(&mut cursor)?),
                PerformRouterDiscovery      => options.perform_router_discovery = Some(Self::get_u8(&mut cursor)?),
                RouterSolicitationAddress   => options.router_solicitation_address = Some(Self::get_ipv4(&mut cursor)?),
                StaticRoutes                => options.static_routes = Some(Self::get_vec_ipv4_pairs(&mut cursor)?),
                TrailerEncapsulation        => options.trailer_encapsulation = Some(Self::get_u8(&mut cursor)?),
                ArpTimeout                  => options.arp_timeout = Some(Self::get_u32(&mut cursor)?),
                EthernetEncapsulation       => options.ethernet_encapsulation = Some(Self::get_u8(&mut cursor)?),
                DefaultTcpTtl               => options.default_tcp_ttl = Some(Self::get_u8(&mut cursor)?),
                KeepaliveTime               => options.keepalive_time = Some(Self::get_u32(&mut cursor)?),
                KeepaliveData               => options.keepalive_data = Some(Self::get_u8(&mut cursor)?),
                NisDomain                   => options.nis_domain = Some(Self::get_string(&mut cursor)?),
                NisServers                  => options.nis_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NtpServers                  => options.ntp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                VendorSpecific              => options.vendor_specific = Some(Self::get_vec(&mut cursor)?),
                NetbiosNameServers          => options.netbios_name_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NetbiosDistributionServers  => options.netbios_distribution_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NetbiosNodeType             => options.netbios_node_type = Some(Self::get_u8(&mut cursor)?),
                NetbiosScope                => options.netbios_scope = Some(Self::get_string(&mut cursor)?),
                XWindowFontServers          => options.x_window_font_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                XWindowManagerServers       => options.x_window_manager_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                AddressRequest              => options.address_request = Some(Self::get_ipv4(&mut cursor)?),
                AddressTime                 => options.address_time = Some(Self::get_u32(&mut cursor)?),
                Overload                    => options.overload = Some(Self::get_u8(&mut cursor)?.into()),
                DhcpMessageType             => options.dhcp_message_type = Some(Self::get_u8(&mut cursor)?.into()),
                DhcpServerId                => options.dhcp_server_id = Some(Self::get_ipv4(&mut cursor)?),
                ParameterList               => options.parameter_list = Some(Self::get_vec(&mut cursor)?),
                DhcpMessage                 => options.dhcp_message = Some(Self::get_string(&mut cursor)?),
                DhcpMaxMessageSize          => options.dhcp_max_message_size = Some(Self::get_u16(&mut cursor)?),
                RenewalTime                 => options.renewal_time = Some(Self::get_u32(&mut cursor)?),
                RebindingTime               => options.rebinding_time = Some(Self::get_u32(&mut cursor)?),
                ClassId                     => options.class_id = Some(Self::get_vec(&mut cursor)?),
                ClientId                    => options.client_id = Some(Self::get_vec(&mut cursor)?),
                NetwareIpDomain             => options.netware_ip_domain = Some(Self::get_vec(&mut cursor)?),
                NetwareIpOption             => options.netware_ip_option = Some(Self::get_vec(&mut cursor)?),
                NisDomainName               => options.nis_v3_domain_name = Some(Self::get_string(&mut cursor)?),
                NisServerAddress            => options.nis_v3_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                ServerName                  => options.server_name = Some(Self::get_string(&mut cursor)?),
                BootfileName                => options.bootfile_name = Some(Self::get_string(&mut cursor)?),
                HomeAgentAddresses          => options.home_agent_addresses = Some(Self::get_vec_ipv4(&mut cursor)?),
                SmtpServers                 => options.smtp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                Pop3Servers                 => options.pop3_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NntpServers                 => options.nntp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                WwwServers                  => options.www_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                FingerServers               => options.finger_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                IrcServers                  => options.irc_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                StreetTalkServers           => options.street_talk_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                StdaServers                 => options.stda_servers = Some(Self::get_vec_ipv4(&mut cursor)?),

                End => break,
                Pad => continue,
                Unknown => Self::skip(&mut cursor)?,
            }
        }
        Ok(())
    }

    fn get_u8(cursor: &mut io::Cursor<&[u8]>) -> io::Result<u8> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value = cursor.get_u8();
        Ok(value)
    }

    fn get_u16(cursor: &mut io::Cursor<&[u8]>) -> io::Result<u16> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value = cursor.get_u16_be();
        Ok(value)
    }

    fn get_u32(cursor: &mut io::Cursor<&[u8]>) -> io::Result<u32> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value = cursor.get_u32_be();
        Ok(value)
    }

    fn get_ipv4(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Ipv4Addr> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value = cursor.get_u32_be();
        Ok(Ipv4Addr::from(value))
    }

    fn get_string(cursor: &mut io::Cursor<&[u8]>) -> io::Result<String> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value = String::from_utf8_lossy(&cursor.bytes()[..len]).into();
        cursor.advance(len);
        Ok(value)
    }

    fn get_vec(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Vec<u8>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value: Vec<u8> = cursor.bytes()[..len].to_vec();
        cursor.advance(len);
        Ok(value)
    }

    fn get_vec_u16(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Vec<u16>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        let element_size = mem::size_of::<u16>();
        check_divisibility!(len, element_size);
        check_remaining!(cursor, len);
        let amount = len / element_size;
        let mut value = Vec::with_capacity(amount);
        for _ in 0..amount {
            check_remaining!(cursor, element_size);
            value.push(cursor.get_u16_be());
        }
        Ok(value)
    }

    fn get_vec_ipv4(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Vec<Ipv4Addr>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        let element_size = mem::size_of::<u32>();
        check_divisibility!(len, element_size);
        check_remaining!(cursor, len);
        let amount = len / element_size;
        let mut value = Vec::with_capacity(amount);
        for _ in 0..amount {
            check_remaining!(cursor, element_size);
            value.push(Ipv4Addr::from(cursor.get_u32_be()))
        }
        Ok(value)
    }

    fn get_vec_ipv4_pairs(cursor: &mut io::Cursor<&[u8]>) -> io::Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        let element_size = mem::size_of::<u32>() * 2;
        check_divisibility!(len, element_size);
        check_remaining!(cursor, len);
        let amount = len / element_size;
        let mut value = Vec::with_capacity(amount);
        for _ in 0..amount {
            check_remaining!(cursor, element_size);
            value.push((Ipv4Addr::from(cursor.get_u32_be()), Ipv4Addr::from(cursor.get_u32_be())))
        }
        Ok(value)
    }

    fn skip(cursor: &mut io::Cursor<&[u8]>) -> io::Result<()> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        cursor.advance(len);
        Ok(())
    }
}