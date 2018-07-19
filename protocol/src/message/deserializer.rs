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

use message::{
    Message,
    options::{
        Options,
        MessageType,
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
    /// `io::Error` on parsing error.
    pub fn from_bytes(src: &[u8]) -> io::Result<Self> {
        println!("{:?}", src);

        let mut cursor = ::std::io::Cursor::new(src.as_ref());
        check_remaining!(cursor, SIZE_HEADER_MINIMAL);

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
            options: Options::new(),
        };

        if cursor.get_u32_be() != MAGIC_COOKIE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "MAGIC_COOKIE"));
        }

        while cursor.remaining() > 0 {
            check_remaining!(cursor, mem::size_of::<u8>());
            let tag = cursor.get_u8();
            match tag.into() {
                SubnetMask                  => message.options.subnet_mask = Some(Self::get_ipv4(&mut cursor)?),
                TimeOffset                  => message.options.time_offset = Some(Self::get_u32(&mut cursor)?),
                Routers                     => message.options.routers = Some(Self::get_vec_ipv4(&mut cursor)?),
                TimeServers                 => message.options.time_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NameServers                 => message.options.name_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                DomainNameServers           => message.options.domain_name_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                LogServers                  => message.options.log_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                QuotesServers               => message.options.quotes_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                LprServers                  => message.options.lpr_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                ImpressServers              => message.options.impress_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                RlpServers                  => message.options.rlp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                Hostname                    => message.options.hostname = Some(Self::get_string(&mut cursor)?),
                BootFileSize                => message.options.boot_file_size = Some(Self::get_u16(&mut cursor)?),
                MeritDumpFile               => message.options.merit_dump_file = Some(Self::get_string(&mut cursor)?),
                DomainName                  => message.options.domain_name = Some(Self::get_string(&mut cursor)?),
                SwapServer                  => message.options.swap_server = Some(Self::get_ipv4(&mut cursor)?),
                RootPath                    => message.options.root_path = Some(Self::get_string(&mut cursor)?),
                ExtensionsPath              => message.options.extensions_path = Some(Self::get_string(&mut cursor)?),
                ForwardOnOff                => message.options.forward_on_off = Some(Self::get_u8(&mut cursor)?),
                NonLocalSourceRouteOnOff    => message.options.non_local_source_route_on_off = Some(Self::get_u8(&mut cursor)?),
                PolicyFilters               => message.options.policy_filters = Some(Self::get_vec_ipv4_pairs(&mut cursor)?),
                MaxDatagramReassemblySize   => message.options.max_datagram_reassembly_size = Some(Self::get_u16(&mut cursor)?),
                DefaultIpTtl                => message.options.default_ip_ttl = Some(Self::get_u8(&mut cursor)?),
                MtuTimeout                  => message.options.mtu_timeout = Some(Self::get_u32(&mut cursor)?),
                MtuPlateau                  => message.options.mtu_plateau = Some(Self::get_vec_u16(&mut cursor)?),
                MtuInterface                => message.options.mtu_interface = Some(Self::get_u16(&mut cursor)?),
                MtuSubnet                   => message.options.mtu_subnet = Some(Self::get_u8(&mut cursor)?),
                BroadcastAddress            => message.options.broadcast_address = Some(Self::get_ipv4(&mut cursor)?),
                MaskRecovery                => message.options.mask_recovery = Some(Self::get_u8(&mut cursor)?),
                MaskSupplier                => message.options.mask_supplier = Some(Self::get_u8(&mut cursor)?),
                PerformRouterDiscovery      => message.options.perform_router_discovery = Some(Self::get_u8(&mut cursor)?),
                RouterSolicitationAddress   => message.options.router_solicitation_address = Some(Self::get_ipv4(&mut cursor)?),
                StaticRoutes                => message.options.static_routes = Some(Self::get_vec_ipv4_pairs(&mut cursor)?),
                TrailerEncapsulation        => message.options.trailer_encapsulation = Some(Self::get_u8(&mut cursor)?),
                ArpTimeout                  => message.options.arp_timeout = Some(Self::get_u32(&mut cursor)?),
                EthernetEncapsulation       => message.options.ethernet_encapsulation = Some(Self::get_u8(&mut cursor)?),
                DefaultTcpTtl               => message.options.default_tcp_ttl = Some(Self::get_u8(&mut cursor)?),
                KeepaliveTime               => message.options.keepalive_time = Some(Self::get_u32(&mut cursor)?),
                KeepaliveData               => message.options.keepalive_data = Some(Self::get_u8(&mut cursor)?),
                NisDomain                   => message.options.nis_domain = Some(Self::get_string(&mut cursor)?),
                NisServers                  => message.options.nis_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NtpServers                  => message.options.ntp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                VendorSpecific              => message.options.vendor_specific = Some(Self::get_vec(&mut cursor)?),
                NetbiosNameServers          => message.options.netbios_name_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NetbiosDistributionServers  => message.options.netbios_distribution_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NetbiosNodeType             => message.options.netbios_node_type = Some(Self::get_u8(&mut cursor)?),
                NetbiosScope                => message.options.netbios_scope = Some(Self::get_string(&mut cursor)?),
                XWindowFontServers          => message.options.x_window_font_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                XWindowManagerServers       => message.options.x_window_manager_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                AddressRequest              => message.options.address_request = Some(Self::get_ipv4(&mut cursor)?),
                AddressTime                 => message.options.address_time = Some(Self::get_u32(&mut cursor)?),
                Overload                    => message.options.overload = Some(Self::get_u8(&mut cursor)?),
                DhcpMessageType             => message.options.dhcp_message_type = Some(Self::get_message_type(&mut cursor)?),
                DhcpServerId                => message.options.dhcp_server_id = Some(Self::get_ipv4(&mut cursor)?),
                ParameterList               => message.options.parameter_list = Some(Self::get_vec(&mut cursor)?),
                DhcpMessage                 => message.options.dhcp_message = Some(Self::get_string(&mut cursor)?),
                DhcpMaxMessageSize          => message.options.dhcp_max_message_size = Some(Self::get_u16(&mut cursor)?),
                RenewalTime                 => message.options.renewal_time = Some(Self::get_u32(&mut cursor)?),
                RebindingTime               => message.options.rebinding_time = Some(Self::get_u32(&mut cursor)?),
                ClassId                     => message.options.class_id = Some(Self::get_vec(&mut cursor)?),
                ClientId                    => message.options.client_id = Some(Self::get_vec(&mut cursor)?),
                NetwareIpDomain             => message.options.netware_ip_domain = Some(Self::get_vec(&mut cursor)?),
                NetwareIpOption             => message.options.netware_ip_option = Some(Self::get_vec(&mut cursor)?),
                NisDomainName               => message.options.nis_v3_domain_name = Some(Self::get_string(&mut cursor)?),
                NisServerAddress            => message.options.nis_v3_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                ServerName                  => message.options.server_name = Some(Self::get_string(&mut cursor)?),
                BootfileName                => message.options.bootfile_name = Some(Self::get_string(&mut cursor)?),
                HomeAgentAddresses          => message.options.home_agent_addresses = Some(Self::get_vec_ipv4(&mut cursor)?),
                SmtpServers                 => message.options.smtp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                Pop3Servers                 => message.options.pop3_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                NntpServers                 => message.options.nntp_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                WwwServers                  => message.options.www_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                FingerServers               => message.options.finger_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                IrcServers                  => message.options.irc_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                StreetTalkServers           => message.options.street_talk_servers = Some(Self::get_vec_ipv4(&mut cursor)?),
                StdaServers                 => message.options.stda_servers = Some(Self::get_vec_ipv4(&mut cursor)?),

                End => break,
                Pad => continue,
                Unknown => Self::skip(&mut cursor)?,
            }
        }
        Ok(message)
    }

    fn get_message_type(cursor: &mut io::Cursor<&[u8]>) -> io::Result<MessageType> {
        check_remaining!(cursor, mem::size_of::<u8>());
        let len = cursor.get_u8() as usize;
        check_remaining!(cursor, len);
        let value = cursor.get_u8();
        Ok(value.into())
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