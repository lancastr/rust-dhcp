//! DHCP message deserialization module (using `nom`).

use std::net::Ipv4Addr;

use nom::*;
use eui48::{
    MacAddress,
    EUI48LEN,
};

use message::{
    Message,
};
use options::{
    Options,
    OptionTag::{
        self,
        *,
    },
    MessageType,
};
use super::constants::*;

// CAN'T PARSE THIS
// [
//  50,   4, 192, 168,   0, 100,  12,   7,
//  68, 117, 122,  97,  45, 143, 138,  60,
//   8,  77,  83,  70,  84,  32,  53,  46,
//  48,  55,  12,   1,  15,   3,   6,  44,
//  46,  47,  31,  33, 121, 249,  43, 255,
//   0,   0,   0,   0,   0,   0,   0,   0
// ]
named!(pub parse_message<&[u8], Message>,
    do_parse!(
        operation_code              : map!(be_u8, |v| v.into()) >>
        hardware_type               : map!(be_u8, |v| v.into()) >>
        hardware_address_length     : be_u8 >>
        hardware_options            : be_u8 >>

        transaction_id              : be_u32 >>
        seconds                     : be_u16 >>
        flags                       : bits!(take_bits!(u16, SIZE_FLAGS)) >>

        client_ip_address           : map!(be_u32, Ipv4Addr::from) >>
        your_ip_address             : map!(be_u32, Ipv4Addr::from) >>
        server_ip_address           : map!(be_u32, Ipv4Addr::from) >>
        gateway_ip_address          : map!(be_u32, Ipv4Addr::from) >>

        client_hardware_address     : map!(take!(SIZE_HARDWARE_ADDRESS), |v| MacAddress::from_bytes(&v[..EUI48LEN]).unwrap_or_default()) >>
        server_name                 : map!(take!(SIZE_SERVER_NAME), |v| String::from_utf8_lossy(v).to_string()) >>
        boot_filename               : map!(take!(SIZE_BOOT_FILENAME), |v| String::from_utf8_lossy(v).to_string()) >>

                                      tag!(MAGIC_COOKIE) >>
        subnet_mask                 : opt!(preceded!(tag!(&[SubnetMask as u8])         , option_u32_to_ipv4)) >>
        routers                     : opt!(preceded!(tag!(&[Routers as u8])            , option_bytes_to_ipv4_vec)) >>
        domain_name_servers         : opt!(preceded!(tag!(&[DomainServers as u8])      , option_bytes_to_ipv4_vec)) >>
        static_routes               : opt!(preceded!(tag!(&[StaticRoutes as u8])       , option_bytes_to_ipv4_pairs_vec)) >>
        address_request             : opt!(preceded!(tag!(&[AddressRequest as u8])     , option_u32_to_ipv4)) >>
        address_time                : opt!(preceded!(tag!(&[AddressTime as u8])        , option_u32_with_len)) >>
        overload                    : opt!(preceded!(tag!(&[Overload as u8])           , option_u8_with_len)) >>
        dhcp_message_type           : opt!(preceded!(tag!(&[DhcpMessageType as u8])    , option_u8_to_message_type)) >>
        dhcp_server_id              : opt!(preceded!(tag!(&[DhcpServerId as u8])       , option_u32_to_ipv4)) >>
        parameter_list              : opt!(preceded!(tag!(&[ParameterList as u8])      , option_bytes_to_string)) >>
        dhcp_message                : opt!(preceded!(tag!(&[DhcpMessage as u8])        , option_bytes_to_string)) >>
        dhcp_max_message_size       : opt!(preceded!(tag!(&[DhcpMaxMessageSize as u8]) , option_u16_with_len)) >>
        renewal_time                : opt!(preceded!(tag!(&[RenewalTime as u8])        , option_u32_with_len)) >>
        rebinding_time              : opt!(preceded!(tag!(&[RebindingTime as u8])      , option_u32_with_len)) >>
        client_id                   : opt!(preceded!(tag!(&[ClientId as u8])           , option_bytes_to_vec)) >>
                                      tag!(&[OptionTag::End as u8]) >>

        (Message{
            operation_code,
            hardware_type,
            hardware_address_length,
            hardware_options,

            transaction_id,
            seconds,
            is_broadcast: flags & FLAG_BROADCAST == 1,

            client_ip_address,
            your_ip_address,
            server_ip_address,
            gateway_ip_address,

            client_hardware_address,
            server_name,
            boot_filename,

            options: Options{
                subnet_mask,
                time_offset                     : None,
                routers,
                time_servers                    : None,
                name_servers                    : None,
                domain_name_servers,
                log_servers                     : None,
                quotes_servers                  : None,
                lpr_servers                     : None,
                impress_servers                 : None,
                rlp_servers                     : None,
                hostname                        : None,
                boot_file_size                  : None,
                merit_dump_file                 : None,
                domain_name                     : None,
                swap_server                     : None,
                root_path                       : None,
                extensions_path                 : None,
                forward_on_off                  : None,
                non_local_source_route_on_off   : None,
                policy_filters                  : None,
                max_datagram_reassembly_size    : None,
                default_ip_ttl                  : None,
                mtu_timeout                     : None,
                mtu_plateau                     : None,
                mtu_interface                   : None,
                mtu_subnet                      : None,
                broadcast_address               : None,
                mask_recovery                   : None,
                mask_supplier                   : None,
                perform_router_discovery        : None,
                router_solicitation_address     : None,
                static_routes,
                trailer_encapsulation           : None,
                arp_timeout                     : None,
                ethernet_encapsulation          : None,
                default_tcp_ttl                 : None,
                keepalive_time                  : None,
                keepalive_data                  : None,
                nis_domain                      : None,
                nis_servers                     : None,
                ntp_servers                     : None,
                vendor_specific                 : None,
                netbios_name_server             : None,
                netbios_distribution_server     : None,
                netbios_node_type               : None,
                netbios_scope                   : None,
                x_window_font_servers           : None,
                x_window_manager_servers        : None,
                address_request,
                address_time,
                overload,
                dhcp_message_type,
                dhcp_server_id,
                parameter_list,
                dhcp_message,
                dhcp_max_message_size,
                renewal_time,
                rebinding_time,
                class_id                        : None,
                client_id,
                // skipping RFC 2242 code 62 (NetWare/IP Domain Name)
                // skipping RFC 2242 code 63 (NetWare/IP sub Options)
                nis_v3_domain_name              : None,
                nis_v3_servers                  : None,
                server_name                     : None,
                bootfile_name                   : None,
                home_agent_addresses            : None,
                smtp_servers                    : None,
                pop3_servers                    : None,
                nntp_servers                    : None,
                www_servers                     : None,
                finger_servers                  : None,
                irc_servers                     : None,
                street_talk_servers             : None,
                stda_servers                    : None,
            },
        })
    )
);

const U8_LEN: u8 = 1u8;
named!(option_u8_with_len<&[u8], u8>,
    preceded!(tag!(&[U8_LEN]), be_u8)
);
named!(option_u8_to_message_type<&[u8], MessageType>,
    map!(preceded!(tag!(&[U8_LEN]), be_u8), |value| value.into())
);

const U16_LEN: u8 = 2u8;
named!(option_u16_with_len<&[u8], u16>,
    preceded!(tag!(&[U16_LEN]), be_u16)
);

const U32_LEN: u8 = 4u8;
named!(option_u32_with_len<&[u8], u32>,
    preceded!(tag!(&[U32_LEN]), be_u32)
);

named!(option_u32_to_ipv4<&[u8], Ipv4Addr>,
    map!(preceded!(tag!(&[U32_LEN]), be_u32), |value| Ipv4Addr::from(value))
);

named!(option_bytes_to_vec<&[u8], Vec<u8>>,
    map!(length_bytes!(be_u8), |value| value.to_vec())
);

named!(option_bytes_to_string<&[u8], String>,
    map!(length_bytes!(be_u8), |value| String::from_utf8_lossy(value).to_string())
);

const IPV4_LEN: usize = 4;
named!(option_bytes_to_ipv4_vec<&[u8], Vec<Ipv4Addr>>,
    map!(length_bytes!(be_u8), |value| {
        if value.len() % IPV4_LEN != 0 { return Vec::new() }

        value
            .chunks(IPV4_LEN)
            .map(|element| {
                let mut array: [u8; IPV4_LEN] = [0u8; IPV4_LEN];
                array.copy_from_slice(element);
                Ipv4Addr::from(array)
            })
            .collect()
    })
);

const IPV4_PAIR_LEN: usize = IPV4_LEN * 2;
named!(option_bytes_to_ipv4_pairs_vec<&[u8], Vec<(Ipv4Addr, Ipv4Addr)>>,
    map!(length_bytes!(be_u8), |value| {
        if value.len() % IPV4_PAIR_LEN != 0 { return Vec::new() }

        value
            .chunks(IPV4_PAIR_LEN)
            .map(|element| {
                let mut array1: [u8; IPV4_LEN] = [0u8; IPV4_LEN];
                let mut array2: [u8; IPV4_LEN] = [0u8; IPV4_LEN];
                array1.copy_from_slice(&element[0..4]);
                array2.copy_from_slice(&element[4..8]);
                (Ipv4Addr::from(array1), Ipv4Addr::from(array2))
            })
            .collect()
    })
);