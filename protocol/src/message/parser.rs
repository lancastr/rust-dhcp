use std::net::Ipv4Addr;

use nom::*;
use eui48::{
    MacAddress,
    EUI48LEN,
};

use super::*;
use super::OptionTag::*;

named!(pub parse_message<&[u8], Message>,
    do_parse!(
        operation_code              : map!(be_u8, |v| v.into()) >>
        hardware_type               : map!(be_u8, |v| v.into()) >>
        hardware_address_length     : be_u8 >>
        hardware_options            : be_u8 >>

        transaction_identifier      : be_u32 >>
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
        subnet_mask                 : opt!(preceded!(tag!(&[SubnetMask as u8, 4u8]), map!(be_u32, |v| Ipv4Addr::from(v)))) >>
        address_request             : opt!(preceded!(tag!(&[AddressRequest as u8, 4u8]), map!(be_u32, |v| Ipv4Addr::from(v)))) >>
        address_time                : opt!(preceded!(tag!(&[AddressTime as u8, 4u8]), be_u32)) >>
        dhcp_message_type           : opt!(preceded!(tag!(&[DhcpMessageType as u8, 1u8]), map!(be_u8, |v| v.into()))) >>
        dhcp_server_id              : opt!(preceded!(tag!(&[DhcpServerId as u8, 4u8]), map!(be_u32, |v| Ipv4Addr::from(v)))) >>
        dhcp_message                : opt!(preceded!(tag!(&[DhcpMessage as u8]), map!(length_bytes!(be_u8), |v| String::from_utf8_lossy(v).to_string()))) >>
                                      tag!(&[OptionTag::End as u8]) >>

        (Message{
            operation_code,
            hardware_type,
            hardware_address_length,
            hardware_options,

            transaction_identifier,
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
                address_request,
                address_time,
                dhcp_message_type,
                dhcp_server_id,
                dhcp_message,
            },
        })
    )
);