use std::{
    io,
    mem,
};

use bytes::BufMut;

use message::*;

use parser;

pub struct Codec;

impl Codec {
    pub fn decode(src: &[u8]) -> io::Result<Message> {
        let message = match parser::parse_message(src) {
            Ok((_, message)) => message,
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidInput, error.to_string())),
        };

        Ok(message)
    }

    pub fn encode(message: &Message, dst: &mut [u8]) -> io::Result<usize> {
        let mut cursor = io::Cursor::new(dst);

        cursor.put_u8(message.operation_code as u8);
        cursor.put_u8(message.hardware_type as u8);
        cursor.put_u8(message.hardware_address_length);
        cursor.put_u8(message.hardware_options);

        cursor.put_u32_be(message.transaction_id);
        cursor.put_u16_be(message.seconds);
        cursor.put_u16_be(if message.is_broadcast {0x0001} else {0x0000});

        cursor.put_u32_be(u32::from(message.client_ip_address));
        cursor.put_u32_be(u32::from(message.your_ip_address));
        cursor.put_u32_be(u32::from(message.server_ip_address));
        cursor.put_u32_be(u32::from(message.gateway_ip_address));

        cursor.put(message.client_hardware_address.as_bytes()); // 6 byte MAC-48
        cursor.put(vec![0u8; SIZE_HARDWARE_ADDRESS - message.client_hardware_address.as_bytes().len()]); // 10 byte padding

        cursor.put(message.server_name.as_bytes());
        cursor.put(vec![0u8; SIZE_SERVER_NAME - message.server_name.len()]); // (64 - length) byte padding

        cursor.put(message.boot_filename.as_bytes());
        cursor.put(vec![0u8; SIZE_BOOT_FILENAME - message.boot_filename.len()]); // (128 - length) byte padding

        cursor.put(MAGIC_COOKIE);
        if let Some(value) = message.options.subnet_mask {
            cursor.put_u8(OptionTag::SubnetMask as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(u32::from(value));
        }

        if let Some(ref value) = message.options.domain_name_servers {
            cursor.put_u8(OptionTag::DomainServer as u8);
            cursor.put_u8((mem::size_of::<u32>() * value.len()) as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.to_owned()));
            }
        }

        if let Some(ref value) = message.options.static_routes {
            cursor.put_u8(OptionTag::StaticRoute as u8);
            cursor.put_u8((mem::size_of::<u32>() * value.len() * 2) as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.0.to_owned()));
                cursor.put_u32_be(u32::from(element.1.to_owned()));
            }
        }

        if let Some(value) = message.options.address_request {
            cursor.put_u8(OptionTag::AddressRequest as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(u32::from(value));
        }
        if let Some(value) = message.options.address_time {
            cursor.put_u8(OptionTag::AddressTime as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(value);
        }
        if let Some(value) = message.options.overload {
            cursor.put_u8(OptionTag::Overload as u8);
            cursor.put_u8(mem::size_of::<u8>() as u8);
            cursor.put_u8(value);
        }
        if let Some(value) = message.options.dhcp_message_type {
            cursor.put_u8(OptionTag::DhcpMessageType as u8);
            cursor.put_u8(mem::size_of::<u8>() as u8);
            cursor.put_u8(value as u8);
        }
        if let Some(value) = message.options.dhcp_server_id {
            cursor.put_u8(OptionTag::DhcpServerId as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(u32::from(value));
        }
        if let Some(ref value) = message.options.parameter_list {
            cursor.put_u8(OptionTag::ParameterList as u8);
            cursor.put_u8(value.len() as u8);
            cursor.put(value);
        }
        if let Some(ref value) = message.options.dhcp_message {
            cursor.put_u8(OptionTag::DhcpMessage as u8);
            cursor.put_u8(value.len() as u8);
            cursor.put(value);
        }
        if let Some(value) = message.options.dhcp_max_message_size {
            cursor.put_u8(OptionTag::DhcpMaxMessageSize as u8);
            cursor.put_u8(mem::size_of::<u16>() as u8);
            cursor.put_u16_be(value);
        }

        if let Some(ref value) = message.options.client_id {
            cursor.put_u8(OptionTag::ClientId as u8);
            cursor.put_u8(value.len() as u8);
            cursor.put(value);
        }
        cursor.put_u8(OptionTag::End as u8);

        Ok(cursor.position() as usize)
    }
}