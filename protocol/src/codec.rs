use std::{
    io,
    mem,
};
use bytes::BufMut;

use super::{
    parser,
    message::*,
};

pub struct Codec;

impl Codec {
    pub fn decode(src: &[u8]) -> io::Result<Message> {
        let message = match parser::parse_message(src) {
            Ok((_, message)) => message,
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidInput, error.to_string())),
        };

        if !message.is_valid() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Validation error"));
        }

        Ok(message)
    }

    pub fn encode(message: &Message, dst: &mut [u8]) -> io::Result<usize> {
        let mut cursor = io::Cursor::new(dst);

        cursor.put_u8(message.operation_code as u8);
        cursor.put_u8(message.hardware_type as u8);
        cursor.put_u8(message.hardware_address_length);
        cursor.put_u8(message.hardware_options);

        cursor.put_u32_be(message.transaction_identifier);
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
        if let Some(value) = message.options.address_time {
            cursor.put_u8(OptionTag::AddressTime as u8);
            cursor.put_u8(mem::size_of::<u32>() as u8);
            cursor.put_u32_be(value);
        }
        if let Some(value) = message.options.message_type {
            cursor.put_u8(OptionTag::MessageType as u8);
            cursor.put_u8(mem::size_of::<u8>() as u8);
            cursor.put_u8(value as u8);
        }
        cursor.put_u8(OptionTag::End as u8);

        Ok(cursor.position() as usize)
    }
}