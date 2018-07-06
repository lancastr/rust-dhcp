use std::{
    mem,
    net::Ipv4Addr,
};
use tokio_codec::{
    Decoder,
    Encoder,
};
use tokio;
use bytes::{
    Buf,
    BytesMut,
    BufMut,
};
use eui48::{
    MacAddress,
    EUI48LEN,
};

use super::message::*;

pub struct Codec;

macro_rules! distance {
    ($cursor:expr, $distance:expr) => {
        $cursor.position() as usize..$cursor.position() as usize + $distance
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = tokio::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < SIZE_HEADER_REQUIRED {
            return Ok(None);
        }

        let mut cursor = ::std::io::Cursor::new(src.as_ref());
        let mut message = Message::empty();
        message.operation_code              = cursor.get_u8().into();
        message.hardware_type               = cursor.get_u8().into();
        message.hardware_address_length     = cursor.get_u8();
        message.hardware_options            = cursor.get_u8();

        message.transaction_identifier      = cursor.get_u32_be();
        message.seconds                     = cursor.get_u16_be();
        message.is_broadcast                = cursor.get_u16_be() & 0x0001 == 1;

        message.client_ip_address           = Ipv4Addr::from(cursor.get_u32_be());
        message.your_ip_address             = Ipv4Addr::from(cursor.get_u32_be());
        message.server_ip_address           = Ipv4Addr::from(cursor.get_u32_be());
        message.gateway_ip_address          = Ipv4Addr::from(cursor.get_u32_be());

        match MacAddress::from_bytes(&src[distance!(cursor, EUI48LEN)]) {
            Ok(address) => message.client_hardware_address = address,
            Err(_) => return Ok(None),
        }
        cursor.advance(SIZE_HARDWARE_ADDRESS);

        message.server_name = String::from_utf8_lossy(&src[distance!(cursor, SIZE_SERVER_NAME)]).into();
        cursor.advance(SIZE_SERVER_NAME);

        message.boot_filename = String::from_utf8_lossy(&src[distance!(cursor, SIZE_BOOT_FILENAME)]).into();
        cursor.advance(SIZE_BOOT_FILENAME);

        if cursor.get_u32_be() != MAGIC_COOKIE {
            return Ok(None);
        }

        while cursor.remaining() > 0 {
            use self::OptionTag::*;

            match cursor.get_u8().into() {
                Pad => continue,
                AddressTime => {
                    if cursor.remaining() < mem::size_of::<u32>() + 1 {
                        return Ok(None);
                    }
                    let _length = cursor.get_u8();
                    message.options.address_time = Some(cursor.get_u32_be());
                },
                MessageType => {
                    if cursor.remaining() < mem::size_of::<u8>() + 1 {
                        return Ok(None);
                    }
                    let _length = cursor.get_u8();
                    message.options.message_type = Some(cursor.get_u8().into());
                },
                End => break,
                value @ _ => println!("Strange value: {}", value as u8),
            }
        }

        if !message.is_valid() {
            return Ok(None);
        }

        Ok(Some(message))
    }
}

impl Encoder for Codec {
    type Item = Message;
    type Error = tokio::io::Error;

    fn encode(&mut self, message: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(message.operation_code as u8);
        dst.put_u8(message.hardware_type as u8);
        dst.put_u8(message.hardware_address_length);
        dst.put_u8(message.hardware_options);

        dst.put_u32_be(message.transaction_identifier);
        dst.put_u16_be(message.seconds);
        dst.put_u16_be(if message.is_broadcast {0x0001} else {0x0000});

        dst.put_u32_be(u32::from(message.client_ip_address));
        dst.put_u32_be(u32::from(message.your_ip_address));
        dst.put_u32_be(u32::from(message.server_ip_address));
        dst.put_u32_be(u32::from(message.gateway_ip_address));

        dst.put(message.client_hardware_address.as_bytes()); // 6 byte MAC-48
        dst.put(vec![0u8; SIZE_HARDWARE_ADDRESS - message.client_hardware_address.as_bytes().len()]); // 10 byte padding

        dst.put(message.server_name.as_bytes());
        dst.put(vec![0u8; SIZE_SERVER_NAME - message.server_name.len()]); // (64 - length) byte padding

        dst.put(message.boot_filename.as_bytes());
        dst.put(vec![0u8; SIZE_BOOT_FILENAME - message.boot_filename.len()]); // (128 - length) byte padding

        dst.put_u32_be(MAGIC_COOKIE);

        if let Some(value) = message.options.message_type {
            dst.put_u8(OptionTag::MessageType as u8);
            dst.put_u8(mem::size_of::<u8>() as u8);
            dst.put_u8(value as u8);
        }
        if let Some(value) = message.options.address_time {
            dst.put_u8(OptionTag::AddressTime as u8);
            dst.put_u8(mem::size_of::<u32>() as u8);
            dst.put_u32_be(value);
        }
        dst.put_u8(OptionTag::End as u8);

        Ok(())
    }
}