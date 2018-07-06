use std::{
    mem,
    net::Ipv4Addr,
};
use tokio_codec::{
    Decoder,
    Encoder,
};
use tokio;
use nom::*;
use bytes::{
    BytesMut,
    BufMut,
};
use eui48::{
    MacAddress,
    EUI48LEN,
};

use super::message::*;

pub struct Codec;

named!(parse_message<&[u8], Message>,
    do_parse!(
        operation_code              : be_u8 >>
        hardware_type               : be_u8 >>
        hardware_address_length     : be_u8 >>
        hardware_options            : be_u8 >>

        transaction_identifier      : be_u32 >>
        seconds                     : be_u16 >>
        flags                       : bits!(take_bits!(u16, SIZE_FLAGS)) >>

        client_ip_address           : be_u32 >>
        your_ip_address             : be_u32 >>
        server_ip_address           : be_u32 >>
        gateway_ip_address          : be_u32 >>

        client_hardware_address     : take!(SIZE_HARDWARE_ADDRESS) >>
        server_name                 : take!(SIZE_SERVER_NAME) >>
        boot_filename               : take!(SIZE_BOOT_FILENAME) >>

                                      tag!(MAGIC_COOKIE) >>

        address_time                : alt!(
                                          tag!(&[OptionTag::AddressTime as u8, 0x04u8])
                                          be_u32
                                      ) >>
        message_type                : alt!(
                                          tag!(&[OptionTag::MessageType as u8, 0x01u8])
                                          be_u8
                                      ) >>

                                      tag!(&[OptionTag::End as u8]) >>

        (Message{
            operation_code: operation_code.into(),
            hardware_type: hardware_type.into(),
            hardware_address_length,
            hardware_options,

            transaction_identifier,
            seconds,
            is_broadcast: flags & FLAG_BROADCAST == 1,

            client_ip_address: Ipv4Addr::from(client_ip_address),
            your_ip_address: Ipv4Addr::from(your_ip_address),
            server_ip_address: Ipv4Addr::from(server_ip_address),
            gateway_ip_address: Ipv4Addr::from(gateway_ip_address),

            client_hardware_address: MacAddress::from_bytes(&client_hardware_address[..EUI48LEN]).unwrap_or_default(),
            server_name: String::from_utf8_lossy(server_name).to_string(),
            boot_filename: String::from_utf8_lossy(boot_filename).to_string(),

            options: Options{
                address_time                : Some(address_time),

                message_type                : Some(message_type.into()),
            },
        })
    )
);

impl Decoder for Codec {
    type Item = Message;
    type Error = tokio::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < SIZE_HEADER_REQUIRED {
            return Ok(None);
        }

        let message = match parse_message(src.as_ref()) {
            Ok((_, message)) => message,
            Err(_) => return Ok(None),
        };
        println!("{}", message);

//        while cursor.remaining() > 0 {
//            use self::OptionTag::*;
//
//            match cursor.get_u8().into() {
//                Pad => continue,
//                AddressTime => {
//                    if cursor.remaining() < mem::size_of::<u32>() + 1 {
//                        return Ok(None);
//                    }
//                    let _length = cursor.get_u8();
//                    message.options.address_time = Some(cursor.get_u32_be());
//                },
//                MessageType => {
//                    if cursor.remaining() < mem::size_of::<u8>() + 1 {
//                        return Ok(None);
//                    }
//                    let _length = cursor.get_u8();
//                    message.options.message_type = Some(cursor.get_u8().into());
//                },
//                End => break,
//                value @ _ => println!("Strange value: {}", value as u8),
//            }
//        }

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

        dst.put(MAGIC_COOKIE);

        if let Some(value) = message.options.address_time {
            dst.put_u8(OptionTag::AddressTime as u8);
            dst.put_u8(mem::size_of::<u32>() as u8);
            dst.put_u32_be(value);
        }
        if let Some(value) = message.options.message_type {
            dst.put_u8(OptionTag::MessageType as u8);
            dst.put_u8(mem::size_of::<u8>() as u8);
            dst.put_u8(value as u8);
        }
        dst.put_u8(OptionTag::End as u8);

        Ok(())
    }
}