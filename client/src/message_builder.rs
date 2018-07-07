use std::{
    net::{
        Ipv4Addr,
    },
};
use eui48::{
    MacAddress,
    EUI48LEN,
};
use rand;

use protocol::*;

pub struct MessageBuilder {
    client_hardware_address     : MacAddress,
    transaction_identifier      : u32,
}

impl MessageBuilder {
    pub fn new<
    >(
        client_hardware_address: &MacAddress,
    ) -> Self {
        MessageBuilder {
            client_hardware_address: client_hardware_address.to_owned(),
            transaction_identifier: rand::random::<u32>(),
        }
    }

    pub fn discover<
    >(
        &self,
    ) -> Message {
        let options = Options{
            address_time: Some(3600),
            message_type: Some(MessageType::Discover),
        };

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_identifier      : self.transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : true,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.clone(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }
}