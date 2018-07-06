use std::{
    cmp,
    net::{
        Ipv4Addr,
    },
};

use protocol::*;

pub struct MessageBuilder {
    server_ip_address   : Ipv4Addr,
    gateway_ip_address  : Ipv4Addr,
    server_name         : String,
}

const MAX_LEASE_TIME: u32 = 86400;

impl MessageBuilder {
    pub fn new<
        S: ToString,
    >(
        server_ip_address   : &Ipv4Addr,
        gateway_ip_address  : &Ipv4Addr,
        server_name         : S
    ) -> Self {
        MessageBuilder {
            server_ip_address: server_ip_address.to_owned(),
            gateway_ip_address: gateway_ip_address.to_owned(),
            server_name: server_name.to_string(),
        }
    }

    pub fn offer<
    >(
        &self,
        discover            : &Message,
        your_ip_address     : Ipv4Addr,
    ) -> Message {
        let options = Options {
            address_time: match discover.options.address_time {
                Some(value) => Some(cmp::min(value, MAX_LEASE_TIME)),
                None => Some(MAX_LEASE_TIME),
            },
            message_type: Some(MessageType::Offer),
        };

        Message {
            operation_code              : OperationCode::BootReply,
            hardware_type               : HardwareType::Ethernet,
            hardware_address_length     : discover.hardware_address_length,
            hardware_options            : 0u8,

            transaction_identifier      : discover.transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : discover.is_broadcast,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address,
            server_ip_address           : self.server_ip_address.clone(),
            gateway_ip_address          : self.gateway_ip_address.clone(),

            client_hardware_address     : discover.client_hardware_address,
            server_name                 : self.server_name.clone(),
            boot_filename               : String::new(),

            options,
        }
    }
}