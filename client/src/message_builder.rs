use std::{
    net::{
        Ipv4Addr,
    },
};

use eui48::{
    MacAddress,
    EUI48LEN,
};

use protocol::*;

pub struct MessageBuilder {
    // header section
    transaction_identifier      : u32,
    client_hardware_address     : MacAddress,

    // options section
}

impl MessageBuilder {
    pub fn new(
        transaction_identifier  : u32,
        client_hardware_address : MacAddress,
    ) -> Self {
        MessageBuilder {
            transaction_identifier,
            client_hardware_address,
        }
    }

    pub fn discover(
        &self,
    ) -> Message {
        let mut options= Options::new();
        options.address_time            = Some(1000000);
        options.dhcp_message_type       = Some(DhcpMessageType::DhcpDiscover);

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
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