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
    client_hardware_address     : MacAddress,
    client_id                   : Vec<u8>,

    // options section
}

impl MessageBuilder {
    pub fn new(
        client_hardware_address : MacAddress,
        client_id               : Vec<u8>,
    ) -> Self {
        MessageBuilder {
            client_hardware_address,
            client_id,
        }
    }

    pub fn discover(
        &self,
        transaction_id              : u32,
        requested_address           : Option<Ipv4Addr>,
    ) -> Message {
        let mut options = Options::new();
        options.address_request         = requested_address;
        options.address_time            = Some(1000000);
        options.dhcp_message_type       = Some(MessageType::DhcpDiscover);
        options.client_id               = Some(self.client_id.to_owned());

        Message {
            operation_code              : OperationCode::BootRequest,
            hardware_type               : HardwareType::Mac48,
            hardware_address_length     : EUI48LEN as u8,
            hardware_options            : 0u8,

            transaction_id,
            seconds                     : 0u16,
            is_broadcast                : true,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : Ipv4Addr::new(0,0,0,0),

            client_hardware_address     : self.client_hardware_address.to_owned(),
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }
}