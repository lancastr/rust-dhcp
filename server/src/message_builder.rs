use std::{
    net::{
        Ipv4Addr,
    },
};

use protocol::*;

use offer::Offer;

pub struct MessageBuilder {
    server_ip_address       : Ipv4Addr,
    gateway_ip_address      : Ipv4Addr,
    server_name             : String,

    subnet_mask             : Ipv4Addr,
}

impl MessageBuilder {
    pub fn new<
        S: ToString,
    >(
        server_ip_address       : Ipv4Addr,
        gateway_ip_address      : Ipv4Addr,
        server_name             : S,

        subnet_mask             : Ipv4Addr,
    ) -> Self {
        MessageBuilder {
            server_ip_address,
            gateway_ip_address,
            server_name: server_name.to_string(),

            subnet_mask,
        }
    }

    pub fn offer<
    >(
        &self,
        discover  : &Message,
        offer     : &Offer,
    ) -> Message {
        let options = Options {
            subnet_mask         : Some(self.subnet_mask),
            address_request     : None,
            address_time        : Some(offer.lease_time),
            dhcp_message_type   : Some(DhcpMessageType::Offer),
            dhcp_server_id      : Some(1488),
            dhcp_message        : Some(offer.message.to_owned()),
        };

        Message {
            operation_code              : OperationCode::BootReply,
            hardware_type               : HardwareType::Defined,
            hardware_address_length     : discover.hardware_address_length,
            hardware_options            : 0u8,

            transaction_identifier      : discover.transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : discover.is_broadcast,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : offer.address,
            server_ip_address           : self.server_ip_address,
            gateway_ip_address          : discover.gateway_ip_address,

            client_hardware_address     : discover.client_hardware_address,
            server_name                 : self.server_name.to_owned(),
            boot_filename               : String::new(),

            options,
        }
    }
}