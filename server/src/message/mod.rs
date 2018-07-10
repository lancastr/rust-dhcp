mod offer;
mod ack;

use std::{
    net::{
        Ipv4Addr,
    },
};

use protocol::*;

pub use self::{
    offer::Offer,
    ack::Ack,
};

pub struct MessageBuilder {
    // header section
    server_ip_address       : Ipv4Addr,
    gateway_ip_address      : Ipv4Addr,
    server_name             : String,

    // options section
    subnet_mask             : Ipv4Addr,
}

impl MessageBuilder {
    pub fn new(
        server_ip_address       : Ipv4Addr,
        gateway_ip_address      : Ipv4Addr,
        server_name             : String,

        subnet_mask             : Ipv4Addr,
    ) -> Self {
        MessageBuilder {
            server_ip_address,
            gateway_ip_address,
            server_name,

            subnet_mask,
        }
    }

    pub fn dhcp_discover_to_offer(
        &self,
        discover  : &Message,
        offer     : &Offer,
    ) -> Message {
        let options = Options {
            subnet_mask         : Some(self.subnet_mask),
            address_request     : None,
            address_time        : Some(offer.lease_time),
            dhcp_message_type   : Some(DhcpMessageType::Offer),
            dhcp_server_id      : Some(self.server_ip_address),
            dhcp_message        : Some(offer.message.to_owned()),
        };

        Message {
            operation_code              : OperationCode::BootReply,
            hardware_type               : HardwareType::Mac48,
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

    pub fn dhcp_request_to_ack(
        &self,
        request     : &Message,
        ack         : &Ack,
    ) -> Message {
        let options = Options {
            subnet_mask         : Some(self.subnet_mask),
            address_request     : None,
            address_time        : Some(ack.lease_time),
            dhcp_message_type   : Some(DhcpMessageType::Ack),
            dhcp_server_id      : Some(self.server_ip_address),
            dhcp_message        : Some(ack.message.to_owned()),
        };

        Message {
            operation_code              : OperationCode::BootReply,
            hardware_type               : HardwareType::Mac48,
            hardware_address_length     : request.hardware_address_length,
            hardware_options            : 0u8,

            transaction_identifier      : request.transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : request.is_broadcast,

            client_ip_address           : request.client_ip_address,
            your_ip_address             : ack.address,
            server_ip_address           : self.server_ip_address,
            gateway_ip_address          : request.gateway_ip_address,

            client_hardware_address     : request.client_hardware_address,
            server_name                 : self.server_name.to_owned(),
            boot_filename               : String::new(),

            options,
        }
    }

    pub fn dhcp_request_to_nak(
        &self,
        request : &Message,
        message : &str,
    ) -> Message {
        let options = Options {
            subnet_mask         : None,
            address_request     : None,
            address_time        : None,
            dhcp_message_type   : Some(DhcpMessageType::Nak),
            dhcp_server_id      : Some(self.server_ip_address),
            dhcp_message        : Some(message.to_owned()),
        };

        Message {
            operation_code              : OperationCode::BootReply,
            hardware_type               : HardwareType::Mac48,
            hardware_address_length     : request.hardware_address_length,
            hardware_options            : 0u8,

            transaction_identifier      : request.transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : request.is_broadcast,

            client_ip_address           : Ipv4Addr::new(0,0,0,0),
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : Ipv4Addr::new(0,0,0,0),
            gateway_ip_address          : request.gateway_ip_address,

            client_hardware_address     : request.client_hardware_address,
            server_name                 : String::new(),
            boot_filename               : String::new(),

            options,
        }
    }

    pub fn dhcp_inform_to_ack(
        &self,
        inform  : &Message,
        message : &str,
    ) -> Message {
        let options = Options {
            subnet_mask         : Some(self.subnet_mask),
            address_request     : None,
            address_time        : None,
            dhcp_message_type   : Some(DhcpMessageType::Ack),
            dhcp_server_id      : Some(self.server_ip_address),
            dhcp_message        : Some(message.to_owned()),
        };

        Message {
            operation_code              : OperationCode::BootReply,
            hardware_type               : HardwareType::Mac48,
            hardware_address_length     : inform.hardware_address_length,
            hardware_options            : 0u8,

            transaction_identifier      : inform.transaction_identifier,
            seconds                     : 0u16,
            is_broadcast                : inform.is_broadcast,

            client_ip_address           : inform.client_ip_address,
            your_ip_address             : Ipv4Addr::new(0,0,0,0),
            server_ip_address           : self.server_ip_address,
            gateway_ip_address          : inform.gateway_ip_address,

            client_hardware_address     : inform.client_hardware_address,
            server_name                 : self.server_name.to_owned(),
            boot_filename               : String::new(),

            options,
        }
    }
}