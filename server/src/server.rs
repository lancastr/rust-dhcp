use std::{
    ops::Range,
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
};

use tokio::{
    io,
    prelude::*,
};
use hostname;

use protocol::*;
use framed::*;
use error::Error;
use message::MessageBuilder;
use storage::Storage;

pub struct Server {
    socket                  : DhcpFramed,
    message_builder         : MessageBuilder,
    storage                 : Storage,
}

impl Server {
    //
    // server_name:
    //     Some(string) if you want to specify the server name manually
    //     None to get the hostname automatically
    //
    // dynamic_address_range:
    //     is not inclusive yet, but may become so later
    //
    pub fn new(
        server_ip_address       : Ipv4Addr,
        gateway_ip_address      : Ipv4Addr,
        server_name             : Option<String>,

        static_address_range    : Range<Ipv4Addr>,
        dynamic_address_range   : Range<Ipv4Addr>,

        subnet_mask             : Ipv4Addr,
    ) -> Result<Self, io::Error> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), DHCP_PORT_SERVER);
        let socket = DhcpFramed::new(addr, false, false)?;

        let message_builder = MessageBuilder::new(
            server_ip_address,
            gateway_ip_address,
            server_name.unwrap_or(hostname::get_hostname().unwrap_or_default()),

            subnet_mask,
        );

        let storage = Storage::new(
            static_address_range,
            dynamic_address_range,
        );

        Ok(Server {
            socket,
            message_builder,
            storage,
        })
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            match self.socket.poll_complete()? {
                Async::Ready(_) => {},
                Async::NotReady => return Ok(Async::NotReady),
            }

            if let Some((mut addr, request)) = try_ready!(self.socket.poll()) {
                // report and drop invalid messages
                if !request.is_valid() {
                    println!("Invalid message from {}:\n{}", addr, request);
                    continue;
                }

                /*
                RFC 2131 §4.1
                If the 'giaddr' field in a DHCP message from a client is non-zero,
                the server sends any return messages to the 'DHCP server' port on the
                BOOTP relay agent whose address appears in 'giaddr'. If the 'giaddr'
                field is zero and the 'ciaddr' field is nonzero, then the server
                unicasts DHCPOFFER and DHCPACK messages to the address in 'ciaddr'.
                If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
                set, then the server broadcasts DHCPOFFER and DHCPACK messages to
                0xffffffff. If the broadcast bit is not set and 'giaddr' is zero and
                'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
                messages to the client's hardware address and 'yiaddr' address.  In
                all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
                messages to 0xffffffff.

                Note: SHOULD also send IP datagrams if the broadcast bit is not set (not implemented)
                */

                // configuration through gateways not required and not supported
                // if !request.gateway_ip_address.is_unspecified() {
                //     addr = SocketAddr::new(IpAddr::V4(request.gateway_ip_address), DHCP_PORT_SERVER)
                // }

                if !request.client_ip_address.is_unspecified() {
                    addr = SocketAddr::new(IpAddr::V4(request.client_ip_address), DHCP_PORT_CLIENT)
                }

                match request.options.dhcp_message_type {
                    Some(DhcpMessageType::DhcpDiscover) => {
                        match self.storage.allocate(
                            request.transaction_identifier,
                            request.options.address_time,
                            request.options.address_request,
                        ) {
                            Ok(offer) => {
                                let response = self.message_builder.dhcp_discover_to_offer(&request, &offer);

                                println!("Request from {}:\n{}", addr, request);
                                println!("Response to {}:\n{}", addr, response);

                                match self.socket.start_send((addr, response))? {
                                    AsyncSink::Ready => continue,
                                    AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                                }
                            },
                            Err(error) => println!("Address allocation error: {}", error.to_string()),
                        };
                    },
                    Some(DhcpMessageType::DhcpRequest) => {
                        /*
                        RFC 2131 §4.3.2
                        A DHCPREQUEST message may come from a client responding to a
                        DHCPOFFER message from a server, from a client verifying a previously
                        allocated IP address or from a client extending the lease on a
                        network address.  If the DHCPREQUEST message contains a 'server
                        identifier' option, the message is in response to a DHCPOFFER
                        message.  Otherwise, the message is a request to verify or extend an
                        existing lease.
                        */
                        if request.options.dhcp_server_id.is_some() {
                            // the client is in SELECTING state
                            match self.storage.assign(
                                request.transaction_identifier,
                                request.options.address_request,
                            ) {
                                Ok(ack) => {
                                    let response = self.message_builder.dhcp_request_to_ack(&request, &ack);

                                    println!("Request from {}:\n{}", addr, request);
                                    println!("Response to {}:\n{}", addr, response);

                                    match self.socket.start_send((addr, response))? {
                                        AsyncSink::Ready => continue,
                                        AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                                    }
                                },
                                Err(error) => println!("Address assignment error: {}", error.to_string()),
                            };
                        } else {
                            if request.client_ip_address.is_unspecified() {
                                // the client is in INIT-REBOOT state
                                match self.storage.check(
                                request.transaction_identifier,
                                request.options.address_request,
                                ) {
                                    Ok(ack) => {
                                        let response = self.message_builder.dhcp_request_to_ack(&request, &ack);

                                        println!("Request from {}:\n{}", addr, request);
                                        println!("Response to {}:\n{}", addr, response);

                                        match self.socket.start_send((addr, response))? {
                                            AsyncSink::Ready => continue,
                                            AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                                        }
                                    },
                                    /*
                                    RFC 2131 §4.3.2
                                    If the DHCP server has no record of this client, then it MUST
                                    remain silent, and MAY output a warning to the network administrator.
                                    */
                                    Err(error) => match error {
                                        Error::LeaseHasDifferentAddress => {
                                            let response = self.message_builder.dhcp_request_to_nak(&request, &error.to_string());

                                            println!("Request from {}:\n{}", addr, request);
                                            println!("Response to {}:\n{}", addr, response);

                                            match self.socket.start_send((addr, response))? {
                                                AsyncSink::Ready => continue,
                                                AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                                            }
                                        }
                                        _ => println!("Address checking error: {}", error.to_string()),
                                    },
                                }
                            } else {
                                // the client is in RENEWING or REBINDING state
                                match self.storage.renew(
                                    request.transaction_identifier,
                                    &request.client_ip_address,
                                    request.options.address_time,
                                ) {
                                    Ok(ack) => {
                                        let response = self.message_builder.dhcp_request_to_ack(&request, &ack);

                                        println!("Request from {}:\n{}", addr, request);
                                        println!("Response to {}:\n{}", addr, response);

                                        match self.socket.start_send((addr, response))? {
                                            AsyncSink::Ready => continue,
                                            AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                                        }
                                    },
                                    Err(error) => println!("Address checking error: {}", error.to_string()),
                                }
                            }
                        }
                    },
                    Some(DhcpMessageType::DhcpDecline) => {
                        match self.storage.freeze(
                            request.transaction_identifier,
                            request.options.address_request,
                        ) {
                            Ok(_) => println!("Address {:?} has been marked as unavailable", request.options.address_request),
                            Err(error) => println!("Address freezing error: {}", error.to_string()),
                        };
                    },
                    Some(DhcpMessageType::DhcpRelease) => {
                        match self.storage.deallocate(
                            request.transaction_identifier,
                            request.options.address_request,
                        ) {
                            Ok(_) => println!("Address {:?} has been released", request.options.address_request),
                            Err(error) => println!("Address releasing error: {}", error.to_string()),
                        };
                    },
                    Some(DhcpMessageType::DhcpInform) => {
                        let response = self.message_builder.dhcp_inform_to_ack(&request, "Accepted");

                        println!("Request from {}:\n{}", addr, request);
                        println!("Response to {}:\n{}", addr, response);

                        match self.socket.start_send((addr, response))? {
                            AsyncSink::Ready => continue,
                            AsyncSink::NotReady(_) => panic!("Must wait for poll_complete before"),
                        }
                    },
                    _ => {},
                }
            }
        }
    }
}