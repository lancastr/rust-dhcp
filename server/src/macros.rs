//! Macro functions used in the `Server:poll` method.

/// By design the pending message must be flushed before sending the next one.
macro_rules! start_send (
    ($socket:expr, $ip:expr, $message:expr) => (
        let destination = SocketAddr::new(IpAddr::V4($ip), DHCP_PORT_CLIENT);
        if let AsyncSink::NotReady(_) = $socket.start_send((destination, $message))? {
            panic!("Must wait for poll_complete first");
        }
    );
);

/// Chooses the destination IP according to RFC 2131 rules.
macro_rules! destination (
    ($request:expr, $response:expr, $iface:expr) => (
        if !$request.client_ip_address.is_unspecified() {
            $request.client_ip_address
        } else {
            if $request.is_broadcast {
                Ipv4Addr::new(255, 255, 255, 255)
            } else {
                info!(
                    "Injecting an ARP entry {} -> {}",
                    $request.client_hardware_address,
                    $response.your_ip_address,
                );
                let _ = arp::add(
                    $request.client_hardware_address,
                    $response.your_ip_address,
                    $iface.to_owned(),
                ).map_err(|error| warn!("ARP error: {:?}", error));
                $response.your_ip_address

                /*
                RFC 2131 §4.1
                If unicasting is not possible, the message
                MAY be sent as an IP broadcast using an IP broadcast address
                (preferably 0xffffffff) as the IP destination address and the link-
                layer broadcast address as the link-layer destination address.

                Note: I don't know when unicasting is not possible yet.
                */
            }
        }
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! poll_complete (
    ($socket:expr) => (
        match $socket.poll_complete() {
            Ok(Async::Ready(_)) => {},
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(error) => {
                warn!("Socket error: {}", error);
                continue;
            },
        }
    );
);

/// The passed `Option` must be already validated in `protocol::Message::validate` method.
macro_rules! expect (
    ($option:expr) => (
        $option.expect("A bug in DHCP message validation")
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! poll (
    ($socket:expr) => (
        match $socket.poll() {
            Ok(Async::Ready(data)) => expect!(data),
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(error) => {
                warn!("Unable to parse a packet: {}", error);
                continue;
            },
        };
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! log_send(
    ($message:expr, $ip:expr) => (
        info!("Sending {} to {}", expect!($message.options.dhcp_message_type), $ip);
        debug!("{}", $message);
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! log_receive(
    ($message:expr, $source:expr) => (
        info!("Received {} from {}", expect!($message.options.dhcp_message_type), $source.ip());
        debug!("{}", $message);
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! validate (
    ($message:expr, $address:expr) => (
        match $message.validate() {
            Ok(dhcp_message_type) => dhcp_message_type,
            Err(error) => {
                warn!("The request from {} is invalid: {} {}", $address, error, $message);
                continue;
            },
        };
    );
);