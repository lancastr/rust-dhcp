//! Macro functions used in the `Server:poll` method.

/// By design the pending message must be flushed before sending the next one.
macro_rules! start_send (
    ($socket:expr, $address:expr, $message:expr) => (
        if let AsyncSink::NotReady(_) = $socket.start_send(($address, $message))? {
            panic!("Must wait for poll_complete first");
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
    ($message:expr, $destination:expr) => (
        info!("Sending {} to {}", expect!($message.options.dhcp_message_type), $destination.ip());
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