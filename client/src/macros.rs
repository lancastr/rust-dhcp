//! Macro functions used in the `Client:poll` method.

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

/// Is safe after calling the `validate_or_continue` macro.
///
/// A panic indicates a bug in the application logic.
macro_rules! expect (
    ($option:expr) => (
        $option.expect("A bug in the Option setting logic")
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
                warn!("The response from {} is invalid: {} {}", $address, error, $message);
                continue;
            },
        };
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! check_xid (
    ($yours:expr, $response:expr) => (
        if $response != $yours {
            warn!("Got a response with wrong transaction ID: {} (yours is {})", $response, $yours);
            continue;
        }
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! poll_timer (
    ($timer:expr, $revert:expr) => (
        if let Some(ref mut timer) = $timer {
            match timer.poll() {
                Ok(Async::Ready(Some(_))) => return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout")),
                Ok(Async::Ready(None)) => $revert,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(error) => panic!("Timer error: {}", error),
            }
        } else {
            panic!("A bug in the timer setting logic");
        }
    );
    ($timer:expr, $revert:expr, $restart:expr) => (
        if let Some(ref mut timer) = $timer {
            match timer.poll() {
                Ok(Async::Ready(Some(_))) => $restart,
                Ok(Async::Ready(None)) => $revert,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(error) => panic!("Timer error: {}", error),
            }
        } else {
            panic!("A bug in the timer setting logic");
        }
    );
);