//! Macro functions used in the `Server:poll` method.

/// The passed `Option` must be already validated in `dhcp_protocol::Message::validate` method.
macro_rules! expect (
    ($option:expr) => (
        $option.expect("A bug in DHCP message validation")
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
macro_rules! log_send(
    ($message:expr, $destination:expr) => (
        info!("Sending {} to {}", expect!($message.options.dhcp_message_type), $destination);
        debug!("{}", $message);
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! poll (
    ($socket:expr) => (
        match $socket.poll() {
            Ok(Async::Ready(Some(data))) => data,
            Ok(Async::Ready(None)) => {
                warn!("Received an invalid packet");
                continue;
            }
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(error) => {
                warn!("Socket error: {}", error);
                return Err(error);
            },
        };
    );
);

/// Just to move some code from the overwhelmed `poll` method.
macro_rules! validate (
    ($message:expr, $address:expr) => (
        match $message.validate() {
            Ok(dhcp_message_type) => dhcp_message_type,
            Err(error) => {
                warn!("The request from {} is invalid: {}", $address, error);
                continue;
            },
        };
    );
);

/// By design the pending message must be flushed before sending the next one.
macro_rules! start_send (
    ($socket:expr, $destination:expr, $message:expr) => (
        match $socket.start_send(($destination, $message)) {
            Ok(AsyncSink::Ready) => {},
            Ok(AsyncSink::NotReady(_)) => {
                panic!("Must wait for poll_complete first");
            },
            Err(error) => {
                warn!("Socket error: {}", error);
                return Err(error);
            },
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
                return Err(error);
            },
        }
    );
);

/// Just to move some code from the overwhelmed `poll` method.
#[cfg(any(target_os = "linux", target_os = "windows"))]
macro_rules! poll_arp (
    ($process:expr) => (
        let mut ready = false;
        if let Some(ref mut process) = $process {
            let output = match process.poll() {
                Ok(Async::Ready(output)) => {
                    ready = true;
                    output
                },
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(error) => {
                    warn!("ARP process future error: {}", error);
                    continue;
                },
            };
            if !output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if stdout != "The object already exists." {
                    error!("ARP process error: {}", stdout);
                }
            }
        }
        if ready {
            $process = None;
        }
    );
);
