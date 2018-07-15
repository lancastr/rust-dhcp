//! The main DHCP socket module.

use std::{
    net::SocketAddr,
};

use futures::{
    Async,
    AsyncSink,
    Poll,
    Sink,
    StartSend,
    Stream,
};
use tokio::{
    io,
    net::UdpSocket,
    reactor::Handle,
};
use net2::UdpBuilder;

use protocol::*;

/// Must be enough to decode all the options.
const BUFFER_READ_CAPACITY: usize = 8192;
/// Must be enough to encode all the options.
const BUFFER_WRITE_CAPACITY: usize = 8192;

/// The modified version of the `tokio::UdpFramed`.
///
/// Works with high level DHCP messages.
pub struct DhcpFramed {
    /// `tokio::UdpSocket`.
    socket      : UdpSocket,
    /// Stores received data and is used for deserialization.
    buf_read    : Vec<u8>,
    /// Stores pending data and is used for serialization.
    buf_write   : Vec<u8>,
    /// Stores the destination address and the number of bytes to send.
    pending     : Option<(SocketAddr, usize)>,
}

impl DhcpFramed {
    /// Binds to addr and returns a future.
    pub fn new(addr: SocketAddr, reuse_addr: bool, reuse_port: bool) -> io::Result<Self> {
        let socket = UdpBuilder::new_v4()?;
        if reuse_addr {
            socket.reuse_address(true)?;
        }
        #[cfg(target_os = "linux")] {
            if reuse_port {
                use net2::unix::UnixUdpBuilderExt;
                socket.reuse_port(true)?;
            }
        }

        let socket = socket.bind(addr)?;
        let socket = UdpSocket::from_std(socket, &Handle::default())?;
        socket.set_broadcast(true)?;

        Ok(DhcpFramed {
            socket,
            buf_read: vec![0u8; BUFFER_READ_CAPACITY],
            buf_write: vec![0u8; BUFFER_WRITE_CAPACITY],
            pending: None,
        })
    }
}

impl Stream for DhcpFramed {
    type Item = (SocketAddr, Message);
    type Error = io::Error;

    /// Returns `Ok(Async::Ready(Some(())))` on successful
    /// both read from socket and decoding the message.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    /// `io::Error` on a packet decoding error.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (amount, addr) = try_ready!(self.socket.poll_recv_from(&mut self.buf_read));
        match Message::from_bytes(&self.buf_read[..amount]) {
            Ok(frame) => Ok(Async::Ready(Some((addr, frame)))),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid packet from {}: {}", addr, error),
            )),
        }
    }
}

impl Sink for DhcpFramed {
    type SinkItem = (SocketAddr, Message);
    type SinkError = io::Error;

    /// Returns `Ok(AsyncSink::Ready)` on successful sending or
    /// storing the data in order to send it when the socket is ready.
    ///
    /// Returns `Ok(AsyncSink::NotReady(item))` if there is pending data
    /// or the socket is not ready for sending.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    /// `io::Error` on an encoding error.
    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, io::Error> {
        if self.pending.is_some() {
            self.poll_complete()?;
            if self.pending.is_some() {
                return Ok(AsyncSink::NotReady(item));
            }
        }

        let (addr, message) = item;
        let amount = message.to_bytes(&mut self.buf_write)?;
        self.pending = Some((addr, amount));
        self.poll_complete()?;

        Ok(AsyncSink::Ready)
    }

    /// Returns `Ok(Async::Ready(()))` on successful sending.
    ///
    /// Returns `Ok(Async::NotReady)` if the socket is not ready for sending.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        match self.pending {
            None => return Ok(Async::Ready(())),
            Some((addr, amount)) => {
                let sent = try_ready!(self.socket.poll_send_to(&self.buf_write[..amount], &addr));
                if sent != amount {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Failed to write entire datagram to socket",
                    ));
                }
            },
        }
        self.pending = None;

        Ok(Async::Ready(()))
    }

    /// Just tries to flush the socket.
    ///
    /// Returns the same as the `poll_complete` method.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    fn close(&mut self) -> Poll<(), io::Error> {
        self.poll_complete()
    }
}