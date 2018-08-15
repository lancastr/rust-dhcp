//! The main DHCP socket module.

use std::net::SocketAddr;

use futures::StartSend;
use tokio::{io, net::UdpSocket, prelude::*};

use dhcp_protocol::*;

/// Must be enough to decode all the options.
pub const BUFFER_READ_CAPACITY: usize = 8192;
/// Must be enough to encode all the options.
pub const BUFFER_WRITE_CAPACITY: usize = 8192;

/// The modified version of the `tokio::UdpFramed`.
///
/// Works with high level DHCP messages.
pub struct DhcpFramed {
    /// `tokio::UdpSocket`.
    socket: UdpSocket,
    /// Stores received data and is used for deserialization.
    buf_read: Vec<u8>,
    /// Stores pending data and is used for serialization.
    buf_write: Vec<u8>,
    /// Stores the destination address and the number of bytes to send.
    pending: Option<(SocketAddr, usize)>,
}

pub type DhcpStreamItem = (SocketAddr, Message);
pub type DhcpSinkItem = (SocketAddr, (Message, Option<u16>));

impl DhcpFramed {
    /// Binds to `addr` and returns a `Stream+Sink` UDP socket abstraction.
    ///
    /// # Errors
    /// `io::Error` on unsuccessful socket building or binding.
    #[allow(unused_variables)]
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        Ok(DhcpFramed {
            socket,
            buf_read: vec![0u8; BUFFER_READ_CAPACITY],
            buf_write: vec![0u8; BUFFER_WRITE_CAPACITY],
            pending: None,
        })
    }
}

impl Stream for DhcpFramed {
    type Item = DhcpStreamItem;
    type Error = io::Error;

    /// Returns `Ok(Async::Ready(Some(_)))` on successful
    /// both read from socket and decoding the message.
    /// Returns `Ok(Async::Ready(None))` a on parsing error.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (amount, addr) = try_ready!(self.socket.poll_recv_from(&mut self.buf_read));
        match Message::from_bytes(&self.buf_read[..amount]) {
            Ok(frame) => Ok(Async::Ready(Some((addr, frame)))),
            Err(_) => Ok(Async::Ready(None)),
        }
    }
}

impl Sink for DhcpFramed {
    type SinkItem = DhcpSinkItem;
    type SinkError = io::Error;

    /// Returns `Ok(AsyncSink::Ready)` on successful sending or
    /// storing the data in order to send it when the socket is ready.
    /// Returns `Ok(AsyncSink::NotReady(item))` if there is pending data.
    ///
    /// # Errors
    /// `io::Error` on an encoding error.
    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        if self.pending.is_some() {
            return Ok(AsyncSink::NotReady(item));
        }

        let (addr, (message, max_size)) = item;
        let amount = message.to_bytes(&mut self.buf_write, max_size)?;
        self.pending = Some((addr, amount));

        Ok(AsyncSink::Ready)
    }

    /// Returns `Ok(Async::Ready(()))` on successful sending.
    /// Returns `Ok(Async::NotReady)` if the socket is not ready for sending.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
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
            }
        }
        self.pending = None;

        Ok(Async::Ready(()))
    }

    /// Just a `poll_complete` proxy.
    ///
    /// # Errors
    /// `io::Error` on a socket error.
    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.poll_complete()
    }
}
