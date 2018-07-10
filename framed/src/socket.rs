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

const BUFFER_READ_CAPACITY: usize   = 1024;
const BUFFER_WRITE_CAPACITY: usize  = 1024;

pub struct DhcpFramed {
    socket      : UdpSocket,
    buf_read    : Vec<u8>,
    buf_write   : Vec<u8>,

    pending     : Option<(SocketAddr, usize)>,
}

impl DhcpFramed {
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

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (amount, addr) = try_ready!(self.socket.poll_recv_from(&mut self.buf_read));
        match Codec::decode(&self.buf_read[..amount]) {
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

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, io::Error> {
        if self.pending.is_some() {
            self.poll_complete()?;
            if self.pending.is_some() {
                return Ok(AsyncSink::NotReady(item));
            }
        }

        let (addr, message) = item;
        let amount = Codec::encode(&message, &mut self.buf_write)?;
        self.pending = Some((addr, amount));
        self.poll_complete()?;

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        match self.pending {
            None => return Ok(Async::Ready(())),
            Some((addr, amount)) => {
                let sent = try_ready!(self.socket.poll_send_to(&self.buf_write[..amount], &addr));
                if sent != amount {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "Failed to write entire datagram to socket"));
                }
            },
        }
        self.pending = None;

        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        try_ready!(self.poll_complete());
        Ok(Async::Ready(()))
    }
}