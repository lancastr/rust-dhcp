use std::{
    net::SocketAddr,
};
use futures::{Async, AsyncSink, Poll, Sink, StartSend, Stream};
use tokio::{
    io,
    net::UdpSocket,
};

use protocol::*;

const BUFFER_READ_CAPACITY: usize   = 1024;
const BUFFER_WRITE_CAPACITY: usize  = 1024;

pub struct DhcpFramed {
    socket      : UdpSocket,
    buf_read    : Vec<u8>,
    buf_write   : Vec<u8>,
}

impl DhcpFramed {
    pub fn new(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(&addr)?;
        socket.set_broadcast(true)?;

        Ok(DhcpFramed {
            socket,
            buf_read: vec![0u8; BUFFER_READ_CAPACITY],
            buf_write: vec![0u8; BUFFER_WRITE_CAPACITY],
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
        let (addr, message) = item;
        let amount = Codec::encode(&message, &mut self.buf_write)?;
        let sent = match self.socket.poll_send_to(&self.buf_write[..amount], &addr)? {
            Async::Ready(sent) => sent,
            Async::NotReady => return Ok(AsyncSink::NotReady((addr, message))),
        };
        if sent != amount {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "Failed to write entire datagram to socket"));
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        try_ready!(self.poll_complete());
        Ok(Async::Ready(()))
    }
}