//! Provides wrappers for tokio's types

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};
use tokio::net::{TcpSocket, TcpStream};

use crate::transport::io::{AsyncRead, AsyncWrite};
use crate::transport::net::Connector;

/// Wrapper for Tokio types
///
/// Wraps a Tokio's [`AsyncRead`](TokioAsyncRead) and [`AsyncWrite`](TokioAsyncWrite) implementor
/// to provide an [`AsyncRead`] and [`AsyncWrite`] implementation.
#[derive(Debug)]
pub struct TokioIo<T>(T);

impl<T> TokioIo<T> {
    /// Wrap a tokio stream so it satisfies this crate's I/O traits.
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> AsyncRead for TokioIo<T>
where
    T: TokioAsyncRead + Unpin + Send,
{
    async fn async_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        tokio::io::AsyncReadExt::read(&mut self.0, buf).await
    }
}

impl<T> AsyncWrite for TokioIo<T>
where
    T: TokioAsyncWrite + Unpin + Send,
{
    async fn async_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        tokio::io::AsyncWriteExt::write(&mut self.0, buf).await
    }

    async fn async_flush(&mut self) -> std::io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.0).await
    }
}

/// Connector for Tokio
///
/// Connects to a host and port using Tokio's [`TcpStream`], with Nagle's
/// algorithm disabled (`TCP_NODELAY`). RPC is request/response: with Nagle on,
/// the final partial segment of a large request waits for the peer to
/// acknowledge the segments before it, which the peer's delayed ACK can hold
/// back by tens of milliseconds. The Linux kernel's own RPC client sets the
/// option for the same reason.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioConnector;

impl Connector for TokioConnector {
    type Connection = TokioIo<TcpStream>;

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::Connection> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(TokioIo::new(stream))
    }

    async fn connect_with_port(&self, addr: SocketAddr, local_port: u16) -> std::io::Result<Self::Connection> {
        let (socket, local_addr) = if addr.is_ipv4() { (TcpSocket::new_v4()?, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)) } else { (TcpSocket::new_v6()?, SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_port)) };
        socket.bind(local_addr)?;

        let stream = socket.connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(TokioIo::new(stream))
    }
}
