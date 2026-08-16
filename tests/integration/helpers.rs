//! Shared test infrastructure for integration tests.
//!
//! Start a MemFs NFS server on an ephemeral port, connect clients.
//! Imported by each test file via `#[path = "helpers.rs"] mod helpers;`.
#![allow(dead_code, unreachable_pub, reason = "shared test helper included via #[path]")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nfs_v3::MountClient;
use nfs_v3::Nfs3Client;
use nfs3_server::memfs::{MemFs, MemFsConfig};
use nfs3_server::tcp::{NFSTcp, NFSTcpListener};
use onc_rpc_client::transport::DirectTransport;
use onc_rpc_client::transport::tokio::TokioIo;
use tokio::net::TcpStream;

/// Start a MemFs NFS server on an ephemeral port, returning the task handle and port.
pub(crate) async fn start_server(config: MemFsConfig) -> (tokio::task::JoinHandle<()>, u16) {
    let fs = MemFs::new(config).expect("MemFs must construct");
    let listener = NFSTcpListener::bind("127.0.0.1:0", fs).await.expect("bind must succeed");
    let port = listener.get_listen_port();
    let task = tokio::spawn(async move { listener.handle_forever().await.expect("server must not crash") });
    (task, port)
}

/// Connect a MOUNT v3 client to localhost on `port`.
pub(crate) async fn mount_client(port: u16) -> MountClient<DirectTransport<TokioIo<TcpStream>>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    MountClient::v3(DirectTransport::new(TokioIo::new(stream)))
}

/// Connect an NFSv3 client to localhost on `port`.
pub(crate) async fn nfs3_client(port: u16) -> Nfs3Client<DirectTransport<TokioIo<TcpStream>>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    Nfs3Client::new(DirectTransport::new(TokioIo::new(stream)))
}

/// Connect a portmapper client to localhost on `port`.
pub(crate) async fn portmap_client(port: u16) -> onc_rpcbind::PortmapperClient<TokioIo<TcpStream>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    onc_rpcbind::PortmapperClient::new(TokioIo::new(stream))
}
