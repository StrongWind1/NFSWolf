//! PROG_MISMATCH-aware RPC probe for NFS version detection.
//!
//! The nfs3_client `RpcClient::call()` converts PROG_MISMATCH to an opaque
//! `RpcError::ProgMismatch` that drops the `(low, high)` version range.
//! The scanner needs that range for the Hint column.
//!
//! This module provides raw TCP and UDP RPC probe functions that parse the
//! reply at a level below `RpcClient` to preserve the version range.
//! RFC 1831 S13 defines the PROG_MISMATCH reply format.

use std::io::Cursor;
use std::net::SocketAddr;
use std::time::Duration;

use nfs3_types::rpc::{RPC_VERSION_2, accept_stat_data, call_body, fragment_header, msg_body, opaque_auth, reply_body, rpc_msg};
use nfs3_types::xdr_codec::{Pack, Unpack, Void};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use crate::engine::scan_types::VersionRange;
use crate::proto::nfs4::types::{ArgOp, CompoundArgs, CompoundRes};

/// Result of an RPC probe that distinguishes PROG_MISMATCH from other failures.
#[derive(Debug)]
pub(crate) enum ProbeResult<T> {
    /// RPC accepted and result decoded.  Version is confirmed.
    Accepted(T),
    /// Server supports the program but not this version.  `(low, high)` is
    /// the contiguous range of supported versions (RFC 1831 S13).
    ProgMismatch(VersionRange),
    /// TCP connection, RPC framing, or auth failure.  No version info.
    Failed(anyhow::Error),
}

impl<T> ProbeResult<T> {
    /// Whether the probe was accepted (version confirmed).
    #[must_use]
    pub(crate) const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// Extract the PROG_MISMATCH version range, if any.
    #[must_use]
    pub(crate) const fn mismatch_range(&self) -> Option<&VersionRange> {
        match self {
            Self::ProgMismatch(r) => Some(r),
            _ => None,
        }
    }
}

// --- Low-level helpers -------------------------------------------------------

/// Atomically incrementing XID source.
fn next_xid() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static XID: AtomicU32 = AtomicU32::new(1);
    XID.fetch_add(1, Ordering::Relaxed)
}

/// Build a raw RPC CALL message with TCP record-marking header.
fn build_tcp_call(xid: u32, program: u32, version: u32, proc_num: u32, args: &impl Pack) -> Vec<u8> {
    let null_auth = opaque_auth::default();
    let call = call_body { rpcvers: RPC_VERSION_2, prog: program, vers: version, proc: proc_num, cred: null_auth.borrow(), verf: null_auth.borrow() };
    let msg = rpc_msg { xid, body: msg_body::CALL(call) };

    let payload_len = msg.packed_size() + args.packed_size();
    let fh = fragment_header::new(
        u32::try_from(payload_len).unwrap_or(u32::MAX),
        true, // last fragment
    );

    let mut buf = Vec::with_capacity(4 + payload_len);
    #[expect(clippy::unwrap_used, reason = "packing into a Vec<u8> cannot fail")]
    {
        _ = fh.pack(&mut buf).unwrap();
        _ = msg.pack(&mut buf).unwrap();
        _ = args.pack(&mut buf).unwrap();
    }
    buf
}

/// Read one complete RPC record from a TCP stream (multi-fragment aware).
async fn read_rpc_record(stream: &mut TcpStream) -> Result<Vec<u8>, anyhow::Error> {
    use tokio::io::AsyncReadExt as _;
    const MAX_RECORD: usize = 4 * 1024 * 1024; // 4 MiB safety cap
    let mut payload = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        _ = stream.read_exact(&mut hdr).await?;
        let fh: fragment_header = hdr.into();
        let frag_len = fh.fragment_length() as usize;
        if payload.len().saturating_add(frag_len) > MAX_RECORD {
            anyhow::bail!("RPC record exceeds {MAX_RECORD} bytes");
        }
        let start = payload.len();
        payload.resize(start + frag_len, 0);
        let slice = payload.get_mut(start..).ok_or_else(|| anyhow::anyhow!("fragment slice out of bounds"))?;
        _ = stream.read_exact(slice).await?;
        if fh.eof() {
            break;
        }
    }
    Ok(payload)
}

/// Parse a raw RPC reply buffer into a `ProbeResult`.
fn parse_reply<R: Unpack>(buf: Vec<u8>, expected_xid: u32) -> ProbeResult<R> {
    let mut cursor = Cursor::new(buf);
    let resp = match rpc_msg::unpack(&mut cursor) {
        Ok((msg, _)) => msg,
        Err(e) => return ProbeResult::Failed(anyhow::anyhow!("unpack RPC reply: {e}")),
    };
    if resp.xid != expected_xid {
        return ProbeResult::Failed(anyhow::anyhow!("XID mismatch: got {}, expected {expected_xid}", resp.xid));
    }
    match resp.body {
        msg_body::REPLY(reply_body::MSG_ACCEPTED(accepted)) => match accepted.reply_data {
            accept_stat_data::SUCCESS => match R::unpack(&mut cursor) {
                Ok((result, _)) => ProbeResult::Accepted(result),
                Err(e) => ProbeResult::Failed(anyhow::anyhow!("decode result: {e}")),
            },
            accept_stat_data::PROG_MISMATCH { low, high } => ProbeResult::ProgMismatch(VersionRange { low, high }),
            other => ProbeResult::Failed(anyhow::anyhow!("RPC not accepted: {other:?}")),
        },
        msg_body::REPLY(reply_body::MSG_DENIED(denied)) => ProbeResult::Failed(anyhow::anyhow!("RPC denied: {denied:?}")),
        msg_body::CALL(_) => ProbeResult::Failed(anyhow::anyhow!("unexpected CALL in reply")),
    }
}

// --- TCP probes --------------------------------------------------------------

/// Send one RPC call over an existing TCP stream and return a `ProbeResult`.
///
/// The stream is NOT consumed -- multiple probes can be sent sequentially
/// over the same connection (each with a different version/xid).
async fn send_and_recv<R: Unpack>(stream: &mut TcpStream, program: u32, version: u32, proc_num: u32, args: &(impl Pack + Send + Sync), timeout: Duration) -> ProbeResult<R> {
    let xid = next_xid();
    let buf = build_tcp_call(xid, program, version, proc_num, args);
    if let Err(e) = tokio::time::timeout(timeout, stream.write_all(&buf)).await {
        return ProbeResult::Failed(e.into());
    }
    match tokio::time::timeout(timeout, read_rpc_record(stream)).await {
        Ok(Ok(reply_buf)) => parse_reply::<R>(reply_buf, xid),
        Ok(Err(e)) => ProbeResult::Failed(e),
        Err(e) => ProbeResult::Failed(e.into()),
    }
}

/// Probe all three NFS versions on a single TCP connection to `addr`.
///
/// Sends NULL v2, NULL v3, and COMPOUND(\[PUTROOTFH\]) for v4 sequentially
/// over one TCP connection.  Returns `(v2, v3, v4)` probe results.
///
/// If the TCP connection itself fails, all three return `Failed`.
pub(crate) async fn probe_nfs_versions_tcp(addr: SocketAddr, timeout: Duration, proxy: Option<&str>) -> (ProbeResult<Void>, ProbeResult<Void>, ProbeResult<CompoundRes>) {
    let connect_result = if let Some(p) = proxy {
        let proxy_addr = match crate::proto::conn::parse_proxy_addr(p) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("bad proxy address: {e}");
                return (ProbeResult::Failed(anyhow::anyhow!("{msg}")), ProbeResult::Failed(anyhow::anyhow!("{msg}")), ProbeResult::Failed(anyhow::anyhow!("{msg}")));
            },
        };
        tokio::time::timeout(timeout, crate::proto::conn::socks5_connect(proxy_addr, addr)).await
    } else {
        tokio::time::timeout(timeout, TcpStream::connect(addr)).await
    };

    let mut stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let msg = format!("connect to {addr}: {e}");
            return (ProbeResult::Failed(anyhow::anyhow!("{msg}")), ProbeResult::Failed(anyhow::anyhow!("{msg}")), ProbeResult::Failed(anyhow::anyhow!("{msg}")));
        },
        Err(_) => {
            let msg = format!("connect to {addr}: timeout");
            return (ProbeResult::Failed(anyhow::anyhow!("{msg}")), ProbeResult::Failed(anyhow::anyhow!("{msg}")), ProbeResult::Failed(anyhow::anyhow!("{msg}")));
        },
    };

    // NULL v2: program=100003, version=2, proc=0
    let v2: ProbeResult<Void> = send_and_recv(&mut stream, 100_003, 2, 0, &Void, timeout).await;

    // NULL v3: program=100003, version=3, proc=0
    let v3: ProbeResult<Void> = send_and_recv(&mut stream, 100_003, 3, 0, &Void, timeout).await;

    // COMPOUND v4: program=100003, version=4, proc=1, args=COMPOUND(\[PUTROOTFH\])
    let v4_args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![ArgOp::Putrootfh] };
    let v4: ProbeResult<CompoundRes> = send_and_recv(&mut stream, 100_003, 4, 1, &v4_args, timeout).await;

    (v2, v3, v4)
}

// --- UDP probes --------------------------------------------------------------

/// Send one RPC call over UDP and return a `ProbeResult`.
pub(crate) async fn probe_rpc_udp<R: Unpack>(addr: SocketAddr, program: u32, version: u32, proc_num: u32, args: &(impl Pack + Send + Sync), timeout: Duration) -> ProbeResult<R> {
    let xid = next_xid();
    let null_auth = opaque_auth::default();
    let call = call_body { rpcvers: RPC_VERSION_2, prog: program, vers: version, proc: proc_num, cred: null_auth.borrow(), verf: null_auth.borrow() };
    let msg = rpc_msg { xid, body: msg_body::CALL(call) };

    let mut buf = Vec::with_capacity(msg.packed_size() + args.packed_size());
    #[expect(clippy::unwrap_used, reason = "packing into Vec cannot fail")]
    {
        _ = msg.pack(&mut buf).unwrap();
        _ = args.pack(&mut buf).unwrap();
    }

    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return ProbeResult::Failed(e.into()),
    };
    if let Err(e) = socket.send_to(&buf, addr).await {
        return ProbeResult::Failed(e.into());
    }

    let mut recv_buf = vec![0u8; 65_536];
    let n = match tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf)).await {
        Ok(Ok((n, _))) => n,
        Ok(Err(e)) => return ProbeResult::Failed(e.into()),
        Err(e) => return ProbeResult::Failed(e.into()),
    };
    recv_buf.truncate(n);
    parse_reply::<R>(recv_buf, xid)
}

/// Probe a single NFS version via UDP NULL call.
pub(crate) async fn probe_nfs_null_udp(addr: SocketAddr, version: u32, timeout: Duration) -> ProbeResult<Void> {
    probe_rpc_udp::<Void>(addr, 100_003, version, 0, &Void, timeout).await
}
