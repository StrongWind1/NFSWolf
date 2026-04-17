//! UDP RPC transport  --  datagram-based RPC for legacy NFS servers.
//!
//! NFS and portmapper both predate TCP-only deployment. RFC 1057 §10 specifies
//! that RPC MAY be used over UDP. Over UDP, each RPC message is a single
//! datagram; there is no record-marking (the 4-byte TCP length prefix is
//! absent). This module implements a single-call UDP RPC round trip.
//!
//! Primary use cases:
//! - Portmapper DUMP/GETPORT when the server blocks TCP/111 but allows UDP/111
//! - Legacy embedded NFS servers (HP-UX, old NetApp, embedded Linux) that
//!   only serve over UDP
//! - Portmapper UDP amplification measurement (F-3.2)

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use nfs3_types::rpc::{RPC_VERSION_2, accept_stat_data, call_body, msg_body, opaque_auth, reply_body, rpc_msg};
use nfs3_types::xdr_codec::{Pack, Unpack};

/// Maximum UDP datagram size accepted for RPC responses.
/// Portmapper DUMP responses can be large on heavily registered servers.
const MAX_UDP_DATAGRAM: usize = 65_536;

/// Send one RPC call over UDP and return the decoded result.
///
/// Uses the anonymous (AUTH_NONE) credential.  UDP RPC omits the 4-byte TCP
/// record-marking header (RFC 1057 §10).  On packet loss the call times out
/// after `timeout` rather than retrying  --  callers that need retries should
/// loop around this function themselves.
///
/// The target `addr` must be the specific RPC program port, not the portmapper.
pub async fn call_rpc_udp<C, R>(addr: SocketAddr, program: u32, version: u32, proc: u32, args: &C, timeout: Duration) -> anyhow::Result<R>
where
    C: Pack + Sync,
    R: Unpack,
{
    use rand::random;

    let xid: u32 = random();

    // Build the RPC CALL message.  Unlike TCP, there is no fragment header.
    let null_auth = opaque_auth::default();
    let call = call_body { rpcvers: RPC_VERSION_2, prog: program, vers: version, proc, cred: null_auth.borrow(), verf: null_auth.borrow() };
    let msg = rpc_msg { xid, body: msg_body::CALL(call) };

    let mut buf = Vec::with_capacity(msg.packed_size() + args.packed_size());
    msg.pack(&mut buf).context("pack RPC call header")?;
    args.pack(&mut buf).context("pack RPC args")?;

    // Bind an ephemeral local UDP port and send the datagram.
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.context("bind UDP socket")?;
    socket.send_to(&buf, addr).await.context("UDP send")?;

    // Wait for a response datagram.
    let mut recv_buf = vec![0u8; MAX_UDP_DATAGRAM];
    let (n, _from) = tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf)).await.context("UDP RPC timeout")?.context("UDP recv_from")?;
    recv_buf.truncate(n);

    // Parse the reply.  The cursor starts right at the rpc_msg (no record header).
    let mut cursor = std::io::Cursor::new(recv_buf);
    let (resp_msg, _) = rpc_msg::unpack(&mut cursor).context("unpack RPC reply header")?;

    anyhow::ensure!(resp_msg.xid == xid, "RPC XID mismatch (got {}, expected {xid})", resp_msg.xid);

    let reply = match resp_msg.body {
        msg_body::REPLY(reply_body::MSG_ACCEPTED(r)) => r,
        msg_body::REPLY(reply_body::MSG_DENIED(_)) => anyhow::bail!("RPC request denied by server"),
        msg_body::CALL(_) => anyhow::bail!("unexpected CALL message in reply position"),
    };

    anyhow::ensure!(matches!(reply.reply_data, accept_stat_data::SUCCESS), "RPC not accepted: {:?}", reply.reply_data);

    let (result, _) = R::unpack(&mut cursor).context("unpack RPC result")?;
    Ok(result)
}

/// Probe whether `addr` responds to an RPC NULL procedure over UDP.
///
/// Sends program/version NULL (proc 0) and returns true if a valid reply
/// arrives within `timeout`.  Used by the scanner to detect UDP-accessible
/// portmapper or NFS services.
pub async fn probe_udp_rpc(addr: SocketAddr, program: u32, version: u32, timeout: Duration) -> bool {
    use nfs3_types::xdr_codec::Void;

    call_rpc_udp::<Void, Void>(addr, program, version, 0, &Void, timeout).await.is_ok()
}
