//! Shared helpers for sideband RPC programs (NFS_ACL, RQUOTA, etc.).
//!
//! Sideband programs are registered in the portmapper alongside NFS but
//! use different RPC program numbers. They share the same connection and
//! XDR decode patterns, consolidated here to avoid duplication.

use std::net::SocketAddr;

use anyhow::Context as _;
use onc_rpc_client::rpc::RpcClient;
use onc_rpc_client::transport::tokio::TokioIo;
use onc_xdr::Unpack;
use tokio::net::TcpStream;

use crate::util::stealth::StealthConfig;

// --- XDR decode helpers ---

/// Read a big-endian u32 from `raw` at `pos`, advancing `pos` by 4.
pub(crate) fn read_u32(raw: &[u8], pos: &mut usize) -> anyhow::Result<u32> {
    let end = *pos + 4;
    let slice = raw.get(*pos..end).context("RPC reply truncated")?;
    let bytes: [u8; 4] = slice.try_into().context("RPC reply truncated")?;
    *pos = end;
    Ok(u32::from_be_bytes(bytes))
}

/// Raw RPC reply body for manual XDR decoding.
///
/// `RpcClient::call` strips the RPC header and passes the procedure-specific
/// result body to `Unpack`. This type captures all remaining bytes so the
/// caller can decode them manually (needed when the result shape is
/// status-discriminated or version-specific).
pub(crate) struct RawReply {
    pub data: Vec<u8>,
}

impl Unpack for RawReply {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut data = Vec::new();
        let n = input.read_to_end(&mut data)?;
        Ok((Self { data }, n))
    }
}

// --- Connection helpers ---

/// Open a TCP connection to a sideband RPC program with AUTH_SYS uid=0.
///
/// Handles SOCKS5 proxy tunneling, stealth pacing, and AUTH_SYS credential
/// construction. Returns a ready-to-use `RpcClient` for issuing calls.
pub(crate) async fn connect_sideband(addr: SocketAddr, proxy: Option<&str>, stealth: &StealthConfig) -> anyhow::Result<RpcClient<TokioIo<TcpStream>>> {
    stealth.wait().await;

    let stream = if let Some(p) = proxy {
        let proxy_addr = crate::proto::conn::parse_proxy_addr(p)?;
        crate::proto::conn::socks5_connect(proxy_addr, addr).await.context("sideband SOCKS5 connect")?
    } else {
        TcpStream::connect(addr).await.context("sideband TCP connect")?
    };

    let auth = crate::proto::auth::AuthSys::new(0, 0, "localhost").to_opaque_auth(crate::proto::auth::next_stamp());
    Ok(RpcClient::new_with_auth(TokioIo::new(stream), auth, onc_rpc_client::rpc::opaque_auth::default()))
}

// --- NFSv4 helpers ---

/// Parse an export path into its component segments.
///
/// `"/srv/nfs/data"` becomes `["srv", "nfs", "data"]`. Empty segments and
/// leading/trailing slashes are stripped.
pub(crate) fn export_components(path: &str) -> Vec<&str> {
    path.trim_start_matches('/').split('/').filter(|c| !c.is_empty()).collect()
}

/// Build an NFSv4 COMPOUND operation sequence that navigates from the
/// pseudo-root to an export path and retrieves the resulting file handle.
///
/// Returns `[PUTROOTFH, LOOKUP("srv"), LOOKUP("nfs"), ..., GETFH]`.
pub(crate) fn build_export_lookup_ops(components: &[&str]) -> Vec<crate::proto::nfs4::types::ArgOp> {
    use crate::proto::nfs4::types::ArgOp;
    let mut ops = Vec::with_capacity(components.len() + 2);
    ops.push(ArgOp::Putrootfh);
    for &c in components {
        ops.push(ArgOp::Lookup(c.to_owned()));
    }
    ops.push(ArgOp::Getfh);
    ops
}
