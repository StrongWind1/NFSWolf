//! RPCBIND v3/v4 types and client -- [RFC 1833].
//!
//! rpcbind (program 100000) extends the portmapper with versioned
//! protocol bindings.  Version 3 adds `GETTIME` (server clock);
//! version 4 adds `GETSTAT` (per-version operational statistics).
//! Both accept `AUTH_NONE` and return useful recon data.
//!
//! [RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833

use crate::error::RpcError;
use crate::rpc::RpcClient;
use crate::transport::io::{AsyncRead, AsyncWrite};
use nfswolf_xdr::{Pack, Unpack, Void};

use super::PROGRAM;

/// RPCBPROC_GETADDR procedure number (rpcbind v3, RFC 1833 sec. 2.1).
const RPCBPROC_GETADDR: u32 = 3;
/// RPCBPROC_GETTIME procedure number (rpcbind v3, RFC 1833 sec. 2.1).
const RPCBPROC_GETTIME: u32 = 6;
/// RPCBPROC_GETSTAT procedure number (rpcbind v4, RFC 1833 sec. 2.2.2).
const RPCBPROC_GETSTAT: u32 = 12;
/// rpcbind version 3 -- adds GETTIME, TADDR2UADDR, UADDR2TADDR.
const RPCBIND_V3: u32 = 3;
/// rpcbind version 4 -- adds GETSTAT and indirect call helpers.
const RPCBIND_V4: u32 = 4;

/// Server time returned by RPCBPROC_GETTIME (RFC 1833 sec. 2.1).
///
/// Just a `u32` wrapper giving the server's local clock as seconds since
/// the Unix epoch.  Useful for Kerberos ticket timing and correlating
/// log timestamps.
#[derive(Debug, Clone, Copy)]
pub struct RpcbindTime {
    /// Seconds since the Unix epoch.
    pub epoch_secs: u32,
}

/// One rpcbind version's operational statistics from RPCBPROC_GETSTAT
/// (RFC 1833 sec. 2.2.2).
///
/// Each entry covers a single rpcbind version (2, 3, or 4) and carries
/// per-procedure call counts plus aggregate SET/UNSET totals.
#[derive(Debug, Clone)]
pub struct RpcbindStatEntry {
    /// rpcbind version this entry covers (2, 3, or 4).
    pub rpcb_version: u32,
    /// Per-procedure call counts (index = procedure number).
    pub info: Vec<u32>,
    /// Total SET calls.
    pub setinfo: u32,
    /// Total UNSET calls.
    pub unsetinfo: u32,
}

/// XDR type for `rpcb_stat_byvers` (RFC 1833 sec. 2.2.2): fixed array of
/// `RPCBVERS_STAT` (3) `rpcb_stat` elements.  Each element contains
/// per-procedure call counts, set/unset totals, and linked lists of
/// per-address and per-rmtcall stats (which we skip).
#[derive(Debug)]
pub struct RpcbStatByvers(
    /// The decoded stat entries, one per rpcbind version.
    pub Vec<RpcbindStatEntry>,
);

impl Unpack for RpcbStatByvers {
    fn unpack(input: &mut impl std::io::Read) -> nfswolf_xdr::Result<(Self, usize)> {
        /// Number of rpcbind versions reported (v2, v3, v4).
        const RPCBVERS_STAT: usize = 3;
        /// Highest procedure number + 1 in the per-version stats array.
        const RPCBSTAT_HIGHPROC: usize = 13;

        let mut entries = Vec::with_capacity(RPCBVERS_STAT);
        let mut total_bytes = 0usize;

        for ver_idx in 0..RPCBVERS_STAT {
            // info[RPCBSTAT_HIGHPROC]: fixed array of 13 u32
            let mut info = Vec::with_capacity(RPCBSTAT_HIGHPROC);
            for _ in 0..RPCBSTAT_HIGHPROC {
                let (v, n) = u32::unpack(input)?;
                info.push(v);
                total_bytes += n;
            }
            // setinfo: u32
            let (setinfo, n) = u32::unpack(input)?;
            total_bytes += n;
            // unsetinfo: u32
            let (unsetinfo, n) = u32::unpack(input)?;
            total_bytes += n;
            // addrinfo: rpcbs_addrlist* (optional linked list)
            loop {
                let (disc, n) = u32::unpack(input)?;
                total_bytes += n;
                if disc == 0 {
                    break;
                }
                // rpcbs_addrlist: prog(u32) + vers(u32) + success(i32) + failure(i32) + netid(string)
                for _ in 0..4 {
                    let (_, n) = u32::unpack(input)?;
                    total_bytes += n;
                }
                let (netid, n) = nfswolf_xdr::unpack_string(input)?;
                total_bytes += n;
                drop(netid);
            }
            // rmtinfo: rpcbs_rmtcalllist* (optional linked list)
            loop {
                let (disc, n) = u32::unpack(input)?;
                total_bytes += n;
                if disc == 0 {
                    break;
                }
                // rpcbs_rmtcalllist: prog(u32) + vers(u32) + proc(u32) + success(i32) + failure(i32) + indirect(i32) + netid(string)
                for _ in 0..6 {
                    let (_, n) = u32::unpack(input)?;
                    total_bytes += n;
                }
                let (netid, n) = nfswolf_xdr::unpack_string(input)?;
                total_bytes += n;
                drop(netid);
            }

            entries.push(RpcbindStatEntry { rpcb_version: u32::try_from(ver_idx).unwrap_or(0) + 2, info, setinfo, unsetinfo });
        }

        Ok((Self(entries), total_bytes))
    }
}

/// The `rpcb` structure used by GETADDR and other rpcbind v3+ procedures
/// (RFC 1833 sec. 2.1).
///
/// Encodes program, version, network id, universal address, and owner
/// as five XDR fields.  For GETADDR queries the caller typically leaves
/// `addr` and `owner` empty.
#[derive(Debug)]
#[expect(clippy::struct_field_names, reason = "r_ prefix matches the RFC 1833 XDR field names verbatim")]
struct Rpcb<'a> {
    /// RPC program number.
    r_prog: u32,
    /// RPC version number.
    r_vers: u32,
    /// Network identifier (e.g., "tcp", "udp", "tcp6").
    r_netid: &'a str,
    /// Universal address (empty string for queries).
    r_addr: &'a str,
    /// Owner of the binding (empty string for queries).
    r_owner: &'a str,
}

impl Pack for Rpcb<'_> {
    fn packed_size(&self) -> usize {
        self.r_prog.packed_size() + self.r_vers.packed_size() + nfswolf_xdr::string_packed_size(self.r_netid) + nfswolf_xdr::string_packed_size(self.r_addr) + nfswolf_xdr::string_packed_size(self.r_owner)
    }

    fn pack(&self, out: &mut impl std::io::Write) -> nfswolf_xdr::Result<usize> {
        let mut n = self.r_prog.pack(out)?;
        n += self.r_vers.pack(out)?;
        n += nfswolf_xdr::pack_string(self.r_netid, out)?;
        n += nfswolf_xdr::pack_string(self.r_addr, out)?;
        n += nfswolf_xdr::pack_string(self.r_owner, out)?;
        Ok(n)
    }
}

/// Newtype around `String` for XDR string responses (e.g., universal
/// addresses from GETADDR).
#[derive(Debug)]
struct XdrString(String);

impl Unpack for XdrString {
    fn unpack(input: &mut impl std::io::Read) -> nfswolf_xdr::Result<(Self, usize)> {
        let (s, n) = nfswolf_xdr::unpack_string(input)?;
        Ok((Self(s), n))
    }
}

/// Client for rpcbind v3/v4 procedures (RFC 1833).
///
/// Provides `gettime()` (version 3) and `getstat()` (version 4) over
/// a single TCP connection.  Accepts `AUTH_NONE`, matching the
/// portmapper convention.
#[derive(Debug)]
pub struct RpcbindClient<IO> {
    rpc: RpcClient<IO>,
}

impl<IO> RpcbindClient<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    /// Create a new rpcbind client.
    ///
    /// The rpcbind service accepts AUTH_NONE for query procedures, so no
    /// credential is set up here.
    pub fn new(io: IO) -> Self {
        Self { rpc: RpcClient::new(io) }
    }

    /// RPCBPROC_GETADDR (proc 3, version 3): looks up the universal
    /// address for a given program, version, and network id.
    ///
    /// Returns the universal address string (e.g., "0.0.0.0.8.1" for
    /// port 2049 on IPv4) or an empty string if the service is not
    /// registered.  Per RFC 1833 sec. 2.1, this is the primary lookup
    /// mechanism in rpcbind v3+.
    pub async fn getaddr(&mut self, program: u32, version: u32, netid: &str) -> Result<String, RpcError> {
        let args = Rpcb { r_prog: program, r_vers: version, r_netid: netid, r_addr: "", r_owner: "" };
        let result: XdrString = self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_GETADDR, &args).await?;
        Ok(result.0)
    }

    /// RPCBPROC_GETTIME (proc 6, version 3): returns the server's local
    /// time as seconds since the Unix epoch.
    pub async fn gettime(&mut self) -> Result<u32, RpcError> {
        self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_GETTIME, &Void).await
    }

    /// RPCBPROC_GETSTAT (proc 12, version 4): returns operational
    /// statistics per rpcbind version.
    pub async fn getstat(&mut self) -> Result<RpcbStatByvers, RpcError> {
        self.rpc.call(PROGRAM, RPCBIND_V4, RPCBPROC_GETSTAT, &Void).await
    }
}
