//! RPCBIND v3/v4 types and client -- [RFC 1833].
//!
//! rpcbind (program 100000) extends the portmapper with versioned
//! protocol bindings.  Version 3 adds `GETTIME` (server clock);
//! version 4 adds `GETSTAT` (per-version operational statistics).
//! Both accept `AUTH_NONE` and return useful recon data.
//!
//! [RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833

use onc_rpc_client::RpcClient;
use onc_rpc_client::RpcError;
use onc_rpc_client::transport::io::{AsyncRead, AsyncWrite};
use onc_xdr::{List, Opaque, Pack, Unpack, Void};

use crate::types::PROGRAM;

// --- Procedure numbers (RFC 1833 sec. 2.1, 2.2.1, 2.2.2) ---

/// RPCBPROC_SET (proc 1, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_SET: u32 = 1;
/// RPCBPROC_UNSET (proc 2, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_UNSET: u32 = 2;
/// RPCBPROC_GETADDR (proc 3, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_GETADDR: u32 = 3;
/// RPCBPROC_DUMP (proc 4, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_DUMP: u32 = 4;
/// RPCBPROC_CALLIT / RPCBPROC_BCAST (proc 5, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_CALLIT: u32 = 5;
/// RPCBPROC_GETTIME (proc 6, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_GETTIME: u32 = 6;
/// RPCBPROC_UADDR2TADDR (proc 7, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_UADDR2TADDR: u32 = 7;
/// RPCBPROC_TADDR2UADDR (proc 8, v3/v4, RFC 1833 sec. 2.1).
const RPCBPROC_TADDR2UADDR: u32 = 8;
/// RPCBPROC_GETVERSADDR (proc 9, v4 only, RFC 1833 sec. 2.2.2).
const RPCBPROC_GETVERSADDR: u32 = 9;
/// RPCBPROC_INDIRECT (proc 10, v4 only, RFC 1833 sec. 2.2.2).
const RPCBPROC_INDIRECT: u32 = 10;
/// RPCBPROC_GETADDRLIST (proc 11, v4 only, RFC 1833 sec. 2.2.2).
const RPCBPROC_GETADDRLIST: u32 = 11;
/// RPCBPROC_GETSTAT (proc 12, v4 only, RFC 1833 sec. 2.2.2).
const RPCBPROC_GETSTAT: u32 = 12;

/// rpcbind version 3 -- adds GETTIME, TADDR2UADDR, UADDR2TADDR.
const RPCBIND_V3: u32 = 3;
/// rpcbind version 4 -- adds GETSTAT and indirect call helpers.
const RPCBIND_V4: u32 = 4;

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
    /// RFC 1833 sec 2.2.2: `typedef int rpcbs_proc[RPCBSTAT_HIGHPROC]`.
    pub info: Vec<i32>,
    /// Total SET calls (RFC 1833: `int setinfo`).
    pub setinfo: i32,
    /// Total UNSET calls (RFC 1833: `int unsetinfo`).
    pub unsetinfo: i32,
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
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        /// Number of rpcbind versions reported (v2, v3, v4).
        const RPCBVERS_STAT: usize = 3;
        /// Highest procedure number + 1 in the per-version stats array.
        const RPCBSTAT_HIGHPROC: usize = 13;

        let mut entries = Vec::with_capacity(RPCBVERS_STAT);
        let mut total_bytes = 0usize;

        for ver_idx in 0..RPCBVERS_STAT {
            // info[RPCBSTAT_HIGHPROC]: fixed array of 13 signed ints (RFC 1833 sec 2.2.2)
            let mut info = Vec::with_capacity(RPCBSTAT_HIGHPROC);
            for _ in 0..RPCBSTAT_HIGHPROC {
                let (v, n) = i32::unpack(input)?;
                info.push(v);
                total_bytes += n;
            }
            // setinfo: int (RFC 1833 sec 2.2.2)
            let (setinfo, n) = i32::unpack(input)?;
            total_bytes += n;
            // unsetinfo: int (RFC 1833 sec 2.2.2)
            let (unsetinfo, n) = i32::unpack(input)?;
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
                let (netid, n) = onc_xdr::unpack_string(input)?;
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
                let (netid, n) = onc_xdr::unpack_string(input)?;
                total_bytes += n;
                drop(netid);
            }

            entries.push(RpcbindStatEntry { rpcb_version: u32::try_from(ver_idx).unwrap_or(0) + 2, info, setinfo, unsetinfo });
        }

        Ok((Self(entries), total_bytes))
    }
}

// --- Wire types (RFC 1833 sec. 2.1) ---

/// The `rpcb` structure used by GETADDR and other rpcbind v3+ procedures
/// (RFC 1833 sec. 2.1).
///
/// Encodes program, version, network id, universal address, and owner
/// as five XDR fields.  For GETADDR queries the caller typically leaves
/// `addr` and `owner` empty.
#[derive(Debug)]
#[expect(clippy::struct_field_names, reason = "r_ prefix matches the RFC 1833 XDR field names verbatim")]
struct Rpcb<'a> {
    r_prog: u32,
    r_vers: u32,
    r_netid: &'a str,
    r_addr: &'a str,
    r_owner: &'a str,
}

impl Pack for Rpcb<'_> {
    fn packed_size(&self) -> usize {
        self.r_prog.packed_size() + self.r_vers.packed_size() + onc_xdr::string_packed_size(self.r_netid) + onc_xdr::string_packed_size(self.r_addr) + onc_xdr::string_packed_size(self.r_owner)
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.r_prog.pack(out)?;
        n += self.r_vers.pack(out)?;
        n += onc_xdr::pack_string(self.r_netid, out)?;
        n += onc_xdr::pack_string(self.r_addr, out)?;
        n += onc_xdr::pack_string(self.r_owner, out)?;
        Ok(n)
    }
}

/// An rpcbind entry from a DUMP response (RFC 1833 sec. 2.1).
///
/// Owned version of `Rpcb` with both Pack and Unpack, used in DUMP
/// result lists and public API.
#[derive(Debug, Clone)]
pub struct RpcbEntry {
    /// RPC program number.
    pub program: u32,
    /// RPC version number.
    pub version: u32,
    /// Network identifier (e.g., "tcp", "udp", "tcp6").
    pub netid: String,
    /// Universal address (e.g., "0.0.0.0.8.1" for port 2049).
    pub addr: String,
    /// Owner of the binding.
    pub owner: String,
}

impl Pack for RpcbEntry {
    fn packed_size(&self) -> usize {
        self.program.packed_size() + self.version.packed_size() + onc_xdr::string_packed_size(&self.netid) + onc_xdr::string_packed_size(&self.addr) + onc_xdr::string_packed_size(&self.owner)
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.program.pack(out)?;
        n += self.version.pack(out)?;
        n += onc_xdr::pack_string(&self.netid, out)?;
        n += onc_xdr::pack_string(&self.addr, out)?;
        n += onc_xdr::pack_string(&self.owner, out)?;
        Ok(n)
    }
}

impl Unpack for RpcbEntry {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut n = 0;
        let (program, b) = u32::unpack(input)?;
        n += b;
        let (version, b) = u32::unpack(input)?;
        n += b;
        let (netid, b) = onc_xdr::unpack_string(input)?;
        n += b;
        let (addr, b) = onc_xdr::unpack_string(input)?;
        n += b;
        let (owner, b) = onc_xdr::unpack_string(input)?;
        n += b;
        Ok((Self { program, version, netid, addr, owner }, n))
    }
}

/// Linked list of rpcbind entries from RPCBPROC_DUMP (RFC 1833 sec. 2.1).
pub type RpcbList = List<RpcbEntry>;

/// Arguments for RPCBPROC_CALLIT / RPCBPROC_BCAST / RPCBPROC_INDIRECT
/// (RFC 1833 sec. 2.1).
#[derive(Debug, Clone)]
pub struct RpcbRmtCallArgs<'a> {
    /// Target RPC program number.
    pub program: u32,
    /// Target RPC version number.
    pub version: u32,
    /// Target RPC procedure number.
    pub proc: u32,
    /// XDR-encoded arguments for the target procedure.
    pub args: Opaque<'a>,
}

impl Pack for RpcbRmtCallArgs<'_> {
    fn packed_size(&self) -> usize {
        self.program.packed_size() + self.version.packed_size() + self.proc.packed_size() + self.args.packed_size()
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.program.pack(out)?;
        n += self.version.pack(out)?;
        n += self.proc.pack(out)?;
        n += self.args.pack(out)?;
        Ok(n)
    }
}

impl Unpack for RpcbRmtCallArgs<'static> {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut n = 0;
        let (program, b) = u32::unpack(input)?;
        n += b;
        let (version, b) = u32::unpack(input)?;
        n += b;
        let (proc, b) = u32::unpack(input)?;
        n += b;
        let (args, b) = Opaque::unpack(input)?;
        n += b;
        Ok((Self { program, version, proc, args }, n))
    }
}

/// Result of RPCBPROC_CALLIT / RPCBPROC_BCAST / RPCBPROC_INDIRECT
/// (RFC 1833 sec. 2.1).
#[derive(Debug, Clone)]
pub struct RpcbRmtCallRes {
    /// Universal address of the responding service.
    pub addr: String,
    /// XDR-encoded results from the target procedure.
    pub results: Vec<u8>,
}

impl Pack for RpcbRmtCallRes {
    fn packed_size(&self) -> usize {
        onc_xdr::string_packed_size(&self.addr) + Opaque::borrowed(&self.results).packed_size()
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = onc_xdr::pack_string(&self.addr, out)?;
        n += Opaque::borrowed(&self.results).pack(out)?;
        Ok(n)
    }
}

impl Unpack for RpcbRmtCallRes {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut n = 0;
        let (addr, b) = onc_xdr::unpack_string(input)?;
        n += b;
        let (results, b) = Opaque::unpack(input)?;
        n += b;
        Ok((Self { addr, results: results.into_owned() }, n))
    }
}

/// Transport address buffer (RFC 1833 sec. 2.1).
///
/// Used by RPCBPROC_UADDR2TADDR (returns a `Netbuf` for a universal address)
/// and RPCBPROC_TADDR2UADDR (takes a `Netbuf`, returns a universal address).
#[derive(Debug, Clone)]
pub struct Netbuf {
    /// Maximum buffer size the caller can accept.
    pub maxlen: u32,
    /// The transport address bytes.
    pub buf: Vec<u8>,
}

impl Pack for Netbuf {
    fn packed_size(&self) -> usize {
        self.maxlen.packed_size() + Opaque::borrowed(&self.buf).packed_size()
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.maxlen.pack(out)?;
        n += Opaque::borrowed(&self.buf).pack(out)?;
        Ok(n)
    }
}

impl Unpack for Netbuf {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut n = 0;
        let (maxlen, b) = u32::unpack(input)?;
        n += b;
        let (buf, b) = Opaque::unpack(input)?;
        n += b;
        Ok((Self { maxlen, buf: buf.into_owned() }, n))
    }
}

/// One entry from RPCBPROC_GETADDRLIST (rpcbind v4, RFC 1833 sec. 2.2.2).
#[derive(Debug, Clone)]
pub struct RpcbAddrEntry {
    /// Merged universal address.
    pub maddr: String,
    /// Network id (e.g., "tcp", "udp").
    pub nc_netid: String,
    /// Transport semantics (NC_TPI_CLTS=1, NC_TPI_COTS=2, NC_TPI_COTS_ORD=3, NC_TPI_RAW=4).
    pub nc_semantics: u32,
    /// Protocol family (e.g., "inet", "inet6", "loopback").
    pub nc_protofmly: String,
    /// Protocol name (e.g., "tcp", "udp").
    pub nc_proto: String,
}

impl Pack for RpcbAddrEntry {
    fn packed_size(&self) -> usize {
        onc_xdr::string_packed_size(&self.maddr) + onc_xdr::string_packed_size(&self.nc_netid) + self.nc_semantics.packed_size() + onc_xdr::string_packed_size(&self.nc_protofmly) + onc_xdr::string_packed_size(&self.nc_proto)
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = onc_xdr::pack_string(&self.maddr, out)?;
        n += onc_xdr::pack_string(&self.nc_netid, out)?;
        n += self.nc_semantics.pack(out)?;
        n += onc_xdr::pack_string(&self.nc_protofmly, out)?;
        n += onc_xdr::pack_string(&self.nc_proto, out)?;
        Ok(n)
    }
}

impl Unpack for RpcbAddrEntry {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut n = 0;
        let (maddr, b) = onc_xdr::unpack_string(input)?;
        n += b;
        let (nc_netid, b) = onc_xdr::unpack_string(input)?;
        n += b;
        let (nc_semantics, b) = u32::unpack(input)?;
        n += b;
        let (nc_protofmly, b) = onc_xdr::unpack_string(input)?;
        n += b;
        let (nc_proto, b) = onc_xdr::unpack_string(input)?;
        n += b;
        Ok((Self { maddr, nc_netid, nc_semantics, nc_protofmly, nc_proto }, n))
    }
}

/// Linked list of address entries from RPCBPROC_GETADDRLIST
/// (rpcbind v4, RFC 1833 sec. 2.2.2).
pub type RpcbAddrList = List<RpcbAddrEntry>;

/// Newtype around `String` for XDR string responses (e.g., universal
/// addresses from GETADDR).
#[derive(Debug)]
struct XdrString(String);

impl Unpack for XdrString {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let (s, n) = onc_xdr::unpack_string(input)?;
        Ok((Self(s), n))
    }
}

/// Pack-only wrapper for sending a string as RPC call arguments.
struct XdrPackString<'a>(&'a str);

impl Pack for XdrPackString<'_> {
    fn packed_size(&self) -> usize {
        onc_xdr::string_packed_size(self.0)
    }

    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        onc_xdr::pack_string(self.0, out)
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

    // --- rpcbind v3 procedures (RFC 1833 sec. 2.2.1) ---

    /// RPCBPROC_SET (proc 1, version 3): register a binding.
    pub async fn set(&mut self, program: u32, version: u32, netid: &str, addr: &str, owner: &str) -> Result<bool, RpcError> {
        let args = Rpcb { r_prog: program, r_vers: version, r_netid: netid, r_addr: addr, r_owner: owner };
        self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_SET, &args).await
    }

    /// RPCBPROC_UNSET (proc 2, version 3): unregister a binding.
    pub async fn unset(&mut self, program: u32, version: u32, netid: &str, addr: &str, owner: &str) -> Result<bool, RpcError> {
        let args = Rpcb { r_prog: program, r_vers: version, r_netid: netid, r_addr: addr, r_owner: owner };
        self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_UNSET, &args).await
    }

    /// RPCBPROC_GETADDR (proc 3, version 3): looks up the universal
    /// address for a given program, version, and network id.
    pub async fn getaddr(&mut self, program: u32, version: u32, netid: &str) -> Result<String, RpcError> {
        let args = Rpcb { r_prog: program, r_vers: version, r_netid: netid, r_addr: "", r_owner: "" };
        let result: XdrString = self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_GETADDR, &args).await?;
        Ok(result.0)
    }

    /// RPCBPROC_DUMP (proc 4, version 3): list all registered bindings.
    pub async fn dump(&mut self) -> Result<Vec<RpcbEntry>, RpcError> {
        let list: RpcbList = self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_DUMP, &Void).await?;
        Ok(list.into_inner())
    }

    /// RPCBPROC_CALLIT (proc 5, version 3): indirect call through rpcbind.
    pub async fn callit(&mut self, program: u32, version: u32, proc: u32, args: &[u8]) -> Result<RpcbRmtCallRes, RpcError> {
        let rmt_args = RpcbRmtCallArgs { program, version, proc, args: Opaque::borrowed(args) };
        self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_CALLIT, &rmt_args).await
    }

    /// RPCBPROC_GETTIME (proc 6, version 3): returns the server's local
    /// time as seconds since the Unix epoch.
    pub async fn gettime(&mut self) -> Result<u32, RpcError> {
        self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_GETTIME, &Void).await
    }

    /// RPCBPROC_UADDR2TADDR (proc 7, version 3): convert a universal
    /// address to a transport-specific address.
    pub async fn uaddr2taddr(&mut self, uaddr: &str) -> Result<Netbuf, RpcError> {
        let args = XdrPackString(uaddr);
        self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_UADDR2TADDR, &args).await
    }

    /// RPCBPROC_TADDR2UADDR (proc 8, version 3): convert a transport-specific
    /// address to a universal address.
    pub async fn taddr2uaddr(&mut self, taddr: &Netbuf) -> Result<String, RpcError> {
        let result: XdrString = self.rpc.call(PROGRAM, RPCBIND_V3, RPCBPROC_TADDR2UADDR, taddr).await?;
        Ok(result.0)
    }

    // --- rpcbind v4 procedures (RFC 1833 sec. 2.2.2) ---

    /// RPCBPROC_BCAST (proc 5, version 4): broadcast call through rpcbind.
    ///
    /// Same wire format as CALLIT but sent via v4; the server broadcasts
    /// the call and returns the first response.
    pub async fn bcast(&mut self, program: u32, version: u32, proc: u32, args: &[u8]) -> Result<RpcbRmtCallRes, RpcError> {
        let rmt_args = RpcbRmtCallArgs { program, version, proc, args: Opaque::borrowed(args) };
        self.rpc.call(PROGRAM, RPCBIND_V4, RPCBPROC_CALLIT, &rmt_args).await
    }

    /// RPCBPROC_GETVERSADDR (proc 9, version 4): like GETADDR but
    /// respects `r_vers` strictly (RFC 1833 sec. 2.2.2).
    pub async fn getversaddr(&mut self, program: u32, version: u32, netid: &str) -> Result<String, RpcError> {
        let args = Rpcb { r_prog: program, r_vers: version, r_netid: netid, r_addr: "", r_owner: "" };
        let result: XdrString = self.rpc.call(PROGRAM, RPCBIND_V4, RPCBPROC_GETVERSADDR, &args).await?;
        Ok(result.0)
    }

    /// RPCBPROC_INDIRECT (proc 10, version 4): indirect RPC call with
    /// error reporting (RFC 1833 sec. 2.2.2).
    pub async fn indirect(&mut self, program: u32, version: u32, proc: u32, args: &[u8]) -> Result<RpcbRmtCallRes, RpcError> {
        let rmt_args = RpcbRmtCallArgs { program, version, proc, args: Opaque::borrowed(args) };
        self.rpc.call(PROGRAM, RPCBIND_V4, RPCBPROC_INDIRECT, &rmt_args).await
    }

    /// RPCBPROC_GETADDRLIST (proc 11, version 4): list all addresses
    /// for a service across transports (RFC 1833 sec. 2.2.2).
    pub async fn getaddrlist(&mut self, program: u32, version: u32, netid: &str) -> Result<Vec<RpcbAddrEntry>, RpcError> {
        let args = Rpcb { r_prog: program, r_vers: version, r_netid: netid, r_addr: "", r_owner: "" };
        let list: RpcbAddrList = self.rpc.call(PROGRAM, RPCBIND_V4, RPCBPROC_GETADDRLIST, &args).await?;
        Ok(list.into_inner())
    }

    /// RPCBPROC_GETSTAT (proc 12, version 4): returns operational
    /// statistics per rpcbind version.
    pub async fn getstat(&mut self) -> Result<RpcbStatByvers, RpcError> {
        self.rpc.call(PROGRAM, RPCBIND_V4, RPCBPROC_GETSTAT, &Void).await
    }
}
