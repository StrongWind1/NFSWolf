//! MOUNT protocol client  --  wraps nfs3_client mount support (RFC 1813 Appendix I).
//!
//! nfs3_client provides MNT (get root handle), UMNT, UMNTALL, DUMP, EXPORT.
//! This module adds:
//! - Auth flavor extraction from MNT response (F-1.1)
//! - Export ACL parsing (wildcards, subnets) (F-7.1)
//! - Connected client enumeration via DUMP
//! - Stealth unmount after handle acquisition (F-2.5)

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::SocketAddr;

use anyhow::Context as _;
use nfs3_client::MountClient;
use nfs3_types::mount::{dirpath, export_node};
use nfs3_types::xdr_codec::Opaque;

use crate::proto::auth::AuthFlavor;
use crate::proto::nfs3::types::FileHandle;

/// Result of a successful MNT call.
#[derive(Debug, Clone)]
pub struct MountResult {
    /// Root file handle for the exported filesystem.
    pub handle: FileHandle,
    /// Authentication flavors advertised by the server.
    ///
    /// Raw u32 values from the MNT response. Known values:
    /// `AUTH_NONE=0`, `AUTH_SYS=1`, `AUTH_SHORT=2`, `RPCSEC_GSS=6`.
    pub auth_flavors: Vec<u32>,
    /// Parsed auth flavor enum values (best-effort).
    pub parsed_flavors: Vec<AuthFlavor>,
}

/// One export with its access control list.
#[derive(Debug, Clone)]
pub struct ExportEntry {
    /// Exported filesystem path on the server.
    pub path: String,
    /// Hostnames, IP addresses, subnets, or wildcards allowed to mount.
    ///
    /// An empty list means the export is open to all (`*`).
    pub allowed_hosts: Vec<String>,
}

/// A client that currently has an export mounted (from MNTPROC_DUMP).
#[derive(Debug, Clone)]
pub struct MountedClient {
    /// Client hostname (as reported by the server).
    pub hostname: String,
    /// Mount point on the server.
    pub directory: String,
}

/// MOUNT protocol client.
#[derive(Debug, Clone)]
pub struct NfsMountClient {
    mount_port: Option<u16>,
}

impl NfsMountClient {
    /// Create a mount client that resolves the mount port via portmapper.
    #[must_use]
    pub const fn new() -> Self {
        Self { mount_port: None }
    }

    /// Create a mount client with a fixed mount port (bypasses portmapper).
    #[must_use]
    pub const fn with_port(port: u16) -> Self {
        Self { mount_port: Some(port) }
    }

    /// Mount an export and return the root file handle + auth flavors.
    ///
    /// Calls MNTPROC_MNT. Auth flavors reveal whether the server supports
    /// Kerberos or only AUTH_SYS (F-1.1).
    pub async fn mount(&self, addr: SocketAddr, export: &str) -> anyhow::Result<MountResult> {
        let mut client = self.connect(addr).await?;
        let path = dirpath(Opaque::owned(export.as_bytes().to_vec()));
        let res = client.mnt(path).await.with_context(|| format!("MNT {export}"))?;
        let handle = FileHandle::from_bytes(res.fhandle.0.as_ref());
        let parsed_flavors = res.auth_flavors.iter().map(|&f| parse_flavor(f)).collect();
        Ok(MountResult { handle, auth_flavors: res.auth_flavors, parsed_flavors })
    }

    /// Unmount an export (MNTPROC_UMNT) for stealth cleanup (F-2.5).
    pub async fn unmount(&self, addr: SocketAddr, export: &str) -> anyhow::Result<()> {
        let mut client = self.connect(addr).await?;
        let path = dirpath(Opaque::owned(export.as_bytes().to_vec()));
        client.umnt(path).await.with_context(|| format!("UMNT {export}"))
    }

    /// Unmount all exports (MNTPROC_UMNTALL).
    pub async fn unmount_all(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let mut client = self.connect(addr).await?;
        client.umntall().await.context("UMNTALL")
    }

    /// List all exports with their ACLs (MNTPROC_EXPORT).
    ///
    /// A wildcard or empty `allowed_hosts` list means the export is world-accessible (F-7.1).
    pub async fn list_exports(&self, addr: SocketAddr) -> anyhow::Result<Vec<ExportEntry>> {
        let mut client = self.connect(addr).await?;
        let exports = client.export().await.context("MNTPROC_EXPORT")?;
        Ok(exports.into_inner().into_iter().map(export_entry_from).collect())
    }

    /// List connected clients via MNTPROC_DUMP.
    ///
    /// Returns hosts that currently have an export mounted.
    pub async fn dump_clients(&self, addr: SocketAddr) -> anyhow::Result<Vec<MountedClient>> {
        let mut client = self.connect(addr).await?;
        let dump = client.dump().await.context("MNTPROC_DUMP")?;
        Ok(dump.into_inner().into_iter().map(|b| MountedClient { hostname: bytes_to_string(b.ml_hostname.0.as_ref()), directory: bytes_to_string(b.ml_directory.0.as_ref()) }).collect())
    }

    /// Open a TCP connection to the mount daemon.
    ///
    /// Tries privileged source ports (300-1023) first since most NFS servers
    /// require `secure` (source port < 1024). Falls back to an ephemeral port
    /// if privileged binding fails (e.g., not running as root).
    async fn connect(&self, addr: SocketAddr) -> anyhow::Result<MountClient<crate::proto::conn::NfsIo>> {
        let port = match self.mount_port {
            Some(p) => p,
            None => crate::proto::portmap::PortmapClient::default_port().query_port(addr, 100_005, 3).await.context("failed to query portmapper for mountd port -- use --mount-port to specify manually")?,
        };
        let mount_addr = SocketAddr::new(addr.ip(), port);
        let io = connect_privileged_or_fallback(mount_addr).await.with_context(|| format!("connect to mountd at {mount_addr}"))?;
        Ok(MountClient::new(io))
    }
}

impl Default for NfsMountClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Connect to `addr` from a privileged source port (300-1023).
///
/// Iterates through the range trying each port; falls back to an
/// unprivileged ephemeral port if all privileged ports fail (e.g., not root).
async fn connect_privileged_or_fallback(addr: SocketAddr) -> std::io::Result<crate::proto::conn::NfsIo> {
    use nfs3_client::net::Connector as _;
    use nfs3_client::tokio::TokioConnector;

    // Try privileged ports first (required by servers with default `secure` option).
    for local_port in 300_u16..1024 {
        match TokioConnector.connect_with_port(addr, local_port).await {
            Ok(io) => return Ok(io),
            Err(e) => {
                // EADDRINUSE = port taken, try next. Other errors = skip range.
                if e.kind() != std::io::ErrorKind::AddrInUse {
                    // Permission denied or other fatal error -- stop trying privileged.
                    break;
                }
            },
        }
    }
    // Fall back to ephemeral port with a warning.
    tracing::warn!(%addr, "privileged port binding failed, falling back to ephemeral port -- server may reject with EACCES");
    TokioConnector.connect(addr).await
}

/// Convert raw auth flavor u32 to the `AuthFlavor` enum (best-effort).
const fn parse_flavor(raw: u32) -> AuthFlavor {
    match raw {
        0 => AuthFlavor::None,
        1 => AuthFlavor::Sys,
        2 => AuthFlavor::Short,
        3 => AuthFlavor::Dh,
        6 => AuthFlavor::Gss,
        _ => AuthFlavor::Unknown,
    }
}

/// Convert an `export_node` to our `ExportEntry`.
fn export_entry_from(node: export_node<'_, '_>) -> ExportEntry {
    let path = bytes_to_string(node.ex_dir.0.as_ref());
    let allowed_hosts = node.ex_groups.into_inner().into_iter().map(|n| bytes_to_string(n.0.as_ref())).collect();
    ExportEntry { path, allowed_hosts }
}

/// Decode XDR bytes to a UTF-8 string, replacing invalid bytes with `?`.
fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
