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
    /// When true, refuse to fall back to an ephemeral source port. Set when
    /// `--privileged-port` is in effect or when retrying after the server
    /// returned MNT3ERR_ACCES from an ephemeral source port.
    privileged_required: bool,
}

impl NfsMountClient {
    /// Create a mount client that resolves the mount port via portmapper.
    #[must_use]
    pub const fn new() -> Self {
        Self { mount_port: None, privileged_required: false }
    }

    /// Create a mount client with a fixed mount port (bypasses portmapper).
    #[must_use]
    pub const fn with_port(port: u16) -> Self {
        Self { mount_port: Some(port), privileged_required: false }
    }

    /// Force this client to bind a privileged source port (<1024) only.
    /// `connect()` will return an error rather than fall back to ephemeral.
    #[must_use]
    pub const fn require_privileged(mut self) -> Self {
        self.privileged_required = true;
        self
    }

    /// Mount an export and return the root file handle + auth flavors.
    ///
    /// Calls MNTPROC_MNT. Auth flavors reveal whether the server supports
    /// Kerberos or only AUTH_SYS (F-1.1).
    ///
    /// On `MNT3ERR_ACCES` (13) from an ephemeral source port, retries once
    /// with `privileged_required = true`. Most servers enforce the `secure`
    /// option (RFC 1813 Appendix I) by rejecting MNT calls from ports at
    /// or above 1024; if the privileged-port pool was exhausted on the
    /// first connect (TIME_WAIT pile-up, transient bind contention) we
    /// silently fall back to ephemeral and the server then rejects us.
    /// The retry path runs the privileged scan again with the
    /// eager-fallback path disabled, which is the same behaviour that
    /// `--privileged-port` requests explicitly.
    pub async fn mount(&self, addr: SocketAddr, export: &str) -> anyhow::Result<MountResult> {
        match self.mount_once(addr, export).await {
            Ok(r) => Ok(r),
            Err(e) if self.privileged_required => Err(e),
            Err(e) => {
                if downcast_mnt_acces(&e) {
                    tracing::warn!(%addr, %export, "MNT returned ACCES from ephemeral source port; retrying with privileged-only");
                    let priv_client = Self { mount_port: self.mount_port, privileged_required: true };
                    priv_client.mount_once(addr, export).await.with_context(|| format!("MNT {export} (privileged retry)"))
                } else {
                    Err(e)
                }
            },
        }
    }

    /// Single MNT attempt without the auto-retry wrapper.
    async fn mount_once(&self, addr: SocketAddr, export: &str) -> anyhow::Result<MountResult> {
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
    /// require `secure` (source port < 1024). Falls back to an ephemeral
    /// port if privileged binding fails AND `privileged_required` is unset
    /// (e.g., not running as root). With `privileged_required` set, the
    /// fallback is suppressed and the call returns an error -- this is the
    /// semantic of `--privileged-port` and of the auto-retry on
    /// `MNT3ERR_ACCES`.
    async fn connect(&self, addr: SocketAddr) -> anyhow::Result<MountClient<crate::proto::conn::NfsIo>> {
        let port = match self.mount_port {
            Some(p) => p,
            None => crate::proto::portmap::PortmapClient::default_port().query_port(addr, 100_005, 3).await.context("failed to query portmapper for mountd port -- use --mount-port to specify manually")?,
        };
        let mount_addr = SocketAddr::new(addr.ip(), port);
        let io = if self.privileged_required { connect_privileged_only(mount_addr).await.with_context(|| format!("connect to mountd at {mount_addr} (privileged-only)"))? } else { connect_privileged_or_fallback(mount_addr).await.with_context(|| format!("connect to mountd at {mount_addr}"))? };
        Ok(MountClient::new(io))
    }
}

impl Default for NfsMountClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true when `err` was caused by `MNT3ERR_ACCES` (13) from the server.
///
/// Used to decide whether to retry with a privileged source port.
/// We walk the anyhow source chain because `mount_once` wraps the raw
/// `nfs3_client::Error::MountError` with a `with_context`.
fn downcast_mnt_acces(err: &anyhow::Error) -> bool {
    use nfs3_client::error::Error as ClientError;
    use nfs3_types::mount::mountstat3;
    err.chain().any(|cause| matches!(cause.downcast_ref::<ClientError>(), Some(ClientError::MountError(mountstat3::MNT3ERR_ACCES))))
}

/// Connect to `addr` from a privileged source port (300-1023), falling back to ephemeral.
///
/// Only `PermissionDenied` (no `CAP_NET_BIND_SERVICE` and not root) breaks
/// out of the privileged pass; transient errors like `AddrInUse`, server
/// reset, or connection refused advance to the next port. This protects
/// against TIME_WAIT pile-up on busy hosts that would otherwise eat the
/// privileged range and silently slide us onto an ephemeral port.
async fn connect_privileged_or_fallback(addr: SocketAddr) -> std::io::Result<crate::proto::conn::NfsIo> {
    use nfs3_client::net::Connector as _;
    use nfs3_client::tokio::TokioConnector;

    for local_port in 300_u16..1024 {
        match TokioConnector.connect_with_port(addr, local_port).await {
            Ok(io) => return Ok(io),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::debug!(%addr, "no privilege to bind <1024, falling back to ephemeral");
                break;
            },
            Err(e) => {
                tracing::trace!(%addr, port = local_port, %e, "privileged mountd connect failed, trying next port");
            },
        }
    }
    tracing::warn!(%addr, "privileged port binding failed, falling back to ephemeral port -- server may reject with EACCES");
    TokioConnector.connect(addr).await
}

/// Connect to `addr` from a privileged source port only -- never falls back.
///
/// Used by `--privileged-port` and by the auto-retry path on
/// `MNT3ERR_ACCES`. Returns the last error if every port in 300-1023
/// fails to bind/connect.
async fn connect_privileged_only(addr: SocketAddr) -> std::io::Result<crate::proto::conn::NfsIo> {
    use nfs3_client::net::Connector as _;
    use nfs3_client::tokio::TokioConnector;

    let mut last_err: Option<std::io::Error> = None;
    for local_port in 300_u16..1024 {
        match TokioConnector.connect_with_port(addr, local_port).await {
            Ok(io) => return Ok(io),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err(e),
            Err(e) => {
                tracing::trace!(%addr, port = local_port, %e, "privileged-only mountd connect failed, trying next port");
                last_err = Some(e);
            },
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("privileged source port range 300-1023 exhausted")))
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
