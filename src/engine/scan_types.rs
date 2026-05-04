//! Data types for the scan module.
//!
//! These types capture the full probe results collected per host during a
//! network scan. They feed every output format (table, JSON, CSV, per-host
//! detail) and are the contract between `scan_host()` and the CLI layer.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::proto::mount::{ExportEntry, MountedClient};

// --- Target specification ---------------------------------------------------

/// A resolved scan target: an IP address with an optional hostname label.
///
/// The hostname is preserved from the CLI input when the target was given as
/// a hostname (e.g., `nfs-prod.corp.local`).  It is `None` for bare IPs and
/// CIDR-expanded addresses.  Round-robin DNS that resolves one hostname to
/// multiple IPs produces one `TargetSpec` per IP, all sharing the hostname.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    /// Resolved IP address.
    pub ip: IpAddr,
    /// Original hostname from CLI input, if the target was a hostname.
    pub hostname: Option<String>,
}

// --- Port reachability ------------------------------------------------------

/// Portmapper (port 111) reachability status.
///
/// Without `--scan-udp`, only TCP is tested and the result is `Tcp` or
/// `Unreachable`.  With `--scan-udp`, both protocols are tested independently.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortReachability {
    /// TCP only (default mode, or TCP succeeded without UDP test).
    Tcp,
    /// UDP only (TCP failed, UDP succeeded with `--scan-udp`).
    Udp,
    /// Both TCP and UDP reachable (`--scan-udp` mode).
    TcpUdp,
    /// Neither protocol responded.
    Unreachable,
}

impl PortReachability {
    /// Build from TCP/UDP probe results.
    #[must_use]
    pub const fn from_probes(tcp: bool, udp: bool) -> Self {
        match (tcp, udp) {
            (true, true) => Self::TcpUdp,
            (true, false) => Self::Tcp,
            (false, true) => Self::Udp,
            (false, false) => Self::Unreachable,
        }
    }

    /// Whether the portmapper was reachable on at least one protocol.
    #[must_use]
    pub const fn is_reachable(&self) -> bool {
        !matches!(self, Self::Unreachable)
    }

    /// Whether TCP is available.
    #[must_use]
    pub const fn has_tcp(&self) -> bool {
        matches!(self, Self::Tcp | Self::TcpUdp)
    }
}

impl fmt::Display for PortReachability {
    /// Renders for the :111 column.
    ///
    /// Without `--scan-udp`: `open` or `--`.
    /// With `--scan-udp`: `tcp`, `udp`, `tcp+udp`, or `--`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The scan_udp context is not available here, so the caller
        // chooses the appropriate rendering.  This Display impl always
        // uses the verbose form; the table renderer simplifies to
        // "open"/"--" when scan_udp is false.
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::TcpUdp => f.write_str("tcp+udp"),
            Self::Unreachable => f.write_str("--"),
        }
    }
}

// --- Version range (PROG_MISMATCH hint) -------------------------------------

/// NFS version range from an RPC PROG_MISMATCH reply (RFC 1831 S13).
///
/// When a version probe is rejected with PROG_MISMATCH, the server includes
/// the contiguous range of supported versions `(low, high)`.  This is "free
/// intelligence" from a failed probe and populates the Hint column.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VersionRange {
    /// Lowest supported version.
    pub low: u32,
    /// Highest supported version.
    pub high: u32,
}

impl fmt::Display for VersionRange {
    /// `v3-v4` if low != high, `v4` if low == high.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low == self.high { write!(f, "v{}", self.low) } else { write!(f, "v{}-v{}", self.low, self.high) }
    }
}

// --- NFS port info ----------------------------------------------------------

/// Version probe results for a single NFS port.
///
/// Each reachable NFS port gets three independent probes (NULL v2, NULL v3,
/// COMPOUND v4).  The booleans record which probes were accepted by the
/// server's RPC layer.
#[derive(Debug, Clone, Serialize)]
pub struct NfsPortInfo {
    /// Port number.
    pub port: u16,
    /// Reachable over TCP.
    pub tcp: bool,
    /// Reachable over UDP (only tested with `--scan-udp`).
    pub udp: bool,
    /// NFSv2 NULL probe accepted.
    pub v2: bool,
    /// NFSv3 NULL probe accepted.
    pub v3: bool,
    /// NFSv4 COMPOUND probe accepted (any NFS4 status, including errors).
    pub v4: bool,
}

impl NfsPortInfo {
    /// Whether any NFS version probe succeeded on this port.
    #[must_use]
    pub const fn any_version(&self) -> bool {
        self.v2 || self.v3 || self.v4
    }
}

// --- Mount port info --------------------------------------------------------

/// Information about a discovered mountd port.
#[derive(Debug, Clone, Serialize)]
pub struct MountPortInfo {
    /// Port number.
    pub port: u16,
    /// Reachable over TCP.
    pub tcp: bool,
    /// Reachable over UDP (only tested with `--scan-udp`).
    pub udp: bool,
    /// MOUNT protocol versions available on this port (e.g., `[1, 3]`).
    pub versions: Vec<u32>,
}

// --- NFSv4 export entry -----------------------------------------------------

/// A top-level entry discovered via NFSv4 READDIR on the pseudo-root.
///
/// Unlike MOUNT EXPORT entries, these have no ACL information -- they are
/// just directory names from the pseudo-filesystem namespace.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V4ExportEntry {
    /// Entry name from the pseudo-root READDIR (e.g., `"srv"`, `"data"`).
    pub path: String,
}

// --- Host result ------------------------------------------------------------

/// Complete scan result for a single host.
///
/// Assembled by `scan_host()` after all probe stages complete.  Consumed by
/// every output format (table, JSON, CSV, per-host detail).
#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    /// Target IP address.
    pub ip: IpAddr,
    /// Original hostname from CLI input (if target was a hostname).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Portmapper (port 111) reachability.
    pub portmap_reachability: PortReachability,
    /// NFS ports discovered and probed.
    pub nfs_ports: Vec<NfsPortInfo>,
    /// Mountd ports discovered.
    pub mount_ports: Vec<MountPortInfo>,
    /// NFSv2 exports from MOUNT v1 EXPORT.  `None` = mountd v1 unreachable.
    pub exports_v2: Option<Vec<ExportEntry>>,
    /// NFSv3 exports from MOUNT v3 EXPORT.  `None` = mountd v3 unreachable.
    pub exports_v3: Option<Vec<ExportEntry>>,
    /// NFSv4 top-level pseudo-FS entries.  `None` = v4 unreachable or READDIR failed.
    pub exports_v4: Option<Vec<V4ExportEntry>>,
    /// Connected clients from MOUNT DUMP.  `None` = DUMP unavailable.
    pub mounts: Option<Vec<MountedClient>>,
    /// Version range from the first PROG_MISMATCH reply (Hint column).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<VersionRange>,
    /// Wall-clock time for all probes on this host.
    #[serde(with = "duration_ms")]
    pub scan_duration: Duration,
}

impl HostResult {
    /// Whether any NFS version was confirmed on any port.
    #[must_use]
    pub fn has_nfs(&self) -> bool {
        self.nfs_ports.iter().any(NfsPortInfo::any_version)
    }

    /// Whether NFSv2 was confirmed on any port.
    #[must_use]
    pub fn has_v2(&self) -> bool {
        self.nfs_ports.iter().any(|p| p.v2)
    }

    /// Whether NFSv3 was confirmed on any port.
    #[must_use]
    pub fn has_v3(&self) -> bool {
        self.nfs_ports.iter().any(|p| p.v3)
    }

    /// Whether NFSv4 was confirmed on any port.
    #[must_use]
    pub fn has_v4(&self) -> bool {
        self.nfs_ports.iter().any(|p| p.v4)
    }
}

/// Serde helper: serialize `Duration` as milliseconds (u64).
mod duration_ms {
    use std::time::Duration;

    use serde::{self, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis().try_into().map_err(serde::ser::Error::custom)?)
    }
}
