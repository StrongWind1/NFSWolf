//! Privileged port binding for NFS connections.
//!
//! Most NFS servers require the client to connect from a port < 1024 (RFC 1094 S3).
//! On Linux, this requires either `CAP_NET_BIND_SERVICE` or running as root.
//! This module checks whether privileged port binding is available and logs
//! a clear warning when it is not.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Probe result for privileged port availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedPortAvailability {
    /// Binding to ports < 1024 is possible (running as root or has capability).
    Available,
    /// Binding requires elevated privileges  --  connections may be refused by servers.
    Unavailable,
}

/// Check whether this process can bind to a privileged port (< 1024).
///
/// Tries to bind a TCP socket to `127.0.0.1:0` with `SO_REUSEADDR`, then
/// verifies the assigned port is in the privileged range.
/// Returns `Available` if the process has the necessary capability.
#[must_use]
pub fn check_privileged_binding() -> PrivilegedPortAvailability {
    // Try ports 600-1023 to find a free privileged port.
    for port in 600_u16..1024_u16 {
        let Ok(sock) = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) else { continue };
        if sock.set_reuse_address(true).is_err() {
            continue;
        }
        // Construct the address directly  --  no string parsing needed.
        let addr = SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port));
        let sock2_addr = socket2::SockAddr::from(addr);
        if sock.bind(&sock2_addr).is_ok() {
            return PrivilegedPortAvailability::Available;
        }
    }
    PrivilegedPortAvailability::Unavailable
}

/// Log a warning if privileged port binding is unavailable.
///
/// Many NFS servers reject connections from unprivileged ports by default.
/// Users should run nfswolf as root or grant `CAP_NET_BIND_SERVICE`.
pub fn warn_if_unprivileged() {
    if check_privileged_binding() == PrivilegedPortAvailability::Unavailable {
        tracing::warn!(
            "cannot bind to privileged ports (<1024); some NFS servers may refuse connections. \
             Run as root or set CAP_NET_BIND_SERVICE."
        );
    }
}
