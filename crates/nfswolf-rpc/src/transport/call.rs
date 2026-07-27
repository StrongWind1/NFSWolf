//! The [`RpcTransport`] seam.
//!
//! Everything above this trait speaks in protocol terms -- procedures,
//! arguments, results. Everything below it speaks in transport terms --
//! sockets, retries, timeouts, connection reuse. A protocol client written
//! against `RpcTransport` therefore carries no policy at all, and the same
//! client works whether it is talking over one plain socket or a pooled,
//! rate-limited, circuit-broken connection farm.
//!
//! That split is what lets each NFS version ship as a library that is useful on
//! its own while a tool layers its own connection management underneath.

use nfswolf_xdr::{Pack, Unpack};

use crate::rpc::opaque_auth;

/// Something that can issue an ONC RPC call.
///
/// Implementors decide how the call reaches the server. Two ship with this
/// workspace: [`DirectTransport`](super::direct::DirectTransport), which owns a
/// single connection and applies no policy, and NFSWolf's own pooled transport,
/// which adds connection reuse, circuit breaking, and pacing.
///
/// Takes `&self` rather than `&mut self` so a client can be shared across tasks
/// behind an `Arc` without the caller threading a lock through every call site.
pub trait RpcTransport: Send + Sync {
    /// Error type this transport reports.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Issue one RPC call against `(prog, vers, proc)`.
    fn call<C, R>(&self, prog: u32, vers: u32, proc: u32, args: &C) -> impl Future<Output = Result<R, Self::Error>> + Send
    where
        C: Pack + Send + Sync,
        R: Unpack;

    /// Issue one call under a different credential, restoring the transport's
    /// own credential afterwards.
    ///
    /// AUTH_SYS re-sends the caller's asserted identity with every request
    /// rather than establishing it once, so the identity can change between
    /// calls on a live connection. That is what makes it practical to sweep a
    /// UID range over a single TCP session instead of reconnecting for each
    /// candidate.
    ///
    /// Implementations must restore the previous credential even when the call
    /// fails, so a shared or pooled connection is never left carrying a
    /// borrowed identity.
    fn call_as<C, R>(&self, cred: opaque_auth<'static>, prog: u32, vers: u32, proc: u32, args: &C) -> impl Future<Output = Result<R, Self::Error>> + Send
    where
        C: Pack + Send + Sync,
        R: Unpack;
}
