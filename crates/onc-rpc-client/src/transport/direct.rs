//! A policy-free [`RpcTransport`] over a single connection.

use ::tokio::sync::Mutex;
use onc_xdr::{Pack, Unpack};

use super::call::RpcTransport;
use super::io::{AsyncRead, AsyncWrite};
use crate::error::RpcError;
use crate::rpc::{RpcClient, opaque_auth};

/// An [`RpcTransport`] backed by one connection, with no retry, pooling, or
/// pacing of any kind.
///
/// This is the transport a library consumer reaches for: it does exactly what
/// it is told, once, and reports what happened. A tool that needs connection
/// reuse or failure handling supplies its own implementation instead.
///
/// Calls are serialised by an async mutex, because ONC RPC over a stream
/// interleaves nothing -- a reply is matched to its call by XID, and this
/// client reads the next reply off the socket rather than demultiplexing.
#[derive(Debug)]
pub struct DirectTransport<IO> {
    rpc: Mutex<RpcClient<IO>>,
}

impl<IO> DirectTransport<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    /// Wrap an established connection, using AUTH_NONE.
    pub fn new(io: IO) -> Self {
        Self { rpc: Mutex::new(RpcClient::new(io)) }
    }

    /// Wrap an established connection with a credential and verifier.
    pub fn with_auth(io: IO, credential: opaque_auth<'static>, verifier: opaque_auth<'static>) -> Self {
        Self { rpc: Mutex::new(RpcClient::new_with_auth(io, credential, verifier)) }
    }

    /// Replace the credential used for subsequent calls.
    pub async fn set_credential(&self, credential: opaque_auth<'static>) {
        self.rpc.lock().await.credential = credential;
    }

    /// Consume the transport and return the underlying client.
    pub fn into_inner(self) -> RpcClient<IO> {
        self.rpc.into_inner()
    }
}

impl<IO> RpcTransport for DirectTransport<IO>
where
    IO: AsyncRead + AsyncWrite + Send + Sync,
{
    type Error = RpcError;

    #[expect(clippy::similar_names, reason = "prog and proc are the RFC 5531 call_body field names")]
    async fn call<C, R>(&self, prog: u32, vers: u32, proc: u32, args: &C) -> Result<R, RpcError>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.rpc.lock().await.call::<C, R>(prog, vers, proc, args).await
    }

    #[expect(clippy::similar_names, reason = "prog and proc are the RFC 5531 call_body field names")]
    async fn call_as<C, R>(&self, cred: opaque_auth<'static>, prog: u32, vers: u32, proc: u32, args: &C) -> Result<R, RpcError>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        let mut guard = self.rpc.lock().await;
        let previous = std::mem::replace(&mut guard.credential, cred);
        let result = guard.call::<C, R>(prog, vers, proc, args).await;
        // Restore unconditionally: leaving a borrowed identity on the
        // connection would silently mis-attribute every later call.
        guard.credential = previous;
        result
    }
}
