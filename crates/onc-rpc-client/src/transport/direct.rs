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
///
/// Dropping a call's future before it completes (a `select!`, an outer
/// timeout) can leave a request half-written or a reply unread. The borrowed
/// credential of [`call_as`](RpcTransport::call_as) is still restored, but the
/// stream itself is out of step, so discard the transport rather than reuse it.
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
        // Restore from a drop guard rather than after the await: if this
        // future is dropped mid-call, a plain statement after the await never
        // runs, and the borrowed identity would silently mis-attribute every
        // later call on this transport.
        let restore = CredentialRestore { rpc: &mut *guard, previous: Some(previous) };
        restore.rpc.call::<C, R>(prog, vers, proc, args).await
    }
}

/// Puts the transport's own credential back when a borrowed-identity call
/// ends, whether it returned, failed, or was cancelled.
struct CredentialRestore<'a, IO> {
    rpc: &'a mut RpcClient<IO>,
    previous: Option<opaque_auth<'static>>,
}

impl<IO> Drop for CredentialRestore<'_, IO> {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.rpc.credential = previous;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::auth_flavor;
    use onc_xdr::{Opaque, Void};

    /// A stream that accepts every write and never produces a reply.
    struct Silent;

    impl AsyncRead for Silent {
        async fn async_read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }
    }

    impl AsyncWrite for Silent {
        async fn async_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
    }

    /// `call_as` must put the transport's own credential back even when the
    /// call is cancelled while waiting for the reply.
    #[tokio::test]
    async fn cancelled_call_as_restores_credential() {
        let own = opaque_auth { flavor: auth_flavor::AUTH_UNIX, body: Opaque::owned(vec![1, 2, 3, 4]) };
        let transport = DirectTransport::with_auth(Silent, own.clone(), opaque_auth::default());
        let borrowed = opaque_auth { flavor: auth_flavor::AUTH_UNIX, body: Opaque::owned(vec![9, 9, 9, 9]) };

        let call = transport.call_as::<Void, Void>(borrowed, 100_003, 3, 0, &Void);
        assert!(::tokio::time::timeout(std::time::Duration::from_millis(20), call).await.is_err(), "the stream never answers");

        let rpc = transport.into_inner();
        assert_eq!(rpc.credential.body.as_ref(), own.body.as_ref(), "the borrowed identity leaked past a cancelled call");
    }
}
