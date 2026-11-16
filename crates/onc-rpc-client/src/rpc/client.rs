//! RPC client implementation

use std::fmt::Debug;

use crate::rpc::{RPC_VERSION_2, call_body, fragment_header, msg_body, opaque_auth, reply_body, rpc_msg};
use onc_xdr::{Pack, Unpack};

use crate::error::RpcError;
use crate::transport::io::{AsyncRead, AsyncWrite};

/// Largest RPC reply this client will accept, summed across all of its
/// record-marking fragments.
///
/// Generous against real servers -- Linux knfsd's default `rtmax` is 1 MiB --
/// and small enough that a forged fragment header cannot exhaust memory.
const MAX_REPLY_BYTES: u32 = 8 * 1024 * 1024;

/// Generic ONC RPC v2 client over a single connection.
///
/// Not tied to any one RPC program: [`call`](Self::call) takes the program,
/// version, and procedure numbers, so the same client drives NFSv2, NFSv3,
/// NFSv4, MOUNT, and the portmapper.
pub struct RpcClient<IO> {
    io: IO,
    xid: u32,
    /// Credential asserting the caller's identity, sent with every call.
    ///
    /// Public so it can be replaced mid-session.  Under AUTH_SYS the
    /// credential is re-sent per call rather than established once at
    /// handshake time, so changing it here changes the claimed identity of
    /// the next call without disturbing the connection.
    pub credential: opaque_auth<'static>,
    /// Verifier accompanying the credential.
    ///
    /// AUTH_SYS has nothing to verify and always sends AUTH_NONE here
    /// (RFC 5531 sec. 14.2); the field matters only for RPCSEC_GSS.
    pub verifier: opaque_auth<'static>,
    /// Reply verifier from the most recent successful call.
    ///
    /// When the server returns a reply verifier with flavor AUTH_SHORT (2),
    /// the body is an opaque session token that can be replayed as a
    /// credential on subsequent calls (RFC 1057 S9.2). This field captures
    /// the reply verifier so callers can detect and extract SHORT tokens.
    pub reply_verf: Option<opaque_auth<'static>>,
}

impl<IO> Debug for RpcClient<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("RpcClient").finish()
    }
}

impl<IO> RpcClient<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    /// Create a new RPC client. XID is initialized to a random value.
    pub fn new(io: IO) -> Self {
        Self::new_with_auth(io, opaque_auth::default(), opaque_auth::default())
    }

    /// Create a new RPC client with custom credential and verifier.
    pub fn new_with_auth(io: IO, credential: opaque_auth<'static>, verifier: opaque_auth<'static>) -> Self {
        Self { io, xid: fastrand::u32(..), credential, verifier, reply_verf: None }
    }

    /// Call an RPC procedure
    ///
    /// # Errors and connection state
    ///
    /// On a successful return the connection is in a clean state and may be
    /// reused for the next call. When an error is returned, use
    /// [`RpcError::is_connection_reusable`] to decide whether the
    /// connection can be kept.
    #[expect(clippy::similar_names, reason = "prog and proc are fields of call_body")]
    pub async fn call<C, R>(&mut self, prog: u32, vers: u32, proc: u32, args: &C) -> Result<R, RpcError>
    where
        R: Unpack,
        C: Pack + Send + Sync,
    {
        let call = call_body { rpcvers: RPC_VERSION_2, prog, vers, proc, cred: self.credential.borrow(), verf: self.verifier.borrow() };
        let msg = rpc_msg { xid: self.xid, body: msg_body::CALL(call) };
        self.xid = self.xid.wrapping_add(1);

        Self::send_call(&mut self.io, &msg, args).await?;
        let (result, verf) = Self::recv_reply_with_verf::<R>(&mut self.io, msg.xid).await?;
        self.reply_verf = verf;
        Ok(result)
    }

    async fn send_call<T>(io: &mut IO, msg: &rpc_msg<'_, '_>, args: &T) -> Result<(), RpcError>
    where
        T: Pack + Send + Sync,
    {
        let total_len = msg.packed_size() + args.packed_size();
        if !total_len.is_multiple_of(4) {
            return Err(RpcError::WrongLength);
        }

        // A fragment header encodes its length in 31 bits -- the top bit is the
        // EOF flag -- so one fragment cannot carry 2 GiB or more.  Reject here
        // rather than let fragment_header::new trip its assert.
        let fragment_len = u32::try_from(total_len).ok().filter(|len| *len <= fragment_header::MASK).ok_or(RpcError::WrongLength)?;
        let fragment_header = fragment_header::new(fragment_len, true);
        let mut buf = Vec::with_capacity(total_len + 4);
        // Byte counts are discarded here; buf.len() below is the real check
        // that what was packed matches what packed_size() promised.
        let _ = fragment_header.pack(&mut buf)?;
        let _ = msg.pack(&mut buf)?;
        let _ = args.pack(&mut buf)?;
        if buf.len() - 4 != total_len {
            return Err(RpcError::WrongLength);
        }
        io.async_write_all(&buf).await?;
        io.async_flush().await?;
        Ok(())
    }

    /// Read one complete RPC reply, reassembling multiple record fragments
    /// if needed (RFC 5531 sec 11). Returns the decoded result and the
    /// reply verifier (if any -- servers may return AUTH_SHORT tokens here).
    async fn recv_reply_with_verf<T>(io: &mut IO, xid: u32) -> Result<(T, Option<opaque_auth<'static>>), RpcError>
    where
        T: Unpack,
    {
        let mut assembled = Vec::new();

        loop {
            let mut hdr_buf = [0u8; 4];
            io.async_read_exact(&mut hdr_buf).await?;
            let frag: fragment_header = hdr_buf.into();
            let frag_len = frag.fragment_length();

            // Guard total assembled size against allocation amplification.
            // The fragment body has not been read, so the stream is now out of
            // step: the error must be one that marks the connection unusable.
            let new_total = assembled.len().saturating_add(frag_len as usize);
            if new_total > MAX_REPLY_BYTES as usize {
                return Err(RpcError::FragmentedReply);
            }

            let start = assembled.len();
            assembled.resize(new_total, 0);
            #[expect(clippy::indexing_slicing, reason = "start..new_total is in range: start was the old len, new_total is the current len")]
            io.async_read_exact(&mut assembled[start..]).await?;

            if frag.eof() {
                break;
            }
        }

        let total_len = assembled.len();
        let mut cursor = std::io::Cursor::new(assembled);
        let (resp_msg, _) = rpc_msg::unpack(&mut cursor)?;

        if resp_msg.xid != xid {
            return Err(RpcError::UnexpectedXid);
        }

        let reply = match resp_msg.body {
            msg_body::REPLY(reply_body::MSG_ACCEPTED(reply)) => reply,
            msg_body::REPLY(reply_body::MSG_DENIED(r)) => return Err(RpcError::from(r)),
            msg_body::CALL(_) => return Err(RpcError::UnexpectedCall),
        };

        let reply_verf = opaque_auth { flavor: reply.verf.flavor, body: onc_xdr::Opaque::owned(reply.verf.body.as_ref().to_vec()) };

        // try_from fails only for SUCCESS -- every other accept_stat maps to an
        // error, so falling through means the call was accepted.
        if let Ok(err) = RpcError::try_from(reply.reply_data) {
            return Err(err);
        }

        let (final_value, _) = T::unpack(&mut cursor)?;
        if cursor.position() != total_len as u64 {
            let pos = cursor.position();
            return Err(RpcError::NotFullyParsed { buf: cursor.into_inner(), pos });
        }
        // Surface the reply verifier -- AUTH_SHORT tokens live here.
        let verf = if reply_verf.flavor == crate::rpc::auth_flavor::AUTH_NULL { None } else { Some(reply_verf) };
        Ok((final_value, verf))
    }

    /// Send a batched call without waiting for a reply (RFC 5531 sec 8.4.1).
    ///
    /// Batching allows sending an arbitrarily large sequence of call
    /// messages without waiting for replies.  The batch is typically
    /// flushed by a final non-batched call.
    #[expect(clippy::similar_names, reason = "prog and proc are fields of call_body")]
    pub async fn send_batch<C>(&mut self, prog: u32, vers: u32, proc: u32, args: &C) -> Result<(), RpcError>
    where
        C: Pack + Send + Sync,
    {
        let call = call_body { rpcvers: RPC_VERSION_2, prog, vers, proc, cred: self.credential.borrow(), verf: self.verifier.borrow() };
        let msg = rpc_msg { xid: self.xid, body: msg_body::CALL(call) };
        self.xid = self.xid.wrapping_add(1);
        Self::send_call(&mut self.io, &msg, args).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onc_xdr::Void;

    /// In-memory stream: replays a canned reply, swallows writes, counts flushes.
    struct ScriptedIo {
        reply: std::io::Cursor<Vec<u8>>,
        flushes: usize,
    }

    impl AsyncRead for ScriptedIo {
        async fn async_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.reply, buf)
        }
    }

    impl AsyncWrite for ScriptedIo {
        async fn async_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        async fn async_flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn client(reply: Vec<u8>) -> RpcClient<ScriptedIo> {
        RpcClient::new_with_auth(ScriptedIo { reply: std::io::Cursor::new(reply), flushes: 0 }, opaque_auth::default(), opaque_auth::default())
    }

    /// A fragment header claiming more than the limit is rejected before its
    /// body is read, so the error must mark the connection unusable.
    #[tokio::test]
    async fn oversized_reply_is_not_reusable() {
        let header = (fragment_header::MASK & (MAX_REPLY_BYTES + 4)) | 0x8000_0000;
        let mut rpc = client(header.to_be_bytes().to_vec());
        let err = rpc.call::<Void, Void>(100_003, 3, 0, &Void).await.expect_err("oversized reply must fail");
        assert!(matches!(err, RpcError::FragmentedReply), "got {err:?}");
        assert!(!err.is_connection_reusable(), "unread fragment data is still in the socket");
    }

    /// Every request is flushed before the client waits for the reply.
    #[tokio::test]
    async fn request_is_flushed_before_reading() {
        let mut rpc = client(Vec::new());
        let err = rpc.call::<Void, Void>(100_003, 3, 0, &Void).await.expect_err("empty stream has no reply");
        assert!(matches!(err, RpcError::Io(_)), "got {err:?}");
        assert_eq!(rpc.io.flushes, 1);
    }
}
