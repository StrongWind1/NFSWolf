//! RPC client implementation

use std::fmt::Debug;

use crate::rpc::{RPC_VERSION_2, call_body, fragment_header, msg_body, opaque_auth, reply_body, rpc_msg};
use onc_xdr::{Pack, Unpack};

use crate::error::RpcError;
use crate::transport::io::{AsyncRead, AsyncWrite};

/// Largest RPC reply this client will accept in one fragment.
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
        Self { io, xid: fastrand::u32(..), credential, verifier }
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
        Self::recv_reply::<R>(&mut self.io, msg.xid).await
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
        Ok(())
    }

    async fn recv_reply<T>(io: &mut IO, xid: u32) -> Result<T, RpcError>
    where
        T: Unpack,
    {
        let mut buf = [0u8; 4];
        io.async_read_exact(&mut buf).await?;
        let fragment_header: fragment_header = buf.into();
        if !fragment_header.eof() {
            return Err(RpcError::FragmentedReply);
        }

        let total_len = fragment_header.fragment_length();
        // A fragment header can declare up to 2 GiB, and the peer chooses the
        // value. Allocating from it directly lets four bytes from a hostile or
        // simply non-RPC listener cost 2 GiB of zeroed memory before a single
        // payload byte arrives -- fatal during a concurrent scan, where one bad
        // host on port 2049 would take the whole sweep down (CWE-789).
        //
        // Real NFS replies are bounded by the server's advertised rtmax, which
        // is at most a few MiB in practice, so anything past this ceiling is
        // not a reply we could have used.
        if total_len > MAX_REPLY_BYTES {
            return Err(RpcError::WrongLength);
        }
        let mut buf = vec![0u8; total_len as usize];
        io.async_read_exact(&mut buf).await?;

        let mut cursor = std::io::Cursor::new(buf);
        let (resp_msg, _) = rpc_msg::unpack(&mut cursor)?;

        if resp_msg.xid != xid {
            return Err(RpcError::UnexpectedXid);
        }

        let reply = match resp_msg.body {
            msg_body::REPLY(reply_body::MSG_ACCEPTED(reply)) => reply,
            msg_body::REPLY(reply_body::MSG_DENIED(r)) => return Err(RpcError::from(r)),
            msg_body::CALL(_) => return Err(RpcError::UnexpectedCall),
        };

        // try_from fails only for SUCCESS -- every other accept_stat maps to an
        // error, so falling through means the call was accepted.
        if let Ok(err) = RpcError::try_from(reply.reply_data) {
            return Err(err);
        }

        let (final_value, _) = T::unpack(&mut cursor)?;
        if cursor.position() != u64::from(total_len) {
            let pos = cursor.position();
            return Err(RpcError::NotFullyParsed { buf: cursor.into_inner(), pos });
        }
        Ok(final_value)
    }
}
