use std::error::Error as StdError;
use std::fmt;

use crate::rpc::{accept_stat_data, auth_stat, rejected_reply};

/// Error from an RPC call.
///
/// Covers I/O failures, XDR encoding/decoding issues, and RPC protocol errors.
/// Returned by [`RpcClient::call`](crate::rpc::RpcClient::call) and by every
/// protocol client built on it.
///
/// # Connection state after an error
///
/// Not every error leaves the underlying transport in the same state.
/// Use [`is_connection_reusable`](Self::is_connection_reusable) to decide
/// whether the connection can be kept.
#[derive(Debug)]
#[non_exhaustive]
pub enum RpcError {
    /// An I/O error occurred during network communication.
    Io(std::io::Error),
    /// Failed to serialize or deserialize an XDR-encoded message.
    Xdr(onc_xdr::Error),
    /// Received a CALL message when a REPLY was expected.
    UnexpectedCall,
    /// Server rejected the request due to an authentication failure.
    Auth(auth_stat),
    /// Server does not support the requested RPC version.
    RpcMismatch {
        /// Lowest supported RPC version.
        low: u32,
        /// Highest supported RPC version.
        high: u32,
    },
    /// The serialized RPC message length is unusable: either not a multiple of
    /// 4 bytes, or too large for a single fragment (2 GiB or more).
    WrongLength,
    /// The reply XID does not match the request XID.
    UnexpectedXid,
    /// The reply was not fully consumed after decoding.
    NotFullyParsed {
        /// Raw reply buffer.
        buf: Vec<u8>,
        /// Cursor position where parsing stopped.
        pos: u64,
    },
    /// The requested program is not available on the server.
    ProgUnavail,
    /// The requested program version is not supported.
    ProgMismatch {
        /// Lowest supported program version.
        low: u32,
        /// Highest supported program version.
        high: u32,
    },
    /// The requested procedure is not available.
    ProcUnavail,
    /// The server could not decode the procedure arguments.
    GarbageArgs,
    /// The server sent a fragmented reply, which is not supported.
    ///
    /// Handling fragmented replies would require significant changes to the
    /// receive logic because subsequent fragments are not guaranteed to arrive
    /// immediately after the first one.
    FragmentedReply,
    /// An unspecified server-side system error occurred.
    SystemErr,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Xdr(e) => e.fmt(f),
            Self::UnexpectedCall => write!(f, "Unexpected CALL request"),
            Self::Auth(stat) => write!(f, "Authentication error: {stat}"),
            Self::RpcMismatch { low, high } => {
                write!(f, "RPC version mismatch (supported: {low}..={high})")
            },
            Self::WrongLength => write!(f, "Wrong length in RPC message"),
            Self::UnexpectedXid => write!(f, "Unexpected XID in RPC reply"),
            Self::NotFullyParsed { .. } => write!(f, "Not fully parsed"),
            Self::ProgUnavail => write!(f, "Program unavailable"),
            Self::ProgMismatch { low, high } => {
                write!(f, "Program mismatch (supported: {low}..={high})")
            },
            Self::ProcUnavail => write!(f, "Procedure unavailable"),
            Self::GarbageArgs => write!(f, "Garbage arguments"),
            Self::FragmentedReply => write!(f, "Fragmented replies are not supported"),
            Self::SystemErr => write!(f, "System error"),
        }
    }
}

impl StdError for RpcError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Xdr(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<onc_xdr::Error> for RpcError {
    fn from(e: onc_xdr::Error) -> Self {
        Self::Xdr(e)
    }
}

impl From<rejected_reply> for RpcError {
    fn from(e: rejected_reply) -> Self {
        match e {
            rejected_reply::RPC_MISMATCH { low, high } => Self::RpcMismatch { low, high },
            rejected_reply::AUTH_ERROR(stat) => Self::Auth(stat),
        }
    }
}

impl TryFrom<accept_stat_data> for RpcError {
    type Error = ();

    fn try_from(value: accept_stat_data) -> Result<Self, Self::Error> {
        match value {
            accept_stat_data::SUCCESS => Err(()),
            accept_stat_data::PROG_UNAVAIL => Ok(Self::ProgUnavail),
            accept_stat_data::PROG_MISMATCH { low, high } => Ok(Self::ProgMismatch { low, high }),
            accept_stat_data::PROC_UNAVAIL => Ok(Self::ProcUnavail),
            accept_stat_data::GARBAGE_ARGS => Ok(Self::GarbageArgs),
            accept_stat_data::SYSTEM_ERR => Ok(Self::SystemErr),
        }
    }
}

impl RpcError {
    /// Returns `true` if the connection that produced this error is still in
    /// a clean state and may be reused for the next call.
    ///
    /// Returns `false` for the three errors that leave the stream unusable:
    ///
    /// * [`Io`](Self::Io) -- the transport is dead.
    /// * [`FragmentedReply`](Self::FragmentedReply) -- unread fragment data is
    ///   still in the socket.
    /// * [`UnexpectedXid`](Self::UnexpectedXid) -- the reply belonged to an
    ///   earlier call, so the stream is off by one reply and every subsequent
    ///   read returns the wrong one. Reusing such a connection wedges it
    ///   permanently: each checkout fails the XID check, and if that were
    ///   judged reusable it would be requeued to fail the same way forever.
    ///
    /// All other errors -- including [`Xdr`](Self::Xdr),
    /// [`WrongLength`](Self::WrongLength), and
    /// [`NotFullyParsed`](Self::NotFullyParsed) -- are produced while operating
    /// on in-memory buffers after the full fragment has already been consumed
    /// from the wire, so the transport remains at a clean message boundary.
    #[must_use]
    pub const fn is_connection_reusable(&self) -> bool {
        !matches!(self, Self::Io(_) | Self::FragmentedReply | Self::UnexpectedXid)
    }
}
