//! Errors from the MOUNT protocol.

use std::error::Error as StdError;
use std::fmt;

use crate::wire::mount::mountstat3;

/// Error from a MOUNT operation.
///
/// Generic over the transport's error type, so a caller layering its own
/// connection policy underneath still gets that policy's errors back
/// unflattened.
///
/// The distinction between the two variants matters: [`Rpc`](Self::Rpc) means
/// the request never got a protocol answer, while [`Status`](Self::Status)
/// means the server understood the request and refused it. Only the second is
/// evidence about the export's configuration.
#[derive(Debug)]
pub enum MountError<E> {
    /// The RPC call failed before the server gave a MOUNT status.
    Rpc(E),
    /// The mount server returned a non-OK status code.
    Status(mountstat3),
}

impl<E: fmt::Display> fmt::Display for MountError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(e) => e.fmt(f),
            Self::Status(e) => e.fmt(f),
        }
    }
}

impl<E: StdError + 'static> StdError for MountError<E> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Rpc(e) => Some(e),
            Self::Status(_) => None,
        }
    }
}

impl<E> MountError<E> {
    /// Whether the server refused the mount, as opposed to the call failing.
    ///
    /// A denial is a finding about the export; a transport failure is not.
    #[must_use]
    pub const fn is_denial(&self) -> bool {
        matches!(self, Self::Status(_))
    }

    /// The MOUNT status code, when the server returned one.
    #[must_use]
    pub const fn status(&self) -> Option<mountstat3> {
        match self {
            Self::Status(s) => Some(*s),
            Self::Rpc(_) => None,
        }
    }
}
