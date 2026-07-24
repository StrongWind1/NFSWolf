//! NFS version 4.0 -- [RFC 7530].
//!
//! NFSv4 is a different shape from v2 and v3.  Rather than one RPC per
//! operation, the client batches operations into a single `COMPOUND` call
//! that the server executes in order against a "current file handle" the
//! operations mutate as they go -- so `PUTROOTFH; LOOKUP "etc"; GETFH` is one
//! round trip.  MOUNT is gone; the server exports a single pseudo-filesystem
//! tree reached from `PUTROOTFH`.
//!
//! This module implements the read-only subset NFSWolf needs for
//! reconnaissance -- enough to walk the pseudo-filesystem, read attributes,
//! list directories, query per-directory security flavors, and read file
//! data.  The stateful half of the protocol (`OPEN`, `CLOSE`, `LOCK`,
//! delegations, and the v4.1 session machinery of [RFC 8881]) is not
//! implemented.
//!
//! [RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
//! [RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881

mod types;

pub use types::*;
