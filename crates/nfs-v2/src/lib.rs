//! NFS version 2 -- [RFC 1094].
//!
//! All 18 procedures. The version is long obsolete and still enabled on plenty
//! of servers, which is exactly why it matters: it is the weakest of the three
//! by a wide margin.
//!
//! * **No security negotiation at all** ([RFC 2623] sec. 2.7). The server
//!   cannot advertise, and the client cannot request, anything beyond AUTH_SYS.
//! * **No `ACCESS` procedure.** NFSv3 added it so a client could ask what it
//!   would be permitted to do; under v2 a client simply tries the operation.
//! * **Fixed 32-byte file handles** with no length prefix (`FHSIZE = 32`,
//!   RFC 1094 sec. 2.3.3), unlike NFSv3's variable-length handle. That changes
//!   the XDR encoding, which is why these types cannot share NFSv3's.
//!
//! Some servers apply `root_squash` on their v3 path but not their v2 path, so
//! where both are offered v2 is worth probing first.
//!
//! [RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
//! [RFC 2623]: https://www.rfc-editor.org/rfc/rfc2623

mod client;
pub mod raw;
pub mod wire;

pub use client::{Nfs2Client, Nfs2Error, READ_FILE_MAX_BYTES};
pub use raw::Nfs2RawClient;
pub use wire::{NFS_PROGRAM as PROGRAM, NFS_VERSION as VERSION, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr, Nfs2Stat};

/// The MOUNT client, re-exported from `nfs-mount` under its old name.
///
/// Only the name is kept: this is [`nfs_mount::MountClient`], so construct it
/// with `MountClient::v1(transport)` (or `new(transport, MountVersion::V1)`)
/// and expect [`nfs_mount::MountedHandle`] from `mnt`. The client that used to
/// live here, with its own constructor and return types, is gone. New code
/// should name `nfs_mount::MountClient` directly.
pub type MountV1Client<T> = nfs_mount::MountClient<T>;
