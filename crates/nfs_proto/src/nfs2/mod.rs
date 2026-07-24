//! NFS version 2 -- [RFC 1094].
//!
//! The 18 procedures of NFSv2 (program 100003, version 2).  This version is
//! long obsolete but still enabled on a surprising number of servers, and it
//! is the weakest of the three by a wide margin:
//!
//! * There is no security negotiation at all ([RFC 2623] sec. 2.7) -- the
//!   server cannot advertise, and the client cannot request, anything beyond
//!   AUTH_SYS.
//! * There is no `ACCESS` procedure, so the server has no way to advise on
//!   permissions ahead of an operation; a client simply tries it.
//! * File handles are a fixed 32 bytes with no length prefix
//!   (`FHSIZE = 32`, RFC 1094 sec. 2.3.3), unlike NFSv3's variable-length
//!   handle.  This changes the XDR encoding, which is why these types cannot
//!   share NFSv3's.
//!
//! Some servers apply `root_squash` on their v3 path but not their v2 path,
//! which makes v2 worth probing first when it is offered.
//!
//! [RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
//! [RFC 2623]: https://www.rfc-editor.org/rfc/rfc2623

mod types;

pub use types::*;
