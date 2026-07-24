//! Async I/O abstraction and TCP connectors.
//!
//! The protocol clients are written against the minimal [`io::AsyncRead`] and
//! [`io::AsyncWrite`] traits rather than a specific runtime's, so a caller can
//! slot in a plain TCP stream, a SOCKS5-proxied stream, or a test double
//! without the client knowing the difference.
//!
//! Only a tokio backend ships here.  Upstream also offered smol; NFSWolf has
//! no smol code path, so that backend was dropped during absorption.

pub mod io;
pub mod net;
pub mod tokio;
