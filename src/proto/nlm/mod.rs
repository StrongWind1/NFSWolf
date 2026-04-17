//! Network Lock Manager (NLM) client.
//!
//! NLM4 is used for file locking in NFSv3 environments (RFC 1813).
//! nfswolf uses it to fingerprint exposed lock services and probe DoS surfaces.

pub mod client;
