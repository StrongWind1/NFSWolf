//! Network Status Monitor (NSM/statd) client.
//!
//! Used to probe statd exposure and read the server reboot counter.
//! A stale reboot counter means NLM lock state may be incorrect after a crash.

pub mod client;
