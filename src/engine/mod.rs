//! Core analysis and exploitation engine.
//!
//! Orchestrates protocol clients to perform security checks,
//! file handle analysis, and automated exploitation primitives
//! (escape construction, handle brute force, UID spray).

pub(crate) mod analyzer;
pub(crate) mod credential;
pub(crate) mod file_handle;
pub(crate) mod scan_types;
pub(crate) mod scanner;
pub(crate) mod uid_sprayer;
