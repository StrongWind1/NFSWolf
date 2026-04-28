//! Core analysis and exploitation engine.
//!
//! Orchestrates protocol clients to perform security checks,
//! file handle analysis, and automated attacks.

pub mod analyzer;
pub mod credential;
pub mod file_handle;
pub mod scanner;
pub mod uid_sprayer;
