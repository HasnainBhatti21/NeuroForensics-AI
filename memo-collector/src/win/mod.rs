//! Windows API helpers.
//!
//! Thin, defensive wrappers around documented Windows APIs and built-in
//! command-line tools. Everything here is strictly READ-ONLY: no registry
//! writes, no process termination, no configuration changes.

pub mod events;
pub mod gpu;
pub mod memory;
pub mod network;
pub mod powershell;
pub mod privs;
pub mod processes;
