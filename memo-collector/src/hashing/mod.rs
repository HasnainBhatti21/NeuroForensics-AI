//! Hashing engine (SHA-256, streaming).

pub mod sha256;

pub use sha256::{hash_bytes, hash_file, hash_reader_counted, hash_while_copying};
