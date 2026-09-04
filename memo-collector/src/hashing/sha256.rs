//! SHA-256 streaming hashing engine.
//!
//! All evidence artifacts are hashed with SHA-256. Large files are hashed
//! with a streaming implementation so the entire file is never loaded into
//! RAM at once.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Size of the streaming read buffer used for hashing (1 MiB).
pub const HASH_BUFFER_SIZE: usize = 1024 * 1024;

/// Hash raw bytes with SHA-256, returning lowercase hex.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Stream-hash a file with SHA-256, returning lowercase hex.
///
/// The file is read in [`HASH_BUFFER_SIZE`] chunks; arbitrarily large files
/// can be hashed without loading them fully into memory.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    hash_reader(BufReader::new(file)).map_err(io_to_hash_err)
}

/// Hash any `Read` source in a streaming fashion. Also returns the number
/// of bytes that were consumed.
pub fn hash_reader_counted<R: Read>(mut reader: R) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUFFER_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

fn hash_reader<R: Read>(reader: R) -> Result<String, std::io::Error> {
    hash_reader_counted(reader).map(|(h, _)| h)
}

fn io_to_hash_err(e: std::io::Error) -> std::io::Error {
    e
}

/// Compute the SHA-256 of a file while copying it to a destination, in a
/// single streaming pass. Returns `(sha256, bytes_written)`.
pub fn hash_while_copying(src: &Path, dst: &Path) -> std::io::Result<(String, u64)> {
    use std::io::Write;
    let mut input = BufReader::new(File::open(src)?);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut output = std::io::BufWriter::new(File::create(dst)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUFFER_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output.write_all(&buf[..n])?;
        total += n as u64;
    }
    output.flush()?;
    Ok((format!("{:x}", hasher.finalize()), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vectors() {
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn streaming_hash_matches_memory_hash() {
        let data = vec![0xABu8; 3 * HASH_BUFFER_SIZE + 17];
        let mem = hash_bytes(&data);
        let (streamed, count) = hash_reader_counted(&data[..]).unwrap();
        assert_eq!(mem, streamed);
        assert_eq!(count as usize, data.len());
    }
}
