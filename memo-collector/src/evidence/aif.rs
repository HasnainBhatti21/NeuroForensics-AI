//! AIF - Acquisition & Investigation Forensic Evidence Container.
//!
//! The AIF container is a structured evidence archive exposed with the
//! `.AIF` extension. For the MVP the internal encoding is ZIP (Deflate),
//! which keeps the container inspectable with standard tooling while the
//! external identity, manifest and integrity model remain AIF-specific.
//!
//! This is a custom NEUROFORENSICS AI format, not an industry-standard
//! forensic image format.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::evidence::manifest::Manifest;
use crate::hashing::sha256;

/// Result of a container-level integrity verification.
#[derive(Debug, Clone)]
pub struct ContainerVerification {
    pub expected: String,
    pub calculated: String,
    pub verified: bool,
    pub bytes: u64,
}

/// Result of deep verification of every artifact listed in the manifest.
#[derive(Debug, Clone)]
pub struct ArtifactVerification {
    pub artifact_id: String,
    pub relative_path: String,
    pub expected: String,
    pub calculated: String,
    pub verified: bool,
}

/// Package a staging directory into a `.AIF` container.
///
/// Files are added with deterministic ordering (sorted by relative path) so
/// identical staging content always produces the same entry order.
pub fn package_aif(staging: &Path, destination: &Path) -> std::io::Result<PathBuf> {
    let mut entries = Vec::new();
    walk_dir(staging, staging, &mut entries)?;
    entries.sort();

    let file = File::create(destination)?;
    let mut zip = zip::ZipWriter::new(BufWriter::new(file));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for rel in &entries {
        let full = staging.join(rel);
        let name = rel.to_string_lossy().replace('\\', "/");
        zip.start_file(name, options)
            .map_err(zip_to_io)?;
        let mut f = BufReader::new(File::open(&full)?);
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            zip.write_all(&buf[..n])?;
        }
    }
    zip.finish().map_err(zip_to_io)?;
    Ok(destination.to_path_buf())
}

fn walk_dir(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(base, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(base)
                .map(|p| p.to_path_buf())
                .unwrap_or(path.clone());
            out.push(rel);
        }
    }
    Ok(())
}

fn zip_to_io(e: zip::result::ZipError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

/// Stream-hash a whole AIF container.
pub fn hash_container(aif: &Path) -> std::io::Result<String> {
    sha256::hash_file(aif)
}

/// Verify the container hash against an expected value (from the sidecar
/// file or the chain-of-custody record).
pub fn verify_container(aif: &Path, expected: &str) -> std::io::Result<ContainerVerification> {
    let (calculated, bytes) = sha256::hash_reader_counted(BufReader::new(File::open(aif)?))?;
    Ok(ContainerVerification {
        expected: expected.to_lowercase(),
        calculated: calculated.clone(),
        verified: calculated.eq_ignore_ascii_case(expected.trim()),
        bytes,
    })
}

/// Read and parse `manifest.json` from an existing AIF container.
pub fn read_manifest(aif: &Path) -> std::io::Result<Manifest> {
    let file = File::open(aif)?;
    let mut archive = zip::ZipArchive::new(BufReader::new(file)).map_err(zip_to_io)?;
    let mut entry = archive
        .by_name("manifest.json")
        .map_err(zip_to_io)?;
    let mut content = String::new();
    entry.read_to_string(&mut content)?;
    serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Deep verification: re-hash every artifact listed in the manifest inside
/// the container and compare against the recorded SHA-256 values.
pub fn verify_artifacts(aif: &Path, manifest: &Manifest) -> std::io::Result<Vec<ArtifactVerification>> {
    let file = File::open(aif)?;
    let mut archive = zip::ZipArchive::new(BufReader::new(file)).map_err(zip_to_io)?;
    let mut results = Vec::with_capacity(manifest.artifacts.len());

    for artifact in &manifest.artifacts {
        let name = artifact.relative_path.replace('\\', "/");
        let (calculated, ok) = match archive.by_name(&name) {
            Ok(mut entry) => {
                match sha256::hash_reader_counted(&mut entry) {
                    Ok((h, _)) => (h, true),
                    Err(_) => (String::new(), false),
                }
            }
            Err(_) => (String::new(), false),
        };
        results.push(ArtifactVerification {
            artifact_id: artifact.artifact_id.clone(),
            relative_path: artifact.relative_path.clone(),
            expected: artifact.sha256.clone(),
            calculated: calculated.clone(),
            verified: ok && calculated == artifact.sha256,
        });
    }
    Ok(results)
}

/// Extract a single file from an AIF container to a destination path.
pub fn extract_file(aif: &Path, inner_path: &str, dest: &Path) -> std::io::Result<()> {
    let file = File::open(aif)?;
    let mut archive = zip::ZipArchive::new(BufReader::new(file)).map_err(zip_to_io)?;
    let mut entry = archive
        .by_name(&inner_path.replace('\\', "/"))
        .map_err(zip_to_io)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = BufWriter::new(File::create(dest)?);
    std::io::copy(&mut entry, &mut out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::artifact::{ArtifactRecord, ArtifactStatus};
    use std::fs;

    fn build_case_dir(dir: &Path) -> Manifest {
        fs::create_dir_all(dir.join("processes")).unwrap();
        fs::create_dir_all(dir.join("logs")).unwrap();

        let body = b"{\"processes\": []}";
        fs::write(dir.join("processes/process_list.json"), body).unwrap();
        let log = b"[engine] acquisition test\n";
        fs::write(dir.join("logs/acquisition.log"), log).unwrap();

        let mut manifest = Manifest::new(
            &crate::evidence::manifest::CaseInfo {
                case_id: "CASE-UNIT".into(),
                case_name: "unit".into(),
                ..Default::default()
            },
            Default::default(),
        );
        let mut art = ArtifactRecord::new("ART-000001".into(), "processes/process_list.json".into());
        art.size = body.len() as u64;
        art.sha256 = sha256::hash_bytes(body);
        art.status = ArtifactStatus::Acquired;
        art.source = "unit test".into();
        art.collector = "processes".into();
        manifest.artifacts.push(art);
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        manifest
    }

    #[test]
    fn aif_roundtrip_and_integrity() {
        let tmp = std::env::temp_dir().join(format!("memo-aif-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let staging = tmp.join("staging");
        fs::create_dir_all(&staging).unwrap();
        let _manifest = build_case_dir(&staging);

        let aif = tmp.join("CASE-UNIT.AIF");
        package_aif(&staging, &aif).unwrap();
        assert!(aif.exists());

        // Container hash must be stable and verifiable.
        let h1 = hash_container(&aif).unwrap();
        let verification = verify_container(&aif, &h1).unwrap();
        assert!(verification.verified);
        assert_eq!(verification.calculated, h1);

        // Tamper detection: wrong expected hash must fail.
        let bad = verify_container(&aif, &"0".repeat(64)).unwrap();
        assert!(!bad.verified);

        // Manifest must be readable back.
        let read = read_manifest(&aif).unwrap();
        assert_eq!(read.case_id, "CASE-UNIT");

        // Deep artifact verification must pass.
        let results = verify_artifacts(&aif, &read).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].verified);

        let _ = fs::remove_dir_all(&tmp);
    }
}
