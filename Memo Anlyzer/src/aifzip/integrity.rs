//! AIF integrity verification — streaming SHA-256, external sidecar
//! discovery and deep per-artifact verification, exactly per the
//! MEMO Collector verification procedure (docs/aif-format.md §8).

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::container::OpenedAif;

const HASH_BUF: usize = 1024 * 1024;

/// Streaming SHA-256 over any reader; returns (hex hash, bytes read).
pub fn hash_stream(reader: &mut dyn Read) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// SHA-256 of a whole file, streamed (never buffered).
pub fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    hash_stream(&mut reader)
}

/// External integrity sidecars found next to an AIF container.
#[derive(Clone, Debug)]
pub struct SidecarInfo {
    /// Expected container SHA-256 from `.AIF.sha256` or custody record.
    pub expected_sha256: Option<String>,
    /// Where the expected value came from (for display).
    pub source: Option<String>,
    /// Paths of companion files that were found.
    pub companions: Vec<PathBuf>,
}

impl SidecarInfo {
    /// Look for `<name>.sha256` and `<stem>.custody.json` beside the
    /// container (MEMO Collector naming convention).
    pub fn discover(aif_path: &Path) -> Option<SidecarInfo> {
        let mut info = SidecarInfo { expected_sha256: None, source: None, companions: Vec::new() };

        // <CASE-ID>.AIF.sha256 — sha256sum format: "<hash>  <filename>"
        let sha_path = PathBuf::from(format!("{}.sha256", aif_path.display()));
        if sha_path.is_file() {
            info.companions.push(sha_path.clone());
            if let Ok(text) = std::fs::read_to_string(&sha_path) {
                let hash = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
                if is_hex64(&hash) {
                    info.expected_sha256 = Some(hash);
                    info.source = Some(
                        sha_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("sidecar")
                            .to_string(),
                    );
                }
            }
        }

        // <CASE-ID>.custody.json — external custody record (aif_sha256).
        let stem = aif_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("case");
        let custody_path = aif_path.with_file_name(format!("{stem}.custody.json"));
        if custody_path.is_file() {
            info.companions.push(custody_path.clone());
            if info.expected_sha256.is_none() {
                if let Ok(text) = std::fs::read_to_string(&custody_path) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                        let hash = v
                            .get("aif_sha256")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if is_hex64(&hash) {
                            info.expected_sha256 = Some(hash);
                            info.source = Some(
                                custody_path
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("custody")
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }

        if info.companions.is_empty() {
            None
        } else {
            Some(info)
        }
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Result of one per-artifact integrity check.
#[derive(Clone, Debug)]
pub struct ArtifactCheck {
    pub artifact_id: String,
    pub relative_path: String,
    pub expected: String,
    pub calculated: String,
    pub ok: bool,
    /// True when the manifest lists the entry but the archive lacks it.
    pub missing: bool,
}

/// Container-level integrity verdict.
#[derive(Clone, Debug)]
pub struct ContainerCheck {
    pub calculated: String,
    pub expected: Option<String>,
    /// None when no external expected hash exists.
    pub ok: Option<bool>,
    pub expected_source: Option<String>,
}

impl ContainerCheck {
    pub fn from(aif: &OpenedAif) -> ContainerCheck {
        let expected = aif.sidecar.as_ref().and_then(|s| s.expected_sha256.clone());
        let ok = expected.as_ref().map(|e| e.eq_ignore_ascii_case(&aif.container_sha256));
        let expected_source = aif.sidecar.as_ref().and_then(|s| s.source.clone());
        ContainerCheck {
            calculated: aif.container_sha256.clone(),
            expected,
            ok,
            expected_source,
        }
    }
}

/// Deep verification: stream-hash every artifact listed in
/// `manifest.json` and compare against the recorded SHA-256.
pub fn deep_verify(aif: &mut OpenedAif) -> Vec<ArtifactCheck> {
    deep_verify_progress(aif, None)
}

/// Deep verification with optional live progress reporting (real
/// counters, never simulated).
pub fn deep_verify_progress(
    aif: &mut OpenedAif,
    progress: Option<&std::sync::mpsc::Sender<String>>,
) -> Vec<ArtifactCheck> {
    let mut checks = Vec::new();
    // Collect first: the borrow of the manifest must end before we
    // borrow the archive mutably for streaming reads.
    let targets: Vec<(String, String, String)> = aif
        .manifest
        .artifacts
        .iter()
        .map(|a| (a.artifact_id.clone(), a.relative_path.clone(), a.sha256.clone()))
        .collect();

    let total = targets.len();
    for (idx, (artifact_id, relative_path, expected)) in targets.into_iter().enumerate() {
        if let Some(tx) = progress {
            if idx % 25 == 0 || idx + 1 == total {
                let _ = tx.send(format!("Deep-verified {}/{} artifact hash(es)…", idx + 1, total));
            }
        }
        if !aif.has_entry(&relative_path) {
            checks.push(ArtifactCheck {
                artifact_id,
                relative_path,
                expected,
                calculated: String::new(),
                ok: false,
                missing: true,
            });
            continue;
        }
        let result = aif.with_entry_reader(&relative_path, |reader| {
            hash_stream(reader).map_err(|e| e.to_string())
        });
        match result {
            Ok((calculated, _)) => {
                let ok = calculated.eq_ignore_ascii_case(&expected);
                checks.push(ArtifactCheck {
                    artifact_id,
                    relative_path,
                    expected,
                    calculated,
                    ok,
                    missing: false,
                });
            }
            Err(_) => checks.push(ArtifactCheck {
                artifact_id,
                relative_path,
                expected,
                calculated: String::new(),
                ok: false,
                missing: true,
            }),
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aifzip::container::open_aif;
    use std::io::Write;
    use zip::write::FileOptions;
    use zip::ZipWriter;

    fn build_test_aif(dir: &Path, artifact_body: &str, recorded_hash: &str) -> PathBuf {
        let aif_path = dir.join("CASE-TEST-0001.AIF");
        let file = std::fs::File::create(&aif_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        let manifest = format!(
            r#"{{
              "case_id": "CASE-TEST-0001",
              "case_name": "Unit Test",
              "collector": {{"name":"MEMO Collector","version":"1.0.0","build":"test","platform":"test"}},
              "host": {{"hostname":"TEST"}},
              "acquisition": {{"start_time":"","end_time":"","operator":"","method":"","status":"COMPLETED"}},
              "modules": [],
              "artifacts": [{{
                "artifact_id": "ART-000001",
                "relative_path": "system/os.json",
                "size": {size},
                "sha256": "{hash}",
                "acquisition_time": "2026-08-29T00:00:00Z",
                "source": "test",
                "collector": "system",
                "status": "ACQUIRED"
              }}],
              "warnings": [],
              "errors": [],
              "integrity": {{"algorithm":"SHA-256","artifact_hashes_in_manifest":true,"aif_sha256":null}}
            }}"#,
            size = artifact_body.len(),
            hash = recorded_hash
        );
        let case = r#"{"format":"AIF - Acquisition & Investigation Forensic Evidence Container","format_version":1,"case":{"case_id":"CASE-TEST-0001","case_name":"Unit Test","investigator_name":"T","organization":"","evidence_description":"","acquisition_notes":"","destination":".","demo_mode":false,"created_at":"2026-08-29T00:00:00Z"},"container_sha256":null}"#;

        zip.start_file("case.json", opts).unwrap();
        zip.write_all(case.as_bytes()).unwrap();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();
        zip.start_file("system/os.json", opts).unwrap();
        zip.write_all(artifact_body.as_bytes()).unwrap();
        zip.finish().unwrap();
        aif_path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("neuroforensics_aifzip_tests").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn opens_real_format_and_parses_manifest() {
        let dir = temp_dir("valid");
        let body = r#"{"os":"Windows"}"#;
        let hash = {
            let mut h = Sha256::new();
            h.update(body.as_bytes());
            hex::encode(h.finalize())
        };
        let path = build_test_aif(&dir, body, &hash);

        let mut aif = open_aif(&path).expect("opens");
        assert_eq!(aif.manifest.case_id, "CASE-TEST-0001");
        assert_eq!(aif.case_doc.format_version, 1);
        assert!(!aif.case_doc.case.demo_mode);
        assert_eq!(aif.manifest.artifacts.len(), 1);
        assert!(aif.has_entry("system/os.json"));

        let checks = deep_verify(&mut aif);
        assert_eq!(checks.len(), 1);
        assert!(checks[0].ok, "artifact hash must verify: {:?}", checks[0]);

        let cc = ContainerCheck::from(&aif);
        assert_eq!(cc.ok, None); // no sidecar -> unknown, not failed
    }

    #[test]
    fn detects_hash_mismatch() {
        let dir = temp_dir("tampered");
        let path = build_test_aif(&dir, r#"{"os":"Windows"}"#, &"0".repeat(64));
        let mut aif = open_aif(&path).expect("opens");
        let checks = deep_verify(&mut aif);
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].ok);
        assert!(!checks[0].missing);
    }

    #[test]
    fn rejects_plain_json_with_forensic_error() {
        let dir = temp_dir("json");
        let path = dir.join("fake.AIF");
        std::fs::write(&path, br#"{"format":"AIF/1.0"}"#).unwrap();
        let err = match open_aif(&path) {
            Ok(_) => panic!("plain JSON must be rejected"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("plain JSON"), "was: {msg}");
        assert!(!msg.contains("invalid AIF JSON"));
    }

    #[test]
    fn rejects_unknown_binary_header() {
        let dir = temp_dir("binary");
        let path = dir.join("fake.AIF");
        std::fs::write(&path, b"NEUR0AIF\x01\x00\x00\x00garbage").unwrap();
        let err = match open_aif(&path) {
            Ok(_) => panic!("unknown binary header must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("Not an AIF evidence container"));
    }

    #[test]
    fn sidecar_hash_is_discovered_and_compared() {
        let dir = temp_dir("sidecar");
        let body = r#"{"ok":true}"#;
        let hash = {
            let mut h = Sha256::new();
            h.update(body.as_bytes());
            hex::encode(h.finalize())
        };
        let path = build_test_aif(&dir, body, &hash);

        // Write the external sidecar in sha256sum format.
        let (container_hash, _) = hash_file(&path).unwrap();
        std::fs::write(
            dir.join("CASE-TEST-0001.AIF.sha256"),
            format!("{container_hash}  CASE-TEST-0001.AIF\n"),
        )
        .unwrap();

        let aif = open_aif(&path).expect("opens");
        let cc = ContainerCheck::from(&aif);
        assert_eq!(cc.ok, Some(true));

        // Tamper with the sidecar -> mismatch reported, not a crash.
        std::fs::write(
            dir.join("CASE-TEST-0001.AIF.sha256"),
            format!("{}  CASE-TEST-0001.AIF\n", "f".repeat(64)),
        )
        .unwrap();
        let aif = open_aif(&path).expect("opens");
        let cc = ContainerCheck::from(&aif);
        assert_eq!(cc.ok, Some(false));
    }

    #[test]
    fn missing_manifest_is_a_format_error() {
        let dir = temp_dir("nomanifest");
        let path = dir.join("no-manifest.AIF");
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("case.json", FileOptions::default()).unwrap();
        zip.write_all(b"{}").unwrap();
        zip.finish().unwrap();
        let err = match open_aif(&path) {
            Ok(_) => panic!("container without manifest.json must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("manifest.json"));
    }

    /// Contract test against a real MEMO Collector output file. Runs
    /// only when the sample case is present on this workstation.
    #[test]
    fn real_collector_case_opens_and_verifies() {
        let path = Path::new(r"E:\Desktop\thE rEAL\CASE-2026-1070.AIF");
        if !path.is_file() {
            eprintln!("sample AIF not present - skipping real-file contract test");
            return;
        }
        let mut aif = open_aif(path).expect("real AIF opens");
        assert_eq!(aif.case_doc.format_version, 1);
        assert_eq!(aif.manifest.case_id, "CASE-2026-1070");
        assert!(!aif.manifest.artifacts.is_empty());
        assert!(aif.manifest.artifacts.iter().all(|a| a.artifact_id.starts_with("ART-")));
        // Sidecar sits next to the container -> container hash must match.
        let cc = ContainerCheck::from(&aif);
        assert_eq!(cc.ok, Some(true), "sidecar container hash must verify");
        // Deep verification: every acquired artifact hash must match.
        let checks = deep_verify(&mut aif);
        assert_eq!(checks.len(), aif.manifest.artifacts.len());
        for c in &checks {
            assert!(c.ok, "artifact {} failed hash verification", c.artifact_id);
        }
    }
}
