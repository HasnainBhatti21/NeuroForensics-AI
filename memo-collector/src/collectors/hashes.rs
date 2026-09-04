//! HashCollector - SHA-256 hashing of observed executables.
//!
//! Uses streaming hashing: large files are never fully loaded into RAM.
//! Files above the configured size cap are recorded with status SKIPPED.

use std::collections::HashSet;
use std::path::Path;

use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::evidence::artifact::ArtifactStatus;
use crate::hashing::sha256;

#[derive(Default)]
pub struct HashCollector {}

impl ICollector for HashCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Hashes
    }

    fn name(&self) -> &'static str {
        "File / Artifact Hashes"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        // Rebuild the unique executable list from the live process snapshot
        // (independent of whether the Processes module was selected).
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut exes: Vec<String> = sys
            .processes()
            .values()
            .filter_map(|p| p.exe().map(|e| e.to_string_lossy().into_owned()))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        exes.sort();

        let max_files = ctx.settings.max_executables_to_hash;
        let max_bytes = ctx.settings.max_hash_file_bytes;

        let mut records = Vec::new();
        let mut hashed = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;

        for (index, exe) in exes.iter().enumerate() {
            ctx.check_cancel()?;
            ctx.wait_if_paused();

            let path = Path::new(exe);
            let status: ArtifactStatus;
            let mut hash = String::new();
            let mut size = 0u64;
            let mut note: Option<String> = None;

            if hashed >= max_files {
                status = ArtifactStatus::Skipped;
                note = Some(format!("hashing cap reached ({})", max_files));
                skipped += 1;
            } else {
                match std::fs::metadata(path) {
                    Ok(meta) => {
                        size = meta.len();
                        if size > max_bytes {
                            status = ArtifactStatus::Skipped;
                            note = Some(format!(
                                "file exceeds hashing size cap ({} bytes)",
                                size
                            ));
                            skipped += 1;
                        } else {
                            match sha256::hash_file(path) {
                                Ok(h) => {
                                    hash = h;
                                    status = ArtifactStatus::Acquired;
                                    hashed += 1;
                                }
                                Err(e) => {
                                    status = ArtifactStatus::Failed;
                                    note = Some(e.to_string());
                                    failed += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        status = ArtifactStatus::Failed;
                        note = Some(e.to_string());
                        failed += 1;
                    }
                }
            }

            records.push(json!({
                "index": index,
                "relative_path": exe,
                "size": size,
                "SHA256": if hash.is_empty() { serde_json::Value::Null } else { json!(hash) },
                "acquisition_time": chrono::Local::now().to_rfc3339(),
                "source": "executable of an observed running process",
                "collector": "hashes",
                "status": format!("{:?}", status).to_uppercase(),
                "note": note,
            }));
        }

        ctx.add_json(
            "hashes/hashes.json",
            "streaming SHA-256 of process executables",
            Some(format!(
                "{} hashed, {} skipped, {} failed (cap: {} files, {} bytes/file)",
                hashed, skipped, failed, max_files, max_bytes
            )),
            &json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "algorithm": "SHA-256",
                "streaming": true,
                "executable_count": exes.len(),
                "hashed": hashed,
                "skipped": skipped,
                "failed": failed,
                "records": records,
            }),
        )?;

        Ok(())
    }
}
