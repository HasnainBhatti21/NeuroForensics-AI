//! Acquisition engine - orchestrates collectors, manifest, custody and
//! AIF packaging. Runs on a worker thread; the GUI observes shared state.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::collectors::{
    build_collector, AcquisitionControl, AcquisitionOutcome, AcquisitionProgress,
    AcquisitionSettings, Availability, CollectContext, CollectorError, CollectorId, ModuleState,
};
use crate::evidence::custody::{ChainOfCustody, CustodyLog};
use crate::evidence::manifest::{CaseDocument, CaseInfo, HostInfo, Manifest};
use crate::evidence::{aif, ArtifactStatus};
use crate::reporting;
use crate::{win, APP_NAME, APP_VERSION, AIF_FORMAT_NAME};

/// Everything the engine needs to run one acquisition.
pub struct AcquisitionParams {
    pub case: CaseInfo,
    pub modules: Vec<CollectorId>,
    pub settings: AcquisitionSettings,
}

fn now_rfc3339() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Sanitize a string for safe use in file names.
pub fn sanitize_file_component(input: &str) -> String {
    let invalid = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    let cleaned: String = input
        .chars()
        .map(|c| if invalid.contains(&c) { '_' } else { c })
        .collect();
    let trimmed = cleaned.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        "case".to_string()
    } else {
        trimmed.to_string()
    }
}

fn snapshot_host() -> HostInfo {
    HostInfo {
        hostname: sysinfo::System::host_name().unwrap_or_default(),
        os: sysinfo::System::name().unwrap_or_default(),
        os_version: sysinfo::System::os_version().unwrap_or_default(),
        architecture: sysinfo::System::cpu_arch(),
        kernel_version: sysinfo::System::kernel_version().unwrap_or_default(),
        boot_time: chrono::DateTime::from_timestamp(sysinfo::System::boot_time() as i64, 0)
            .map(|d| d.to_rfc3339()),
        username: std::env::var("USERNAME").unwrap_or_default(),
        domain: std::env::var("USERDOMAIN").unwrap_or_default(),
        elevated: win::privs::is_elevated(),
    }
}

/// Run a full acquisition. Intended to run on a background thread.
pub fn run_acquisition(
    params: AcquisitionParams,
    progress: Arc<Mutex<AcquisitionProgress>>,
    control: Arc<AcquisitionControl>,
) {
    let started = now_rfc3339();
    {
        let mut p = progress.lock().unwrap();
        p.running = true;
        p.phase = "Initializing".to_string();
        p.demo_mode = params.case.demo_mode;
        p.started_at = Some(started.clone());
        p.modules = params
            .modules
            .iter()
            .map(|id| crate::collectors::ModuleProgress {
                id: *id,
                name: id.display_name().to_string(),
                state: ModuleState::Pending,
                artifacts: 0,
                bytes: 0,
                note: String::new(),
                started_at: None,
                finished_at: None,
            })
            .collect();
    }

    // ------------------------------------------------------------------
    // Staging + custody log
    // ------------------------------------------------------------------
    let case_file_id = sanitize_file_component(&params.case.case_id);
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let staging = std::env::temp_dir()
        .join("MEMO Collector")
        .join(format!("{}-{}", case_file_id, stamp));
    if std::fs::create_dir_all(&staging).is_err() {
        fail_run(&progress, "Failed to create staging directory", &started);
        return;
    }

    let mut log = CustodyLog::new();
    log.bind(&staging.join("logs").join("acquisition.log"));
    let log = Arc::new(Mutex::new(log));

    {
        let mut log = log.lock().unwrap();
        log.info("engine", &format!("{} {} acquisition started", APP_NAME, APP_VERSION));
        log.info("engine", &format!("case id: {}", params.case.case_id));
        log.info(
            "engine",
            &format!(
                "requested modules: {}",
                params
                    .modules
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        if params.case.demo_mode {
            log.warn("engine", "DEMO MODE active: artifacts are SYNTHETIC DEMONSTRATION DATA");
        }
    }

    let host = snapshot_host();
    let mut manifest = Manifest::new(&params.case, host.clone());
    manifest.acquisition.start_time = started.clone();

    let artifact_seq = Arc::new(AtomicU64::new(0));
    let mut cancelled = false;
    let mut failed_module_names: Vec<String> = Vec::new();

    // ------------------------------------------------------------------
    // Module execution loop - one failure never stops the acquisition
    // ------------------------------------------------------------------
    for (index, module_id) in params.modules.iter().enumerate() {
        if control.cancel.load(Ordering::SeqCst) {
            cancelled = true;
            break;
        }

        {
            let mut p = progress.lock().unwrap();
            p.current_module = Some(index);
            p.phase = format!("Acquiring: {}", module_id.display_name());
            if let Some(m) = p.modules.get_mut(index) {
                m.state = ModuleState::Running;
                m.started_at = Some(now_rfc3339());
            }
        }
        if let Ok(mut log) = log.lock() {
            log.info("engine", &format!("module started: {}", module_id.as_str()));
        }

        let mut collector = build_collector(*module_id, params.case.demo_mode);
        let mut ctx = CollectContext::new(
            *module_id,
            staging.clone(),
            params.case.demo_mode,
            params.settings.clone(),
            Arc::clone(&log),
            Arc::clone(&progress),
            Arc::clone(&control),
            Arc::clone(&artifact_seq),
        );

        let module_result: Result<(), CollectorError> = (|| {
            collector.initialize(&mut ctx)?;
            match collector.check_availability() {
                Availability::Available => collector.collect(&mut ctx),
                Availability::NotAvailable { reason } => {
                    ctx.warn(format!(
                        "STATUS: NOT AVAILABLE ({}); ACTION: SKIPPED",
                        reason
                    ));
                    Err(CollectorError {
                        module: module_id.as_str().to_string(),
                        code: "NOT_AVAILABLE".to_string(),
                        description: reason,
                        recommended_action: "Skipped; no action required.".to_string(),
                    })
                }
            }
        })();

        let records = ctx.take_records();
        let warnings = ctx.take_warnings();
        let artifacts = records.len();
        let bytes: u64 = records.iter().map(|r| r.size).sum();
        manifest.artifacts.extend(records);
        manifest.warnings.extend(warnings.iter().cloned());

        let (state, status_label, reason) = match &module_result {
            Ok(()) => {
                if let Ok(mut log) = log.lock() {
                    log.info(
                        "engine",
                        &format!(
                            "module completed: {} ({} artifacts, {} bytes)",
                            module_id.as_str(),
                            artifacts,
                            bytes
                        ),
                    );
                }
                (ModuleState::Completed, "COMPLETED", None)
            }
            Err(err) if err.is_cancelled() => {
                cancelled = true;
                if let Ok(mut log) = log.lock() {
                    log.warn("engine", "acquisition cancelled by operator");
                }
                (ModuleState::Cancelled, "CANCELLED", Some(err.description.clone()))
            }
            Err(err) if err.code == "NOT_AVAILABLE" => {
                if let Ok(mut log) = log.lock() {
                    log.warn(
                        "engine",
                        &format!("module skipped: {} ({})", module_id.as_str(), err.description),
                    );
                }
                (ModuleState::Skipped, "SKIPPED", Some(err.description.clone()))
            }
            Err(err) => {
                failed_module_names.push(module_id.display_name().to_string());
                manifest.errors.push(format!(
                    "[{}] {} - {}",
                    err.module, err.code, err.description
                ));
                if let Ok(mut log) = log.lock() {
                    log.error(
                        "engine",
                        &format!(
                            "module failed: {} [{}] {}",
                            err.module, err.code, err.description
                        ),
                    );
                }
                {
                    let mut p = progress.lock().unwrap();
                    p.errors.push(crate::collectors::FailureRecord {
                        timestamp: now_rfc3339(),
                        module: err.module.clone(),
                        code: err.code.clone(),
                        description: err.description.clone(),
                        recommended_action: err.recommended_action.clone(),
                    });
                }
                (
                    ModuleState::Failed,
                    "FAILED",
                    Some(format!("[{}] {}", err.code, err.description)),
                )
            }
        };

        manifest.modules.push(crate::evidence::artifact::ModuleSummary {
            module_id: module_id.as_str().to_string(),
            module_name: module_id.display_name().to_string(),
            status: status_label.to_string(),
            reason,
            artifacts,
            bytes,
            started_at: None,
            finished_at: None,
            warnings: warnings.clone(),
        });

        {
            let mut p = progress.lock().unwrap();
            if let Some(m) = p.modules.get_mut(index) {
                m.state = state;
                m.finished_at = Some(now_rfc3339());
                if state == ModuleState::Cancelled {
                    m.note = "Cancelled by operator".to_string();
                }
            }
        }

        collector.cleanup();

        if cancelled {
            break;
        }
    }

    // Remaining modules after a cancellation stay marked as cancelled.
    if cancelled {
        let mut p = progress.lock().unwrap();
        for module in p.modules.iter_mut() {
            if module.state == ModuleState::Pending {
                module.state = ModuleState::Cancelled;
            }
        }
    }

    // ------------------------------------------------------------------
    // Finalize manifest + custody
    // ------------------------------------------------------------------
    let ended = now_rfc3339();
    manifest.acquisition.end_time = ended.clone();
    manifest.acquisition.status = if cancelled {
        "PARTIAL".to_string()
    } else if failed_module_names.is_empty() {
        "COMPLETED".to_string()
    } else {
        "COMPLETED_WITH_FAILURES".to_string()
    };

    let mut custody = ChainOfCustody::new(
        &params.case.case_id,
        &host.hostname,
        &params.case.investigator_name,
    );
    custody.start_time = started.clone();
    custody.end_time = ended.clone();
    custody.modules_requested = params.modules.iter().map(|m| m.as_str().to_string()).collect();
    custody.modules_successful = manifest
        .modules
        .iter()
        .filter(|m| m.status == "COMPLETED")
        .map(|m| m.module_name.clone())
        .collect();
    custody.modules_skipped = manifest
        .modules
        .iter()
        .filter(|m| m.status == "SKIPPED" || m.status == "CANCELLED")
        .map(|m| m.module_name.clone())
        .collect();
    custody.modules_failed = manifest
        .modules
        .iter()
        .filter(|m| m.status == "FAILED")
        .map(|m| m.module_name.clone())
        .collect();
    custody.warning_count = manifest.warnings.len();
    custody.artifact_count = manifest.artifacts.len();
    custody.status = manifest.acquisition.status.clone();

    {
        let mut log = log.lock().unwrap();
        log.info(
            "engine",
            &format!(
                "acquisition finished: {} artifacts, {} warnings, {} failed modules",
                custody.artifact_count, custody.warning_count, custody.modules_failed.len()
            ),
        );
    }

    // ------------------------------------------------------------------
    // Write root documents into staging, then package the AIF container
    // ------------------------------------------------------------------
    {
        let mut p = progress.lock().unwrap();
        p.phase = "Packaging AIF container".to_string();
    }

    let write_root = |name: &str, bytes: Vec<u8>| -> Result<(), String> {
        std::fs::write(staging.join(name), bytes).map_err(|e| e.to_string())
    };
    if let Err(e) = write_root(
        "manifest.json",
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    ) {
        fail_run(&progress, &format!("Failed to write manifest: {}", e), &started);
        return;
    }

    let case_doc = CaseDocument {
        format: AIF_FORMAT_NAME.to_string(),
        format_version: 1,
        case: params.case.clone(),
        container_sha256: None,
    };
    let _ = write_root("case.json", serde_json::to_vec_pretty(&case_doc).unwrap_or_default());
    let _ = write_root(
        "custody.json",
        serde_json::to_vec_pretty(&custody).unwrap_or_default(),
    );

    // Report copy inside the container (container hash recorded later in the
    // sidecar because a container cannot contain its own hash).
    let inner_report = reporting::html::render(&manifest, &custody, None);
    let _ = write_root(
        "reports/acquisition_report.html",
        inner_report.into_bytes(),
    );

    let destination_dir = PathBuf::from(&params.case.destination);
    if std::fs::create_dir_all(&destination_dir).is_err() {
        fail_run(&progress, "Failed to create destination directory", &started);
        return;
    }
    let aif_path = destination_dir.join(format!("{}.AIF", case_file_id));

    {
        let mut log = log.lock().unwrap();
        log.info("engine", &format!("packaging container: {}", aif_path.display()));
    }

    if let Err(e) = aif::package_aif(&staging, &aif_path) {
        fail_run(&progress, &format!("AIF packaging failed: {}", e), &started);
        return;
    }

    // ------------------------------------------------------------------
    // Container integrity: streaming SHA-256 + sidecar + custody record
    // ------------------------------------------------------------------
    {
        let mut p = progress.lock().unwrap();
        p.phase = "Computing container SHA-256".to_string();
    }
    let container_hash = match aif::hash_container(&aif_path) {
        Ok(h) => h,
        Err(e) => {
            fail_run(&progress, &format!("Container hashing failed: {}", e), &started);
            return;
        }
    };
    let container_bytes = std::fs::metadata(&aif_path).map(|m| m.len()).unwrap_or(0);

    custody.aif_sha256 = container_hash.clone();
    {
        let mut log = log.lock().unwrap();
        log.info("engine", &format!("AIF SHA-256: {}", container_hash));
    }

    // Sidecar file next to the AIF.
    let sidecar_path = destination_dir.join(format!("{}.AIF.sha256", case_file_id));
    let _ = std::fs::write(
        &sidecar_path,
        format!("{}  {}.AIF\n", container_hash, case_file_id),
    );

    // External custody record (carries the real container hash).
    let custody_path = destination_dir.join(format!("{}.custody.json", case_file_id));
    let _ = std::fs::write(
        &custody_path,
        serde_json::to_vec_pretty(&custody).unwrap_or_default(),
    );

    // External report copy including the container hash.
    let report_path = destination_dir.join(format!("{}_acquisition_report.html", case_file_id));
    let _ = std::fs::write(
        &report_path,
        reporting::html::render(&manifest, &custody, Some(&container_hash)),
    );

    // Copy the acquisition log next to the case for quick inspection.
    if let Ok(log) = log.lock() {
        let log_path = destination_dir.join(format!("{}.acquisition.log", case_file_id));
        let content = log
            .entries
            .iter()
            .map(|e| format!("[{}] [{}] [{}] {}", e.timestamp, e.level, e.module, e.message))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(log_path, content);
    }

    // ------------------------------------------------------------------
    // Outcome + cleanup
    // ------------------------------------------------------------------
    let artifact_count = manifest.artifacts.len();
    let evidence_bytes: u64 = manifest.artifacts.iter().map(|a| a.size).sum();
    let warning_count = manifest.warnings.len();

    {
        let mut p = progress.lock().unwrap();
        p.current_artifact.clear();
        p.phase = if cancelled {
            "Cancelled - partial case preserved".to_string()
        } else {
            "Completed".to_string()
        };
        p.running = false;
        p.finished_at = Some(ended.clone());
        p.outcome = Some(AcquisitionOutcome {
            status: if cancelled { "PARTIAL ACQUISITION" } else { "ACQUISITION COMPLETED" }.to_string(),
            aif_path: aif_path.clone(),
            aif_sha256: container_hash.clone(),
            sidecar_path,
            report_path,
            artifact_count,
            total_evidence_bytes: evidence_bytes,
            container_bytes,
            start_time: started,
            end_time: ended,
            warnings: warning_count,
            failed_modules: failed_module_names.clone(),
        });
    }

    let _ = std::fs::remove_dir_all(&staging);
}

fn fail_run(progress: &Arc<Mutex<AcquisitionProgress>>, message: &str, started: &str) {
    let mut p = progress.lock().unwrap();
    p.running = false;
    p.phase = "Failed".to_string();
    p.finished_at = Some(now_rfc3339());
    p.errors.push(crate::collectors::FailureRecord {
        timestamp: now_rfc3339(),
        module: "engine".to_string(),
        code: "ENGINE".to_string(),
        description: message.to_string(),
        recommended_action: "Check destination path and disk space, then retry.".to_string(),
    });
    let _ = started;
}

/// Verify an existing AIF case: container hash plus per-artifact deep check.
pub fn verify_case(
    aif_path: &Path,
    expected_hash: &str,
) -> Result<(crate::evidence::ContainerVerification, Vec<crate::evidence::ArtifactVerification>), String> {
    let container = aif::verify_container(aif_path, expected_hash)
        .map_err(|e| format!("cannot read container: {}", e))?;
    let manifest = aif::read_manifest(aif_path)
        .map_err(|e| format!("cannot read manifest: {}", e))?;
    let artifacts = aif::verify_artifacts(aif_path, &manifest)
        .map_err(|e| format!("deep verification failed: {}", e))?;
    Ok((container, artifacts))
}

/// Statuses used when rendering artifact tables.
pub fn artifact_status_label(status: &ArtifactStatus) -> &'static str {
    match status {
        ArtifactStatus::Acquired => "ACQUIRED",
        ArtifactStatus::Partial => "PARTIAL",
        ArtifactStatus::Skipped => "SKIPPED",
        ArtifactStatus::Failed => "FAILED",
    }
}
