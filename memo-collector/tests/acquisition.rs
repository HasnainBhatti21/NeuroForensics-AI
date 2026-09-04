//! Integration tests: full demo-mode acquisition pipeline, integrity
//! verification and cancel-with-partial-case behaviour.
//!
//! These tests only exercise DEMO MODE (synthetic data) so they are safe to
//! run on any machine and never touch real evidence sources.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use memo_collector::app::engine::{self, AcquisitionParams};
use memo_collector::collectors::{
    AcquisitionControl, AcquisitionProgress, AcquisitionSettings, CollectorId,
};
use memo_collector::evidence::manifest::CaseInfo;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("memo-it-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn demo_case(case_id: &str, destination: &std::path::Path) -> CaseInfo {
    CaseInfo {
        case_id: case_id.to_string(),
        case_name: "Integration Test".into(),
        investigator_name: "cargo-test".into(),
        organization: "QA".into(),
        evidence_description: "synthetic demo".into(),
        acquisition_notes: String::new(),
        reference_number: None,
        destination: destination.display().to_string(),
        demo_mode: true,
        created_at: chrono::Local::now().to_rfc3339(),
    }
}

/// Full pipeline: demo acquisition -> AIF -> sidecar -> custody -> report,
/// followed by full integrity verification.
#[test]
fn demo_acquisition_end_to_end() {
    let dest = temp_dir("full");

    let params = AcquisitionParams {
        case: demo_case("CASE-IT-FULL", &dest),
        modules: CollectorId::all().to_vec(),
        settings: AcquisitionSettings::default(),
    };
    let progress = Arc::new(Mutex::new(AcquisitionProgress::new()));
    let control = Arc::new(AcquisitionControl::new());
    engine::run_acquisition(params, Arc::clone(&progress), control);

    let outcome = progress
        .lock()
        .unwrap()
        .outcome
        .clone()
        .expect("acquisition must produce an outcome");

    assert_eq!(outcome.status, "ACQUISITION COMPLETED");
    assert!(outcome.aif_path.exists(), "AIF container must exist");
    assert!(
        outcome.aif_path.extension().and_then(|e| e.to_str()) == Some("AIF"),
        "container must use the .AIF extension"
    );
    assert!(outcome.artifact_count > 0);

    // Sidecar carries the container hash in `hash  name` format.
    let sidecar = std::fs::read_to_string(&outcome.sidecar_path).expect("sidecar must exist");
    assert!(sidecar.starts_with(&outcome.aif_sha256));
    assert!(sidecar.contains(".AIF"));

    // External custody record and report must exist.
    let custody_path = dest.join("CASE-IT-FULL.custody.json");
    assert!(custody_path.exists(), "custody record must exist");
    assert!(outcome.report_path.exists(), "external report must exist");
    let report = std::fs::read_to_string(&outcome.report_path).unwrap();
    assert!(report.contains(&outcome.aif_sha256));
    assert!(
        report.to_lowercase().contains("no forensic conclusions")
            || report.contains("does not draw forensic conclusions")
            || report.contains("no analysis"),
        "report must state it draws no forensic conclusions"
    );

    // Manifest readable from the container; all demo artifacts are synthetic.
    let manifest = memo_collector::evidence::aif::read_manifest(&outcome.aif_path)
        .expect("manifest must be readable");
    assert_eq!(manifest.case_id, "CASE-IT-FULL");
    assert!(!manifest.artifacts.is_empty());
    assert!(manifest.artifacts.iter().all(|a| a.synthetic));

    // Deep verification: container hash + every artifact hash must verify.
    let (container, artifacts) =
        engine::verify_case(&outcome.aif_path, &outcome.aif_sha256).expect("verify_case");
    assert!(container.verified);
    assert_eq!(container.calculated, outcome.aif_sha256);
    let failed: Vec<String> = artifacts
        .iter()
        .filter(|a| !a.verified)
        .map(|a| {
            format!(
                "{}: {} expected={} calculated={}",
                a.artifact_id, a.relative_path, a.expected, a.calculated
            )
        })
        .collect();
    assert!(
        failed.is_empty(),
        "all artifact hashes must verify; failures: {:?}",
        failed
    );

    // A wrong expected hash must NOT verify.
    let (bad, _) = engine::verify_case(&outcome.aif_path, &"0".repeat(64)).expect("verify_case");
    assert!(!bad.verified);

    let _ = std::fs::remove_dir_all(&dest);
}

/// Cancelling mid-run must preserve a PARTIAL case (never abort silently).
#[test]
fn cancel_preserves_partial_case() {
    let dest = temp_dir("cancel");

    let params = AcquisitionParams {
        case: demo_case("CASE-IT-CNCL", &dest),
        modules: CollectorId::all().to_vec(),
        settings: AcquisitionSettings::default(),
    };
    let progress = Arc::new(Mutex::new(AcquisitionProgress::new()));
    let control = Arc::new(AcquisitionControl::new());

    let worker_progress = Arc::clone(&progress);
    let worker_control = Arc::clone(&control);
    let worker = std::thread::spawn(move || {
        engine::run_acquisition(params, worker_progress, worker_control);
    });

    // Let the first module start, then cancel.
    std::thread::sleep(Duration::from_millis(500));
    control
        .cancel
        .store(true, std::sync::atomic::Ordering::SeqCst);
    worker.join().expect("engine thread must finish after cancel");

    let outcome = progress
        .lock()
        .unwrap()
        .outcome
        .clone()
        .expect("a cancelled run must still produce an outcome");
    assert_eq!(
        outcome.status, "PARTIAL ACQUISITION",
        "cancelled acquisition must be preserved as a PARTIAL case"
    );

    // The preserved partial case must still be verifiable.
    if outcome.aif_path.exists() {
        let (container, _) = engine::verify_case(&outcome.aif_path, &outcome.aif_sha256)
            .expect("verify_case on partial container");
        assert!(container.verified, "partial container hash must verify");
    }

    let _ = std::fs::remove_dir_all(&dest);
}
