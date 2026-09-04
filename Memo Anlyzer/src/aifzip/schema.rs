//! AIF v1 data models — the exact contract implemented by MEMO
//! Collector (`memo-collector/src/evidence/*.rs`). The Analyzer is the
//! read side of this contract and must never diverge from it.
//!
//! Physical format: an AIF case is a ZIP (Deflate) archive with the
//! extension `.AIF`, containing `manifest.json`, `case.json` and
//! `custody.json` at the root plus one directory per evidence module.

use serde::Deserialize;

/// `case.json` — case metadata document at the container root.
#[derive(Clone, Debug, Deserialize)]
pub struct CaseDocument {
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub format_version: u32,
    #[serde(default)]
    pub case: CaseInfo,
    /// Always null inside the container (a container cannot contain its
    /// own hash); the real hash lives in the external sidecar/custody.
    #[serde(default)]
    pub container_sha256: Option<String>,
}

/// Case details entered by the investigator in MEMO Collector.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CaseInfo {
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub case_name: String,
    #[serde(default)]
    pub investigator_name: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub evidence_description: String,
    #[serde(default)]
    pub acquisition_notes: String,
    #[serde(default)]
    pub reference_number: Option<String>,
    #[serde(default)]
    pub destination: String,
    /// Clearly labelled synthetic demonstration mode.
    #[serde(default)]
    pub demo_mode: bool,
    #[serde(default)]
    pub created_at: String,
}

/// Acquisition status of an artifact as recorded in `manifest.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArtifactStatus {
    Acquired,
    Partial,
    Skipped,
    Failed,
}

impl ArtifactStatus {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactStatus::Acquired => "ACQUIRED",
            ArtifactStatus::Partial => "PARTIAL",
            ArtifactStatus::Skipped => "SKIPPED",
            ArtifactStatus::Failed => "FAILED",
        }
    }
}

/// One artifact record from `manifest.json` → `artifacts[]`.
#[derive(Clone, Debug, Deserialize)]
pub struct ArtifactRecord {
    /// Collector-assigned unique ID, e.g. `ART-000042`.
    pub artifact_id: String,
    /// Path of the artifact relative to the AIF container root.
    pub relative_path: String,
    #[serde(default)]
    pub size: u64,
    /// Lowercase hex SHA-256 of the artifact content.
    #[serde(default)]
    pub sha256: String,
    /// RFC 3339 acquisition timestamp.
    #[serde(default)]
    pub acquisition_time: String,
    /// Human readable data source description.
    #[serde(default)]
    pub source: String,
    /// Collector module id (e.g. `processes`).
    #[serde(default)]
    pub collector: String,
    #[serde(default = "default_status")]
    pub status: ArtifactStatus,
    #[serde(default)]
    pub notes: Option<String>,
    /// True only for clearly labelled synthetic demonstration data.
    #[serde(default)]
    pub synthetic: bool,
}

fn default_status() -> ArtifactStatus {
    ArtifactStatus::Acquired
}

/// Per-module execution summary from `manifest.json` → `modules[]`.
#[derive(Clone, Debug, Deserialize)]
pub struct ModuleSummary {
    #[serde(default)]
    pub module_id: String,
    #[serde(default)]
    pub module_name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub artifacts: usize,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CollectorInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub platform: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct HostInfo {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub os_version: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub kernel_version: String,
    #[serde(default)]
    pub boot_time: Option<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub elevated: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AcquisitionInfo {
    #[serde(default)]
    pub start_time: String,
    #[serde(default)]
    pub end_time: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub method: String,
    /// COMPLETED / COMPLETED_WITH_FAILURES / PARTIAL / CANCELLED / FAILED
    #[serde(default)]
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IntegrityInfo {
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub artifact_hashes_in_manifest: bool,
    /// Null inside the container by design (chicken-and-egg rule).
    #[serde(default)]
    pub aif_sha256: Option<String>,
}

/// `manifest.json` — the evidence manifest at the root of every AIF.
#[derive(Clone, Debug, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub case_name: String,
    #[serde(default)]
    pub collector: CollectorInfo,
    #[serde(default)]
    pub host: HostInfo,
    #[serde(default)]
    pub acquisition: AcquisitionInfo,
    #[serde(default)]
    pub modules: Vec<ModuleSummary>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactRecord>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub integrity: Option<IntegrityInfo>,
}

/// `custody.json` — chain-of-custody record inside the container.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Custody {
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub collector_version: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub start_time: String,
    #[serde(default)]
    pub end_time: String,
    #[serde(default)]
    pub modules_requested: Vec<String>,
    #[serde(default)]
    pub modules_successful: Vec<String>,
    #[serde(default)]
    pub modules_failed: Vec<String>,
    #[serde(default)]
    pub modules_skipped: Vec<String>,
    #[serde(default)]
    pub warning_count: u32,
    #[serde(default)]
    pub artifact_count: u32,
    /// Empty inside the container; the external custody copy carries it.
    #[serde(default)]
    pub aif_sha256: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub notice: String,
}
