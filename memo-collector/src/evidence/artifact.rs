//! Artifact records: every piece of acquired evidence is described by an
//! [`ArtifactRecord`] with a unique ID, SHA-256 hash and provenance.

use serde::{Deserialize, Serialize};

/// Status of an artifact acquisition.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArtifactStatus {
    Acquired,
    Partial,
    Skipped,
    Failed,
}

/// A single acquired evidence artifact inside an AIF case.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArtifactRecord {
    /// Unique artifact identifier, e.g. `ART-000042`.
    pub artifact_id: String,
    /// Path of the artifact relative to the AIF container root.
    pub relative_path: String,
    /// Size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the artifact content.
    pub sha256: String,
    /// RFC 3339 acquisition timestamp.
    pub acquisition_time: String,
    /// Human readable data source description.
    pub source: String,
    /// Collector module id (e.g. `processes`).
    pub collector: String,
    /// Acquisition status.
    pub status: ArtifactStatus,
    /// Optional free-form note (limitations, scope, capability notes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// True only for clearly labelled synthetic demonstration data.
    #[serde(default)]
    pub synthetic: bool,
}

impl ArtifactRecord {
    pub fn new(artifact_id: String, relative_path: String) -> Self {
        Self {
            artifact_id,
            relative_path,
            size: 0,
            sha256: String::new(),
            acquisition_time: String::new(),
            source: String::new(),
            collector: String::new(),
            status: ArtifactStatus::Acquired,
            notes: None,
            synthetic: false,
        }
    }
}

/// Summary of a collector module execution.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ModuleSummary {
    pub module_id: String,
    pub module_name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub artifacts: usize,
    pub bytes: u64,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub warnings: Vec<String>,
}
