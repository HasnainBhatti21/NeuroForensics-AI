//! Evidence manifest, case metadata and host snapshot structures.

use serde::{Deserialize, Serialize};

use super::artifact::{ArtifactRecord, ModuleSummary};
use crate::{APP_BUILD, APP_NAME, APP_VERSION};

/// Case details entered by the investigator.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CaseInfo {
    pub case_id: String,
    pub case_name: String,
    pub investigator_name: String,
    pub organization: String,
    pub evidence_description: String,
    pub acquisition_notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_number: Option<String>,
    /// Destination folder chosen by the investigator.
    pub destination: String,
    /// Clearly labelled synthetic demonstration mode.
    #[serde(default)]
    pub demo_mode: bool,
    pub created_at: String,
}

impl CaseInfo {
    pub fn is_valid(&self) -> bool {
        !self.case_id.trim().is_empty()
            && !self.case_name.trim().is_empty()
            && !self.investigator_name.trim().is_empty()
            && !self.destination.trim().is_empty()
    }
}

/// Host snapshot recorded at acquisition time.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub architecture: String,
    pub kernel_version: String,
    pub boot_time: Option<String>,
    pub username: String,
    pub domain: String,
    pub elevated: bool,
}

/// Acquisition timeline block.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AcquisitionInfo {
    pub start_time: String,
    pub end_time: String,
    pub operator: String,
    pub method: String,
    /// COMPLETED / PARTIAL / CANCELLED / FAILED
    pub status: String,
}

/// Integrity block of the manifest.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IntegrityInfo {
    pub algorithm: String,
    /// SHA-256 of every artifact is stored in `artifacts`.
    pub artifact_hashes_in_manifest: bool,
    /// SHA-256 of the final AIF container (also written to the sidecar).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aif_sha256: Option<String>,
}

impl Default for IntegrityInfo {
    fn default() -> Self {
        Self {
            algorithm: "SHA-256".to_string(),
            artifact_hashes_in_manifest: true,
            aif_sha256: None,
        }
    }
}

/// `manifest.json` - the evidence manifest at the root of every AIF case.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub case_id: String,
    pub case_name: String,
    pub collector: CollectorInfo,
    pub host: HostInfo,
    pub acquisition: AcquisitionInfo,
    pub modules: Vec<ModuleSummary>,
    pub artifacts: Vec<ArtifactRecord>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub integrity: IntegrityInfo,
}

/// Collector tool identity.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectorInfo {
    pub name: String,
    pub version: String,
    pub build: String,
    pub platform: String,
}

impl CollectorInfo {
    pub fn current() -> Self {
        Self {
            name: APP_NAME.to_string(),
            version: APP_VERSION.to_string(),
            build: APP_BUILD.to_string(),
            platform: crate::APP_PLATFORM.to_string(),
        }
    }
}

impl Manifest {
    pub fn new(case: &CaseInfo, host: HostInfo) -> Self {
        Self {
            case_id: case.case_id.clone(),
            case_name: case.case_name.clone(),
            collector: CollectorInfo::current(),
            host,
            acquisition: AcquisitionInfo {
                operator: case.investigator_name.clone(),
                method: if case.demo_mode {
                    "Synthetic demonstration mode".to_string()
                } else {
                    "Live local evidence acquisition".to_string()
                },
                ..Default::default()
            },
            modules: Vec::new(),
            artifacts: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            integrity: IntegrityInfo::default(),
        }
    }

    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.artifacts.iter().map(|a| a.size).sum()
    }
}

/// `case.json` - case metadata at the root of every AIF case.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CaseDocument {
    pub format: String,
    pub format_version: u32,
    pub case: CaseInfo,
    pub container_sha256: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let case = CaseInfo {
            case_id: "CASE-TEST-001".into(),
            case_name: "Unit Test Case".into(),
            investigator_name: "Tester".into(),
            organization: "QA".into(),
            evidence_description: "synthetic".into(),
            acquisition_notes: String::new(),
            reference_number: None,
            destination: ".".into(),
            demo_mode: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let manifest = Manifest::new(&case, HostInfo::default());
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.case_id, case.case_id);
        assert_eq!(back.integrity.algorithm, "SHA-256");
    }

    #[test]
    fn case_validation() {
        let mut case = CaseInfo::default();
        assert!(!case.is_valid());
        case.case_id = "C1".into();
        case.case_name = "N".into();
        case.investigator_name = "I".into();
        case.destination = ".".into();
        assert!(case.is_valid());
    }
}
