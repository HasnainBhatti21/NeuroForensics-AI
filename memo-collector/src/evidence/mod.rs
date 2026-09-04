//! Evidence subsystem: artifacts, manifest, AIF container and custody.

pub mod aif;
pub mod artifact;
pub mod custody;
pub mod manifest;

pub use aif::{
    extract_file, hash_container, package_aif, read_manifest, verify_artifacts,
    verify_container, ArtifactVerification, ContainerVerification,
};
pub use artifact::{ArtifactRecord, ArtifactStatus, ModuleSummary};
pub use custody::{ChainOfCustody, CustodyLog, LogEntry};
pub use manifest::{
    AcquisitionInfo, CaseDocument, CaseInfo, CollectorInfo, HostInfo, IntegrityInfo, Manifest,
};
