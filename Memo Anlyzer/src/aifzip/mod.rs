//! AIF v1 reader — the Analyzer side of the MEMO Collector contract.
//!
//! * `schema`     — manifest/case/custody models (exact collector types)
//! * `container`  — detection by header, validation, streamed access
//! * `integrity`  — streaming SHA-256, sidecar discovery, deep verify

pub mod container;
pub mod integrity;
pub mod schema;

#[allow(unused_imports)] // consumed by later stages of the refactor
pub use container::{open_aif, AifOpenError, OpenedAif};
#[allow(unused_imports)]
pub use integrity::{deep_verify, hash_file, hash_stream, ArtifactCheck, ContainerCheck, SidecarInfo};
#[allow(unused_imports)]
pub use schema::{
    ArtifactRecord, ArtifactStatus, CaseDocument, CaseInfo, Custody, Manifest, ModuleSummary,
};
