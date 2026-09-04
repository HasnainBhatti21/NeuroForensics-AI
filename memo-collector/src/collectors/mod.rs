//! Modular acquisition architecture.
//!
//! Every collector implements the common [`ICollector`] interface. Modules
//! are independent: one collector failing never terminates the acquisition.
//! If a data source is unavailable the module reports
//! `NOT AVAILABLE / SKIPPED` and the engine continues with the next module.

pub mod cpu;
pub mod demo;
pub mod event_logs;
pub mod gpu;
pub mod hashes;
pub mod memory;
pub mod network;
pub mod persistence;
pub mod processes;
pub mod registry;
pub mod system;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::evidence::artifact::{ArtifactRecord, ArtifactStatus};
use crate::evidence::custody::CustodyLog;
use crate::hashing::sha256;

/// Identifier of an acquisition module.
#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum CollectorId {
    Memory,
    Cpu,
    Gpu,
    Processes,
    Network,
    Events,
    Persistence,
    Registry,
    Hashes,
    SystemMetadata,
}

impl CollectorId {
    pub fn as_str(&self) -> &'static str {
        match self {
            CollectorId::Memory => "memory",
            CollectorId::Cpu => "cpu",
            CollectorId::Gpu => "gpu",
            CollectorId::Processes => "processes",
            CollectorId::Network => "network",
            CollectorId::Events => "events",
            CollectorId::Persistence => "persistence",
            CollectorId::Registry => "registry",
            CollectorId::Hashes => "hashes",
            CollectorId::SystemMetadata => "system",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CollectorId::Memory => "Memory",
            CollectorId::Cpu => "CPU / System",
            CollectorId::Gpu => "GPU",
            CollectorId::Processes => "Processes",
            CollectorId::Network => "Network",
            CollectorId::Events => "Windows Event Logs",
            CollectorId::Persistence => "Persistence",
            CollectorId::Registry => "Registry / System Artifacts",
            CollectorId::Hashes => "File / Artifact Hashes",
            CollectorId::SystemMetadata => "System Metadata",
        }
    }

    /// All modules in acquisition order.
    pub fn all() -> &'static [CollectorId] {
        &[
            CollectorId::SystemMetadata,
            CollectorId::Cpu,
            CollectorId::Memory,
            CollectorId::Gpu,
            CollectorId::Processes,
            CollectorId::Network,
            CollectorId::Events,
            CollectorId::Persistence,
            CollectorId::Registry,
            CollectorId::Hashes,
        ]
    }

    /// Recommended profile: everything except memory acquisition, which is
    /// the most capability-sensitive module.
    pub fn recommended() -> Vec<CollectorId> {
        Self::all()
            .iter()
            .copied()
            .filter(|id| *id != CollectorId::Memory)
            .collect()
    }
}

/// Result of the availability check.
#[derive(Clone, Debug)]
pub enum Availability {
    Available,
    NotAvailable { reason: String },
}

/// Collector failure. The engine records it and continues with the next
/// module - a single failure must never terminate the whole acquisition.
#[derive(Clone, Debug)]
pub struct CollectorError {
    pub module: String,
    pub code: String,
    pub description: String,
    pub recommended_action: String,
}

impl CollectorError {
    pub fn new(module: &str, code: &str, description: impl Into<String>) -> Self {
        Self {
            module: module.to_string(),
            code: code.to_string(),
            description: description.into(),
            recommended_action: "Module skipped; acquisition continued with remaining modules."
                .to_string(),
        }
    }

    pub fn cancelled(module: &str) -> Self {
        Self {
            module: module.to_string(),
            code: "CANCELLED".to_string(),
            description: "Acquisition cancelled by the operator.".to_string(),
            recommended_action: "Already acquired artifacts are preserved in a partial case."
                .to_string(),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.code == "CANCELLED"
    }
}

impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.module, self.code, self.description)
    }
}

impl std::error::Error for CollectorError {}

/// Common interface implemented by every acquisition module.
pub trait ICollector: Send {
    /// Stable module id (e.g. `processes`).
    fn id(&self) -> CollectorId;
    /// Human readable module name.
    fn name(&self) -> &'static str;
    /// One-time setup before the availability check.
    fn initialize(&mut self, _ctx: &mut CollectContext) -> Result<(), CollectorError> {
        Ok(())
    }
    /// Detect whether the data source is usable on this system.
    fn check_availability(&self) -> Availability;
    /// Acquire evidence into the staging directory via `ctx`.
    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError>;
    /// Release resources.
    fn cleanup(&mut self) {}
}

/// Build the concrete collector for a module id. In demo mode every module
/// is served by a clearly-labelled synthetic collector.
pub fn build_collector(id: CollectorId, demo: bool) -> Box<dyn ICollector> {
    if demo {
        return Box::new(demo::DemoCollector::new(id));
    }
    match id {
        CollectorId::Memory => Box::new(memory::MemoryCollector::default()),
        CollectorId::Cpu => Box::new(cpu::CpuCollector::default()),
        CollectorId::Gpu => Box::new(gpu::GpuCollector::default()),
        CollectorId::Processes => Box::new(processes::ProcessCollector::default()),
        CollectorId::Network => Box::new(network::NetworkCollector::default()),
        CollectorId::Events => Box::new(event_logs::EventLogCollector::default()),
        CollectorId::Persistence => Box::new(persistence::PersistenceCollector::default()),
        CollectorId::Registry => Box::new(registry::RegistryCollector::default()),
        CollectorId::Hashes => Box::new(hashes::HashCollector::default()),
        CollectorId::SystemMetadata => Box::new(system::SystemMetadataCollector::default()),
    }
}

/// Live state of one module for the GUI.
#[derive(Clone, Debug)]
pub struct ModuleProgress {
    pub id: CollectorId,
    pub name: String,
    pub state: ModuleState,
    pub artifacts: usize,
    pub bytes: u64,
    pub note: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModuleState {
    Pending,
    Running,
    Completed,
    Skipped,
    Failed,
    Cancelled,
}

impl ModuleState {
    pub fn label(&self) -> &'static str {
        match self {
            ModuleState::Pending => "PENDING",
            ModuleState::Running => "RUNNING",
            ModuleState::Completed => "COMPLETED",
            ModuleState::Skipped => "SKIPPED",
            ModuleState::Failed => "FAILED",
            ModuleState::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Clone, Debug)]
pub struct WarningRecord {
    pub timestamp: String,
    pub module: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct FailureRecord {
    pub timestamp: String,
    pub module: String,
    pub code: String,
    pub description: String,
    pub recommended_action: String,
}

/// Final result of an acquisition run, handed back to the GUI.
#[derive(Clone, Debug)]
pub struct AcquisitionOutcome {
    pub status: String, // COMPLETED / PARTIAL / CANCELLED / FAILED
    pub aif_path: PathBuf,
    pub aif_sha256: String,
    pub sidecar_path: PathBuf,
    pub report_path: PathBuf,
    pub artifact_count: usize,
    pub total_evidence_bytes: u64,
    pub container_bytes: u64,
    pub start_time: String,
    pub end_time: String,
    pub warnings: usize,
    pub failed_modules: Vec<String>,
}

/// Shared, lock-protected acquisition state polled by the GUI.
#[derive(Clone)]
pub struct AcquisitionProgress {
    pub phase: String,
    pub running: bool,
    pub paused: bool,
    pub demo_mode: bool,
    pub modules: Vec<ModuleProgress>,
    pub current_module: Option<usize>,
    pub current_artifact: String,
    pub items_collected: u64,
    pub bytes_acquired: u64,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub elapsed_seconds: u64,
    pub throughput_bytes_per_sec: u64,
    pub warnings: Vec<WarningRecord>,
    pub errors: Vec<FailureRecord>,
    pub outcome: Option<AcquisitionOutcome>,
}

impl AcquisitionProgress {
    pub fn new() -> Self {
        Self {
            phase: "Idle".to_string(),
            running: false,
            paused: false,
            demo_mode: false,
            modules: Vec::new(),
            current_module: None,
            current_artifact: String::new(),
            items_collected: 0,
            bytes_acquired: 0,
            started_at: None,
            finished_at: None,
            elapsed_seconds: 0,
            throughput_bytes_per_sec: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
            outcome: None,
        }
    }

    /// Overall fraction of completed modules (for the total progress bar).
    pub fn total_fraction(&self) -> f32 {
        if self.modules.is_empty() {
            return 0.0;
        }
        let done = self
            .modules
            .iter()
            .filter(|m| !matches!(m.state, ModuleState::Pending | ModuleState::Running))
            .count();
        done as f32 / self.modules.len() as f32
    }
}

impl Default for AcquisitionProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Cooperative control flags shared with the acquisition worker thread.
pub struct AcquisitionControl {
    pub cancel: AtomicBool,
    pub pause: AtomicBool,
}

impl AcquisitionControl {
    pub fn new() -> Self {
        Self {
            cancel: AtomicBool::new(false),
            pause: AtomicBool::new(false),
        }
    }

    pub fn wait_if_paused(&self) {
        while self.pause.load(Ordering::SeqCst) && !self.cancel.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

impl Default for AcquisitionControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Acquisition settings adjustable by the investigator.
#[derive(Clone, Debug)]
pub struct AcquisitionSettings {
    /// Maximum events acquired per event log channel.
    pub events_per_channel: usize,
    /// Maximum number of process executables to hash.
    pub max_executables_to_hash: usize,
    /// Maximum size of a single file that will be hashed.
    pub max_hash_file_bytes: u64,
}

impl Default for AcquisitionSettings {
    fn default() -> Self {
        Self {
            events_per_channel: 500,
            max_executables_to_hash: 100,
            max_hash_file_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Per-module execution context passed to collectors.
pub struct CollectContext {
    pub module: CollectorId,
    pub staging: PathBuf,
    pub demo: bool,
    pub settings: AcquisitionSettings,
    pub log: Arc<Mutex<CustodyLog>>,
    pub progress: Arc<Mutex<AcquisitionProgress>>,
    pub control: Arc<AcquisitionControl>,
    artifact_seq: Arc<AtomicU64>,
    records: Vec<ArtifactRecord>,
    module_artifacts: usize,
    module_bytes: u64,
    warnings: Vec<String>,
}

impl CollectContext {
    pub fn new(
        module: CollectorId,
        staging: PathBuf,
        demo: bool,
        settings: AcquisitionSettings,
        log: Arc<Mutex<CustodyLog>>,
        progress: Arc<Mutex<AcquisitionProgress>>,
        control: Arc<AcquisitionControl>,
        artifact_seq: Arc<AtomicU64>,
    ) -> Self {
        Self {
            module,
            staging,
            demo,
            settings,
            log,
            progress,
            control,
            artifact_seq,
            records: Vec::new(),
            module_artifacts: 0,
            module_bytes: 0,
            warnings: Vec::new(),
        }
    }

    /// Cancellation gate: collectors call this between work items.
    pub fn check_cancel(&self) -> Result<(), CollectorError> {
        if self.control.cancel.load(Ordering::SeqCst) {
            return Err(CollectorError::cancelled(self.module.as_str()));
        }
        Ok(())
    }

    /// Pause gate: blocks while the operator has paused the acquisition.
    pub fn wait_if_paused(&self) {
        self.control.wait_if_paused();
    }

    fn now(&self) -> String {
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn next_artifact_id(&self) -> String {
        let n = self.artifact_seq.fetch_add(1, Ordering::SeqCst) + 1;
        format!("ART-{:06}", n)
    }

    fn register_artifact(&mut self, record: ArtifactRecord) {
        self.module_artifacts += 1;
        self.module_bytes += record.size;
        let (module_name, _) = {
            let mut p = self.progress.lock().unwrap();
            p.items_collected += 1;
            p.bytes_acquired += record.size;
            p.current_artifact = record.relative_path.clone();
            if let Some(idx) = p.current_module {
                if let Some(m) = p.modules.get_mut(idx) {
                    m.artifacts = self.module_artifacts;
                    m.bytes = self.module_bytes;
                }
            }
            (p.modules.get(p.current_module.unwrap_or(0)).map(|m| m.name.clone()), ())
        };
        let _ = module_name;
        if let Ok(mut log) = self.log.lock() {
            log.info(
                self.module.as_str(),
                &format!(
                    "artifact {} acquired: {} ({} bytes, sha256 {})",
                    record.artifact_id, record.relative_path, record.size, record.sha256
                ),
            );
        }
        self.records.push(record.clone());
        self.progress_artifacts_push(record);
    }

    fn progress_artifacts_push(&self, record: ArtifactRecord) {
        let mut p = self.progress.lock().unwrap();
        if let Some(idx) = p.current_module {
            if let Some(m) = p.modules.get_mut(idx) {
                m.note = format!("last: {}", record.relative_path);
            }
        }
    }

    /// Serialize a value as pretty JSON into the staging directory, hash it
    /// and register it as an artifact.
    pub fn add_json<T: serde::Serialize>(
        &mut self,
        relative_path: &str,
        source: &str,
        notes: Option<String>,
        value: &T,
    ) -> Result<ArtifactRecord, CollectorError> {
        self.check_cancel()?;
        self.wait_if_paused();
        let data = serde_json::to_vec_pretty(value)
            .map_err(|e| CollectorError::new(self.module.as_str(), "SERIALIZE", e.to_string()))?;
        self.add_bytes(relative_path, source, notes, &data)
    }

    /// Register raw bytes as an artifact.
    pub fn add_bytes(
        &mut self,
        relative_path: &str,
        source: &str,
        notes: Option<String>,
        data: &[u8],
    ) -> Result<ArtifactRecord, CollectorError> {
        self.check_cancel()?;
        self.wait_if_paused();
        let full = self.staging.join(relative_path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CollectorError::new(self.module.as_str(), "STAGING_IO", e.to_string())
            })?;
        }
        std::fs::write(&full, data).map_err(|e| {
            CollectorError::new(self.module.as_str(), "STAGING_IO", e.to_string())
        })?;
        let mut record = ArtifactRecord::new(self.next_artifact_id(), relative_path.to_string());
        record.size = data.len() as u64;
        record.sha256 = sha256::hash_bytes(data);
        record.acquisition_time = self.now();
        record.source = source.to_string();
        record.collector = self.module.as_str().to_string();
        record.status = ArtifactStatus::Acquired;
        record.notes = notes;
        record.synthetic = self.demo;
        self.register_artifact(record.clone());
        Ok(record)
    }

    /// Copy an existing file into the staging directory with streaming hash.
    pub fn add_file_copy(
        &mut self,
        relative_path: &str,
        source: &str,
        notes: Option<String>,
        from: &Path,
    ) -> Result<ArtifactRecord, CollectorError> {
        self.check_cancel()?;
        self.wait_if_paused();
        let full = self.staging.join(relative_path);
        let (hash, bytes) = sha256::hash_while_copying(from, &full).map_err(|e| {
            CollectorError::new(self.module.as_str(), "STAGING_IO", e.to_string())
        })?;
        let mut record = ArtifactRecord::new(self.next_artifact_id(), relative_path.to_string());
        record.size = bytes;
        record.sha256 = hash;
        record.acquisition_time = self.now();
        record.source = source.to_string();
        record.collector = self.module.as_str().to_string();
        record.status = ArtifactStatus::Acquired;
        record.notes = notes;
        record.synthetic = self.demo;
        self.register_artifact(record.clone());
        Ok(record)
    }

    /// Record a non-fatal warning.
    pub fn warn(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.warnings.push(message.clone());
        if let Ok(mut log) = self.log.lock() {
            log.warn(self.module.as_str(), &message);
        }
        let mut p = self.progress.lock().unwrap();
        p.warnings.push(WarningRecord {
            timestamp: self.now(),
            module: self.module.as_str().to_string(),
            message,
        });
    }

    pub fn module_artifacts(&self) -> usize {
        self.module_artifacts
    }

    pub fn module_bytes(&self) -> u64 {
        self.module_bytes
    }

    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// Hand the acquired artifact records back to the engine.
    pub fn take_records(&mut self) -> Vec<ArtifactRecord> {
        std::mem::take(&mut self.records)
    }
}
