//! Shared application state between the GUI and the acquisition engine.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::collectors::{
    AcquisitionControl, AcquisitionProgress, AcquisitionSettings, CollectorId,
};
use crate::evidence::manifest::{CaseInfo, Manifest};
use crate::evidence::{ArtifactVerification, ContainerVerification};

/// Main navigation screens.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    Dashboard,
    NewCase,
    Acquisition,
    Evidence,
    Integrity,
    CaseInfo,
    Settings,
    About,
}

/// Case creation form values.
#[derive(Clone, Debug)]
pub struct CaseForm {
    pub case_id: String,
    pub case_name: String,
    pub investigator_name: String,
    pub organization: String,
    pub evidence_description: String,
    pub acquisition_notes: String,
    pub reference_number: String,
    pub destination: String,
    pub demo_mode: bool,
}

impl Default for CaseForm {
    fn default() -> Self {
        Self {
            case_id: suggest_case_id(),
            case_name: String::new(),
            investigator_name: std::env::var("USERNAME").unwrap_or_default(),
            organization: String::new(),
            evidence_description: String::new(),
            acquisition_notes: String::new(),
            reference_number: String::new(),
            destination: std::env::var("USERPROFILE")
                .map(|p| format!("{}\\Desktop", p))
                .unwrap_or_default(),
            demo_mode: false,
        }
    }
}

impl CaseForm {
    pub fn to_case_info(&self) -> CaseInfo {
        CaseInfo {
            case_id: self.case_id.trim().to_string(),
            case_name: self.case_name.trim().to_string(),
            investigator_name: self.investigator_name.trim().to_string(),
            organization: self.organization.trim().to_string(),
            evidence_description: self.evidence_description.trim().to_string(),
            acquisition_notes: self.acquisition_notes.trim().to_string(),
            reference_number: if self.reference_number.trim().is_empty() {
                None
            } else {
                Some(self.reference_number.trim().to_string())
            },
            destination: self.destination.trim().to_string(),
            demo_mode: self.demo_mode,
            created_at: chrono::Local::now().to_rfc3339(),
        }
    }
}

/// Suggest a case id like `CASE-2026-0421`.
pub fn suggest_case_id() -> String {
    let now = chrono::Local::now();
    let serial = (now.timestamp() % 10_000) as u32;
    format!("CASE-{}-{:04}", now.format("%Y"), serial)
}

/// System status snapshot for the dashboard.
#[derive(Clone, Debug)]
pub struct SystemStatus {
    pub os: String,
    pub admin: bool,
    pub cpu: String,
    pub gpu_detected: bool,
    pub ram_gb: f64,
    pub network_available: bool,
    pub storage_available: bool,
}

pub fn collect_system_status() -> SystemStatus {
    let sys = sysinfo::System::new_all();
    let cpu = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let ram_gb = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let network_available = !networks.is_empty();
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let storage_available = !disks.list().is_empty();

    SystemStatus {
        os: format!(
            "{} {}",
            sysinfo::System::name().unwrap_or_else(|| "Windows".to_string()),
            sysinfo::System::os_version().unwrap_or_default()
        ),
        admin: crate::win::privs::is_elevated(),
        cpu,
        gpu_detected: gpu_detected(),
        ram_gb,
        network_available,
        storage_available,
    }
}

/// Detect display adapters via the documented video class registry key
/// (read-only; no WMI round trip needed for a dashboard snapshot).
fn gpu_detected() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        if let Ok(class) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
            KEY_READ,
        ) {
            return class.enum_keys().count() > 0;
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Result of a VERIFY AIF run.
#[derive(Clone, Debug)]
pub struct VerifyResult {
    pub path: PathBuf,
    pub container: ContainerVerification,
    pub artifacts: Vec<ArtifactVerification>,
}

impl VerifyResult {
    pub fn artifacts_ok(&self) -> bool {
        self.artifacts.iter().all(|a| a.verified)
    }
}

/// Central application state shared by all screens.
pub struct AppState {
    pub screen: Screen,
    pub status: SystemStatus,
    pub form: CaseForm,
    pub selected: BTreeSet<CollectorId>,
    pub settings: AcquisitionSettings,
    pub progress: Arc<Mutex<AcquisitionProgress>>,
    pub control: Arc<AcquisitionControl>,
    /// Manifest of the most recently created case (for Evidence/Case Info).
    pub last_manifest: Option<Manifest>,
    /// Path of the most recently created AIF container.
    pub last_aif: Option<PathBuf>,
    pub verify_path: String,
    pub verify_expected: String,
    pub verify_result: Option<VerifyResult>,
    pub verify_error: Option<String>,
    pub banner: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            screen: Screen::Dashboard,
            status: collect_system_status(),
            form: CaseForm::default(),
            selected: CollectorId::recommended().into_iter().collect(),
            settings: AcquisitionSettings::default(),
            progress: Arc::new(Mutex::new(AcquisitionProgress::new())),
            control: Arc::new(AcquisitionControl::new()),
            last_manifest: None,
            last_aif: None,
            verify_path: String::new(),
            verify_expected: String::new(),
            verify_result: None,
            verify_error: None,
            banner: None,
        }
    }

    pub fn acquisition_running(&self) -> bool {
        self.progress.lock().unwrap().running
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a byte count for display.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

/// Format seconds as HH:MM:SS.
pub fn format_duration(seconds: u64) -> String {
    format!("{:02}:{:02}:{:02}", seconds / 3600, (seconds % 3600) / 60, seconds % 60)
}

/// Open a folder (or reveal a file) in Windows Explorer.
pub fn reveal_path(path: &std::path::Path) {
    #[cfg(windows)]
    {
        if path.is_file() {
            let _ = std::process::Command::new("explorer.exe")
                .arg(format!("/select,{}", path.display()))
                .spawn();
        } else {
            let _ = std::process::Command::new("explorer.exe")
                .arg(path)
                .spawn();
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}

/// Open a file with its default application (used for reports).
pub fn open_file(path: &std::path::Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd.exe")
            .args(["/C", "start", "", &path.display().to_string()])
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}
