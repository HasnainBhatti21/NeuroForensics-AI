//! GPU helper detection (compute environments and NVIDIA tooling).
//!
//! All metadata here is real capability detection. If a capability cannot
//! be observed, it is recorded as unavailable - never invented.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use super::powershell::run_capture;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ComputeEnvironmentInfo {
    pub cuda_available: bool,
    pub cuda_evidence: Vec<String>,
    pub opencl_available: bool,
    pub opencl_evidence: Vec<String>,
    pub nvidia_smi_path: Option<String>,
    pub compute_capability: Option<String>,
}

/// Locate `nvidia-smi.exe` if the NVIDIA driver/tooling is installed.
pub fn find_nvidia_smi() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(r"C:\Windows\System32\nvidia-smi.exe"),
        PathBuf::from(r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Detect CUDA / OpenCL runtime presence through documented, read-only
/// filesystem checks. No GPU state is modified.
pub fn detect_compute_environments() -> ComputeEnvironmentInfo {
    let mut info = ComputeEnvironmentInfo::default();

    let cuda_dlls = [
        r"C:\Windows\System32\nvcuda.dll",
        r"C:\Program Files\NVIDIA GPU Computing Toolkit",
    ];
    for path in cuda_dlls {
        if std::path::Path::new(path).exists() {
            info.cuda_available = true;
            info.cuda_evidence.push(format!("found: {}", path));
        }
    }
    if let Some(smi) = find_nvidia_smi() {
        info.nvidia_smi_path = Some(smi.to_string_lossy().into_owned());
        info.cuda_evidence.push(format!("found: {}", smi.display()));
    }

    let opencl_dlls = [r"C:\Windows\System32\OpenCL.dll", r"C:\Windows\SysWOW64\OpenCL.dll"];
    for path in opencl_dlls {
        if std::path::Path::new(path).exists() {
            info.opencl_available = true;
            info.opencl_evidence.push(format!("found: {}", path));
        }
    }

    // Compute capability requires a CUDA runtime query; only report it when
    // nvidia-smi can actually answer.
    if info.nvidia_smi_path.is_some() {
        if let Some(smi) = &info.nvidia_smi_path {
            if let Ok(out) = run_capture(
                smi,
                &["--query-gpu=compute_cap", "--format=csv,noheader"],
                Duration::from_secs(15),
            ) {
                let first = out.lines().next().unwrap_or("").trim().to_string();
                if !first.is_empty() {
                    info.compute_capability = Some(first);
                }
            }
        }
    }

    info
}

/// GPU compute processes via `nvidia-smi` (read-only). Returns `None` when
/// the tool is not installed - this must never be faked.
pub fn nvidia_compute_processes() -> Option<Vec<serde_json::Value>> {
    let smi = find_nvidia_smi()?;
    let out = run_capture(
        &smi.to_string_lossy(),
        &[
            "--query-compute-apps=pid,process_name,used_gpu_memory",
            "--format=csv,noheader,nounits",
        ],
        Duration::from_secs(20),
    )
    .ok()?;
    let mut processes = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if fields.len() >= 3 {
            processes.push(serde_json::json!({
                "pid": fields[0].parse::<u32>().ok(),
                "process_name": fields[1],
                "used_gpu_memory_mib": fields[2].parse::<u64>().ok(),
                "source": "nvidia-smi --query-compute-apps",
            }));
        }
    }
    Some(processes)
}
