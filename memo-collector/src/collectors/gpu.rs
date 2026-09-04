//! GPUCollector - GPU is a primary feature of MEMO Collector.
//!
//! Collects every accessible GPU metadata source. Raw VRAM contents are NOT
//! invented: when Windows exposes no supported VRAM acquisition path the
//! collector records "VRAM raw acquisition unavailable."

use serde::Deserialize;
use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_VideoController")]
#[allow(dead_code)]
struct Win32VideoController {
    #[serde(default, rename = "Name")]
    name: Option<String>,
    #[serde(default, rename = "Description")]
    description: Option<String>,
    #[serde(default, rename = "AdapterRAM")]
    adapter_ram: Option<u32>,
    #[serde(default, rename = "DriverVersion")]
    driver_version: Option<String>,
    #[serde(default, rename = "DriverDate")]
    driver_date: Option<String>,
    #[serde(default, rename = "InstalledDisplayDrivers")]
    installed_display_drivers: Option<String>,
    #[serde(default, rename = "VideoProcessor")]
    video_processor: Option<String>,
    #[serde(default, rename = "VideoModeDescription")]
    video_mode_description: Option<String>,
    #[serde(default, rename = "VideoArch")]
    video_arch: Option<u16>,
    #[serde(default, rename = "PNPDeviceID")]
    pnp_device_id: Option<String>,
    #[serde(default, rename = "DeviceID")]
    device_id: Option<String>,
    #[serde(default, rename = "Status")]
    status: Option<String>,
    #[serde(default, rename = "Availability")]
    availability: Option<u16>,
    #[serde(default, rename = "CurrentHorizontalResolution")]
    current_horizontal_resolution: Option<u32>,
    #[serde(default, rename = "CurrentVerticalResolution")]
    current_vertical_resolution: Option<u32>,
    #[serde(default, rename = "CurrentRefreshRate")]
    current_refresh_rate: Option<u32>,
}

#[derive(Default)]
pub struct GpuCollector {
    gpu_count: usize,
}

impl ICollector for GpuCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Gpu
    }

    fn name(&self) -> &'static str {
        "GPU"
    }

    fn check_availability(&self) -> Availability {
        // The module itself always runs: even without a GPU it records the
        // negative result. Only WMI failure degrades it.
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        // --- Adapter metadata (WMI Win32_VideoController) -------------------
        let mut adapters: Vec<Win32VideoController> = Vec::new();
        #[cfg(windows)]
        {
            match wmi::COMLibrary::new()
                .map_err(|e| e.to_string())
                .and_then(|com| wmi::WMIConnection::new(com).map_err(|e| e.to_string()))
            {
                Ok(wmi) => match wmi.query::<Win32VideoController>() {
                    Ok(rows) => adapters = rows,
                    Err(e) => {
                        ctx.warn(format!("Win32_VideoController query failed: {}", e));
                    }
                },
                Err(e) => {
                    ctx.warn(format!("WMI unavailable, GPU adapter metadata skipped: {}", e));
                }
            }
        }
        self.gpu_count = adapters.len();

        let metadata = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "gpu_count": adapters.len(),
            "gpus": adapters.iter().map(|a| json!({
                "name": a.name,
                "description": a.description,
                // AdapterRAM is a 32-bit WMI field and saturates at ~4 GiB;
                // record it exactly as exposed without extrapolation.
                "adapter_ram_bytes_u32": a.adapter_ram,
                "adapter_ram_note": "WMI AdapterRAM is 32-bit; values saturate at ~4 GiB",
                "driver_version": a.driver_version,
                "driver_date": a.driver_date,
                "installed_display_drivers": a.installed_display_drivers,
                "video_processor": a.video_processor,
                "video_mode": a.video_mode_description,
                "pnp_device_id": a.pnp_device_id,
                "device_id": a.device_id,
                "status": a.status,
                "current_resolution": a.current_horizontal_resolution
                    .zip(a.current_vertical_resolution)
                    .map(|(w, h)| format!("{}x{}", w, h)),
                "current_refresh_rate": a.current_refresh_rate,
            })).collect::<Vec<_>>(),
            "vram_raw_acquisition": "VRAM raw acquisition unavailable.",
            "vram_note": "Direct VRAM imaging is not exposed by supported Windows APIs/drivers in this build. No VRAM contents are claimed or fabricated.",
        });
        ctx.add_json("gpu/gpu_metadata.json", "WMI Win32_VideoController", None, &metadata)?;

        // --- GPU processes --------------------------------------------------
        let gpu_processes = win::gpu::nvidia_compute_processes();
        let processes_doc = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "source_available": gpu_processes.is_some(),
            "source": gpu_processes.as_ref().map(|_| "nvidia-smi --query-compute-apps"),
            "processes": gpu_processes.clone().unwrap_or_default(),
            "note": match &gpu_processes {
                Some(_) => "Real compute processes reported by the NVIDIA driver tooling.",
                None => "GPU process enumeration unavailable: nvidia-smi not installed. Data NOT AVAILABLE - nothing was fabricated.",
            },
        });
        ctx.add_json("gpu/gpu_processes.json", "nvidia-smi (when installed)", None, &processes_doc)?;

        // --- Compute environments (CUDA / OpenCL) ----------------------------
        let compute = win::gpu::detect_compute_environments();
        let compute_doc = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "cuda": {
                "available": compute.cuda_available,
                "evidence": compute.cuda_evidence,
            },
            "opencl": {
                "available": compute.opencl_available,
                "evidence": compute.opencl_evidence,
            },
            "nvidia_smi_path": compute.nvidia_smi_path,
            "compute_capability": compute.compute_capability,
            "compute_capability_note": match &compute.compute_capability {
                Some(_) => "Reported by nvidia-smi.",
                None => "Compute capability query unavailable (requires CUDA-capable driver tooling).",
            },
            "active_compute_contexts": "NOT AVAILABLE: Windows does not expose active compute context enumeration to user mode in this build.",
        });
        ctx.add_json("gpu/compute_metadata.json", "filesystem + nvidia-smi detection", None, &compute_doc)?;

        // --- Graphics driver files (read-only presence) ----------------------
        let mut driver_files = Vec::new();
        if let Some(first) = adapters.iter().find_map(|a| a.installed_display_drivers.clone()) {
            for entry in first.split(',') {
                let path = entry.trim();
                if path.is_empty() {
                    continue;
                }
                let full = if path.contains(':') {
                    path.to_string()
                } else {
                    format!(
                        "{}\\System32\\{}",
                        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
                        path
                    )
                };
                let exists = std::path::Path::new(&full).exists();
                let size = std::fs::metadata(&full).map(|m| m.len()).ok();
                driver_files.push(json!({
                    "reported_name": path,
                    "resolved_path": full,
                    "exists": exists,
                    "size_bytes": size,
                }));
            }
        }
        ctx.add_json(
            "gpu/driver_files.json",
            "InstalledDisplayDrivers resolution",
            None,
            &driver_files,
        )?;

        if self.gpu_count == 0 {
            ctx.warn("No GPU adapters detected via WMI; GPU metadata limited.");
        }
        Ok(())
    }
}
