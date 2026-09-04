//! CPUCollector - CPU / processor forensic metadata.
//!
//! Windows does not expose arbitrary CPU internal register state to
//! user-mode applications; this collector records exactly what the platform
//! exposes and says so explicitly.

use serde::Deserialize;
use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};

#[derive(serde::Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_Processor")]
#[allow(dead_code)]
struct Win32Processor {
    #[serde(default, rename = "Name")]
    name: Option<String>,
    #[serde(default, rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(default, rename = "Description")]
    description: Option<String>,
    #[serde(default, rename = "ProcessorId")]
    processor_id: Option<String>,
    #[serde(default, rename = "Architecture")]
    architecture: Option<u16>,
    #[serde(default, rename = "NumberOfCores")]
    number_of_cores: Option<u32>,
    #[serde(default, rename = "NumberOfLogicalProcessors")]
    number_of_logical_processors: Option<u32>,
    #[serde(default, rename = "MaxClockSpeed")]
    max_clock_speed_mhz: Option<u32>,
    #[serde(default, rename = "CurrentClockSpeed")]
    current_clock_speed_mhz: Option<u32>,
    #[serde(default, rename = "L2CacheSize")]
    l2_cache_kb: Option<u32>,
    #[serde(default, rename = "L3CacheSize")]
    l3_cache_kb: Option<u32>,
    #[serde(default, rename = "VirtualizationFirmwareEnabled")]
    virtualization_firmware_enabled: Option<bool>,
    #[serde(default, rename = "SecondLevelAddressTranslationExtensions")]
    second_level_address_translation: Option<bool>,
    #[serde(default, rename = "Status")]
    status: Option<String>,
}

#[derive(Default)]
pub struct CpuCollector {
    wmi_failed: bool,
}

impl ICollector for CpuCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Cpu
    }

    fn name(&self) -> &'static str {
        "CPU / System"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();

        // Per logical processor snapshot (vendor, brand, frequency, usage).
        let cpus: Vec<serde_json::Value> = sys
            .cpus()
            .iter()
            .map(|c| {
                json!({
                    "name": c.brand(),
                    "vendor": c.vendor_id(),
                    "frequency_mhz": c.frequency(),
                    "usage_percent": c.cpu_usage(),
                })
            })
            .collect();

        let snapshot = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "physical_core_count": sysinfo::System::physical_core_count(),
            "logical_processor_count": sys.cpus().len(),
            "global_usage_percent": sys.global_cpu_usage(),
            "processors": cpus,
            "capability_note": "Windows does not expose CPU internal register state to user-mode applications; register capture is NOT AVAILABLE and is not claimed.",
        });
        ctx.add_json("cpu/cpu_metadata.json", "sysinfo CPU snapshot", None, &snapshot)?;

        // Topology / relationships between logical processors and processes.
        let top = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "logical_processors": sys.cpus().len(),
            "physical_cores": sysinfo::System::physical_core_count(),
            "architecture": sysinfo::System::cpu_arch(),
        });
        ctx.add_json("cpu/topology.json", "sysinfo topology", None, &top)?;

        // WMI processor metadata (richer identity details).
        #[cfg(windows)]
        {
            match wmi::COMLibrary::new()
                .map_err(|e| e.to_string())
                .and_then(|com| wmi::WMIConnection::new(com).map_err(|e| e.to_string()))
            {
                Ok(wmi) => match wmi.query::<Win32Processor>() {
                    Ok(rows) => {
                        ctx.add_json(
                            "cpu/wmi_processors.json",
                            "WMI Win32_Processor",
                            None,
                            &rows,
                        )?;
                    }
                    Err(e) => {
                        self.wmi_failed = true;
                        ctx.warn(format!("Win32_Processor query failed: {}", e));
                    }
                },
                Err(e) => {
                    self.wmi_failed = true;
                    ctx.warn(format!("WMI unavailable for CPU metadata: {}", e));
                }
            }
        }

        Ok(())
    }
}
