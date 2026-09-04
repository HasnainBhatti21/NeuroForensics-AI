//! SystemMetadataCollector - host identity, OS, firmware and platform facts.

use serde::Deserialize;
use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win;

#[derive(serde::Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_OperatingSystem")]
#[allow(dead_code)]
struct Win32OperatingSystem {
    #[serde(default, rename = "Caption")]
    caption: Option<String>,
    #[serde(default, rename = "Version")]
    version: Option<String>,
    #[serde(default, rename = "BuildNumber")]
    build_number: Option<String>,
    #[serde(default, rename = "OSArchitecture")]
    os_architecture: Option<String>,
    #[serde(default, rename = "InstallDate")]
    install_date: Option<String>,
    #[serde(default, rename = "LastBootUpTime")]
    last_boot_up_time: Option<String>,
    #[serde(default, rename = "LocalDateTime")]
    local_date_time: Option<String>,
    #[serde(default, rename = "TotalVisibleMemorySize")]
    total_visible_memory_kb: Option<u64>,
    #[serde(default, rename = "FreePhysicalMemory")]
    free_physical_memory_kb: Option<u64>,
    #[serde(default, rename = "WindowsDirectory")]
    windows_directory: Option<String>,
    #[serde(default, rename = "CountryCode")]
    country_code: Option<String>,
    #[serde(default, rename = "MUILanguages")]
    mui_languages: Option<Vec<String>>,
}

#[derive(serde::Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_ComputerSystem")]
#[allow(dead_code)]
struct Win32ComputerSystem {
    #[serde(default, rename = "Name")]
    name: Option<String>,
    #[serde(default, rename = "Domain")]
    domain: Option<String>,
    #[serde(default, rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(default, rename = "Model")]
    model: Option<String>,
    #[serde(default, rename = "SystemType")]
    system_type: Option<String>,
    #[serde(default, rename = "TotalPhysicalMemory")]
    total_physical_memory: Option<u64>,
    #[serde(default, rename = "NumberOfLogicalProcessors")]
    logical_processors: Option<u32>,
    #[serde(default, rename = "NumberOfProcessors")]
    processors: Option<u32>,
    #[serde(default, rename = "UserName")]
    user_name: Option<String>,
    #[serde(default, rename = "BootupState")]
    bootup_state: Option<String>,
}

#[derive(serde::Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_BaseBoard")]
#[allow(dead_code)]
struct Win32BaseBoard {
    #[serde(default, rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(default, rename = "Product")]
    product: Option<String>,
    #[serde(default, rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(default, rename = "Version")]
    version: Option<String>,
}

#[derive(serde::Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_BIOS")]
#[allow(dead_code)]
struct Win32Bios {
    #[serde(default, rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(default, rename = "SMBIOSBIOSVersion")]
    smbios_version: Option<String>,
    #[serde(default, rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(default, rename = "ReleaseDate")]
    release_date: Option<String>,
}

#[derive(Default)]
pub struct SystemMetadataCollector {}

impl ICollector for SystemMetadataCollector {
    fn id(&self) -> CollectorId {
        CollectorId::SystemMetadata
    }

    fn name(&self) -> &'static str {
        "System Metadata"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        let module = self.id().as_str().to_string();
        let elevated = win::privs::is_elevated();

        // --- OS snapshot ---------------------------------------------------
        let boot_time = sysinfo::System::boot_time();
        let os = json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "hostname": sysinfo::System::host_name().unwrap_or_default(),
            "os_name": sysinfo::System::name().unwrap_or_default(),
            "os_version": sysinfo::System::os_version().unwrap_or_default(),
            "kernel_version": sysinfo::System::kernel_version().unwrap_or_default(),
            "cpu_architecture": sysinfo::System::cpu_arch(),
            "boot_time_unix": boot_time,
            "boot_time_rfc3339": chrono::DateTime::from_timestamp(boot_time as i64, 0).map(|d| d.to_rfc3339()).unwrap_or_default(),
            "uptime_seconds": sysinfo::System::uptime(),
            "username": std::env::var("USERNAME").unwrap_or_default(),
            "userdomain": std::env::var("USERDOMAIN").unwrap_or_default(),
            "elevated": elevated,
        });
        ctx.add_json("system/os.json", "sysinfo + environment", None, &os)?;

        // --- WMI blocks (graceful degradation when WMI is unreachable) ----
        #[cfg(windows)]
        {
            match wmi::COMLibrary::new()
                .map_err(|e| e.to_string())
                .and_then(|com| wmi::WMIConnection::new(com).map_err(|e| e.to_string()))
            {
                Ok(wmi) => {
                    if let Ok(rows) = wmi.query::<Win32OperatingSystem>() {
                        ctx.add_json(
                            "system/wmi_operating_system.json",
                            "WMI Win32_OperatingSystem",
                            None,
                            &rows,
                        )?;
                    }
                    if let Ok(rows) = wmi.query::<Win32ComputerSystem>() {
                        ctx.add_json(
                            "system/wmi_computer_system.json",
                            "WMI Win32_ComputerSystem",
                            None,
                            &rows,
                        )?;
                    }
                    if let Ok(rows) = wmi.query::<Win32BaseBoard>() {
                        ctx.add_json(
                            "system/wmi_base_board.json",
                            "WMI Win32_BaseBoard",
                            None,
                            &rows,
                        )?;
                    }
                    if let Ok(rows) = wmi.query::<Win32Bios>() {
                        ctx.add_json(
                            "system/wmi_bios.json",
                            "WMI Win32_BIOS",
                            None,
                            &rows,
                        )?;
                    }
                }
                Err(e) => {
                    ctx.warn(format!("WMI unavailable, WMI metadata skipped: {}", e));
                }
            }
        }

        // --- Storage snapshot ----------------------------------------------
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk_info: Vec<serde_json::Value> = disks
            .list()
            .iter()
            .map(|d| {
                json!({
                    "name": d.name().to_string_lossy(),
                    "mount_point": d.mount_point().to_string_lossy(),
                    "file_system": d.file_system().to_string_lossy(),
                    "total_bytes": d.total_space(),
                    "available_bytes": d.available_space(),
                })
            })
            .collect();
        ctx.add_json("system/disks.json", "sysinfo disks", None, &disk_info)?;

        // --- Environment snapshot (case-relevant, non-sensitive) -----------
        let env = json!({
            "computername": std::env::var("COMPUTERNAME").unwrap_or_default(),
            "processor_architecture": std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default(),
            "systemroot": std::env::var("SystemRoot").unwrap_or_default(),
            "windows_build_lab": read_build_lab(),
        });
        ctx.add_json("system/environment.json", "process environment", None, &env)?;

        let _ = module;
        Ok(())
    }
}

fn read_build_lab() -> String {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
        {
            let lab: std::io::Result<String> = hklm.get_value("BuildLabEx");
            return lab.unwrap_or_default();
        }
    }
    String::new()
}
