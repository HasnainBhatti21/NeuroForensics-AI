//! PersistenceCollector - persistence-related artifacts, READ-ONLY.
//!
//! The collector never deletes, disables, quarantines, terminates or
//! modifies any persistence mechanism.

use serde_json::json;
use std::time::Duration;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win::powershell;

#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

#[derive(Default)]
pub struct PersistenceCollector {}

impl ICollector for PersistenceCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Persistence
    }

    fn name(&self) -> &'static str {
        "Persistence"
    }

    fn check_availability(&self) -> Availability {
        if cfg!(windows) {
            Availability::Available
        } else {
            Availability::NotAvailable {
                reason: "Windows persistence artifacts require Windows".to_string(),
            }
        }
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        ctx.check_cancel()?;
        let registry_runs = collect_registry_run_keys();
        ctx.add_json(
            "persistence/registry_runs.json",
            "Registry Run / RunOnce keys (read-only)",
            None,
            &registry_runs,
        )?;

        ctx.check_cancel()?;
        let startup = collect_startup_folders();
        ctx.add_json(
            "persistence/startup.json",
            "Startup folder listings (read-only)",
            None,
            &startup,
        )?;

        ctx.check_cancel()?;
        let services = collect_services(ctx);
        ctx.add_json(
            "persistence/services.json",
            "PowerShell Get-Service (read-only)",
            None,
            &services,
        )?;

        ctx.check_cancel()?;
        let tasks = collect_scheduled_tasks(ctx);
        ctx.add_json(
            "persistence/scheduled_tasks.json",
            "PowerShell Get-ScheduledTask (read-only)",
            None,
            &tasks,
        )?;

        ctx.check_cancel()?;
        let wmi_persistence = collect_wmi_persistence(ctx);
        ctx.add_json(
            "persistence/wmi_subscriptions.json",
            "WMI __EventFilter / __EventConsumer (read-only)",
            None,
            &wmi_persistence,
        )?;

        ctx.check_cancel()?;
        let logon = collect_logon_related();
        ctx.add_json(
            "persistence/logon_and_other.json",
            "Winlogon / AppInit / IFEO configuration (read-only)",
            None,
            &logon,
        )?;

        Ok(())
    }
}

/// Read a registry key's values into a JSON array (read-only).
#[cfg(windows)]
fn read_key_values(root: winreg::HKEY, subkey: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if let Ok(key) = RegKey::predef(root).open_subkey_with_flags(subkey, KEY_READ) {
        for entry in key.enum_values() {
            if let Ok((name, value)) = entry {
                out.push(json!({
                    "value_name": if name.is_empty() { "(Default)" } else { &name },
                    "data": value.to_string(),
                }));
            }
        }
    }
    out
}

#[cfg(not(windows))]
fn read_key_values(_root: (), _subkey: &str) -> Vec<serde_json::Value> {
    Vec::new()
}

fn collect_registry_run_keys() -> serde_json::Value {
    let mut blocks = Vec::new();
    #[cfg(windows)]
    {
        let targets: &[(winreg::HKEY, &str, &str, &str)] = &[
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", "HKLM"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", "HKLM"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (Wow6432Node)", "HKLM"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (Wow6432Node)", "HKLM"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", "HKCU"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", "HKCU"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policies Explorer Run", "HKLM"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policies Explorer Run", "HKCU"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Terminal Server Run", "HKLM"),
        ];
        for (root, path, label, hive) in targets {
            blocks.push(json!({
                "label": label,
                "hive": hive,
                "key_path": path,
                "values": read_key_values(*root, path),
            }));
        }
    }
    json!({
        "acquired_at": chrono::Local::now().to_rfc3339(),
        "access": "READ-ONLY",
        "keys": blocks,
    })
}

fn collect_startup_folders() -> serde_json::Value {
    let mut folders = Vec::new();
    let candidates = [
        ("All users Startup", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"),
        ("All users Startup (alt)", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
    ];
    for (label, path) in candidates {
        folders.push(list_directory(label, path));
    }
    if let Ok(profile) = std::env::var("APPDATA") {
        let path = format!(
            "{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            profile
        );
        folders.push(list_directory("Current user Startup", &path));
    }
    json!({
        "acquired_at": chrono::Local::now().to_rfc3339(),
        "access": "READ-ONLY",
        "folders": folders,
    })
}

fn list_directory(label: &str, path: &str) -> serde_json::Value {
    let mut entries = Vec::new();
    let exists = std::path::Path::new(path).is_dir();
    if exists {
        if let Ok(read) = std::fs::read_dir(path) {
            for entry in read.flatten() {
                let meta = entry.metadata().ok();
                entries.push(json!({
                    "name": entry.file_name().to_string_lossy(),
                    "size_bytes": meta.as_ref().map(|m| m.len()),
                    "modified": meta.as_ref().and_then(|m| m.modified().ok())
                        .map(|t| chrono::DateTime::<chrono::Local>::from(t).to_rfc3339()),
                }));
            }
        }
    }
    json!({
        "label": label,
        "path": path,
        "exists": exists,
        "entries": entries,
    })
}

fn collect_services(ctx: &mut CollectContext) -> serde_json::Value {
    let script = "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json -Compress";
    match powershell::run_powershell_json(script, Duration::from_secs(90)) {
        Ok(value) => json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "service_count": powershell::as_array(value.clone()).len(),
            "services": powershell::as_array(value),
        }),
        Err(e) => {
            ctx.warn(format!("Get-Service failed: {}", e));
            json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "status": "NOT AVAILABLE",
                "reason": e,
            })
        }
    }
}

fn collect_scheduled_tasks(ctx: &mut CollectContext) -> serde_json::Value {
    let script = "Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{n='Author';e={$_.Author}} | ConvertTo-Json -Compress";
    match powershell::run_powershell_json(script, Duration::from_secs(90)) {
        Ok(value) => json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "task_count": powershell::as_array(value.clone()).len(),
            "tasks": powershell::as_array(value),
        }),
        Err(e) => {
            ctx.warn(format!("Get-ScheduledTask failed: {}", e));
            json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "status": "NOT AVAILABLE",
                "reason": e,
            })
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[allow(dead_code)]
struct WmiEventFilter {
    #[serde(default, rename = "Name")]
    name: Option<String>,
    #[serde(default, rename = "Query")]
    query: Option<String>,
    #[serde(default, rename = "EventNamespace")]
    event_namespace: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[allow(dead_code)]
struct WmiEventConsumer {
    #[serde(default, rename = "Name")]
    name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[allow(dead_code)]
struct WmiFilterToConsumerBinding {
    #[serde(default, rename = "Filter")]
    filter: Option<String>,
    #[serde(default, rename = "Consumer")]
    consumer: Option<String>,
}

fn collect_wmi_persistence(ctx: &mut CollectContext) -> serde_json::Value {
    #[cfg(windows)]
    {
        match wmi::COMLibrary::new()
            .map_err(|e| e.to_string())
            .and_then(|com| wmi::WMIConnection::new(com).map_err(|e| e.to_string()))
        {
            Ok(wmi) => {
                let filters: Vec<WmiEventFilter> = wmi
                    .raw_query("SELECT Name, Query, EventNamespace FROM __EventFilter")
                    .unwrap_or_default();
                let consumers: Vec<WmiEventConsumer> = wmi
                    .raw_query("SELECT Name FROM __EventConsumer")
                    .unwrap_or_default();
                let bindings: Vec<WmiFilterToConsumerBinding> = wmi
                    .raw_query("SELECT Filter, Consumer FROM __FilterToConsumerBinding")
                    .unwrap_or_default();
                return json!({
                    "acquired_at": chrono::Local::now().to_rfc3339(),
                    "event_filters": filters,
                    "event_consumers": consumers,
                    "filter_to_consumer_bindings": bindings,
                });
            }
            Err(e) => {
                ctx.warn(format!("WMI persistence query unavailable: {}", e));
            }
        }
    }
    #[allow(unused_variables)]
    let _ = ctx;
    json!({
        "acquired_at": chrono::Local::now().to_rfc3339(),
        "status": "NOT AVAILABLE",
        "reason": "WMI connection unavailable",
    })
}

fn collect_logon_related() -> serde_json::Value {
    #[cfg(windows)]
    {
        let winlogon = read_key_values(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        );
        let windows_cv = read_key_values(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        );

        // Image File Execution Options: record subkeys that define a Debugger value.
        let mut ifeo = Vec::new();
        if let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            KEY_READ,
        ) {
            for sub in root.enum_keys() {
                if let Ok(name) = sub {
                    if let Ok(key) = root.open_subkey_with_flags(&name, KEY_READ) {
                        let debugger: std::io::Result<String> = key.get_value("Debugger");
                        if let Ok(debugger) = debugger {
                            ifeo.push(json!({ "image": name, "debugger": debugger }));
                        }
                    }
                }
            }
        }

        json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "access": "READ-ONLY",
            "winlogon_values": winlogon,
            "windows_current_version_values": windows_cv,
            "appinit_note": "AppInit_DLLs / LoadAppInit_DLLs are inside windows_current_version_values when present",
            "image_file_execution_options_debuggers": ifeo,
        })
    }
    #[cfg(not(windows))]
    {
        json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "status": "NOT AVAILABLE",
        })
    }
}
