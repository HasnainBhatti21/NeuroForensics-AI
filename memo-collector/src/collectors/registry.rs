//! RegistryCollector - targeted forensic registry metadata.
//!
//! The collector acquires specific forensic artifacts instead of blindly
//! dumping whole hives, and records the exact acquisition scope. Raw SAM
//! parsing is not claimed: SAM is only accessible through raw hive access,
//! which this build does not perform.

use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};

#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

#[derive(Default)]
pub struct RegistryCollector {}

impl ICollector for RegistryCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Registry
    }

    fn name(&self) -> &'static str {
        "Registry / System Artifacts"
    }

    fn check_availability(&self) -> Availability {
        if cfg!(windows) {
            Availability::Available
        } else {
            Availability::NotAvailable {
                reason: "Windows registry requires Windows".to_string(),
            }
        }
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        ctx.check_cancel()?;
        let identity = collect_system_identity();
        ctx.add_json(
            "registry/artifacts/system_identity.json",
            "SYSTEM hive: ComputerName / TimeZoneInformation (read-only)",
            Some("scope: HKLM\\SYSTEM\\CurrentControlSet\\Control".to_string()),
            &identity,
        )?;

        ctx.check_cancel()?;
        let software = collect_installed_software();
        ctx.add_json(
            "registry/artifacts/installed_software.json",
            "Uninstall keys (read-only)",
            Some("scope: HKLM/HKCU ...\\CurrentVersion\\Uninstall".to_string()),
            &software,
        )?;

        ctx.check_cancel()?;
        let usb = collect_usb_history(ctx);
        ctx.add_json(
            "registry/artifacts/usb_history.json",
            "SYSTEM hive USBSTOR enumeration (read-only)",
            Some("requires administrator privileges on most systems".to_string()),
            &usb,
        )?;

        ctx.check_cancel()?;
        let networks = collect_network_profiles(ctx);
        ctx.add_json(
            "registry/artifacts/network_profiles.json",
            "SOFTWARE NetworkList profiles (read-only)",
            Some("requires administrator privileges on most systems".to_string()),
            &networks,
        )?;

        ctx.check_cancel()?;
        ctx.add_json(
            "registry/artifacts/sam_note.json",
            "collector capability note",
            None,
            &json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "status": "NOT AVAILABLE",
                "note": "SAM account data requires raw hive acquisition (e.g. SYSTEM/SAM files) or privileged APIs not used by this build. No SAM data is claimed or fabricated.",
            }),
        )?;

        Ok(())
    }
}

#[cfg(windows)]
fn read_subkey_values(root: winreg::HKEY, subkey: &str) -> Vec<serde_json::Value> {
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

fn collect_system_identity() -> serde_json::Value {
    #[cfg(windows)]
    {
        json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "computer_name": read_subkey_values(
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
            ),
            "time_zone_information": read_subkey_values(
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
            ),
            "windows_version": read_subkey_values(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            ).into_iter().take(40).collect::<Vec<_>>(),
        })
    }
    #[cfg(not(windows))]
    {
        json!({"status": "NOT AVAILABLE"})
    }
}

fn collect_installed_software() -> serde_json::Value {
    #[cfg(windows)]
    {
        let mut products = Vec::new();
        let scopes: &[(winreg::HKEY, &str)] = &[
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ];
        for (root, path) in scopes {
            if let Ok(uninstall) = RegKey::predef(*root).open_subkey_with_flags(path, KEY_READ) {
                for sub in uninstall.enum_keys() {
                    let Ok(name) = sub else { continue };
                    let Ok(key) = uninstall.open_subkey_with_flags(&name, KEY_READ) else {
                        continue;
                    };
                    let display: std::io::Result<String> = key.get_value("DisplayName");
                    let Ok(display) = display else { continue };
                    let version: std::io::Result<String> = key.get_value("DisplayVersion");
                    let publisher: std::io::Result<String> = key.get_value("Publisher");
                    let install_date: std::io::Result<String> = key.get_value("InstallDate");
                    let install_location: std::io::Result<String> =
                        key.get_value("InstallLocation");
                    products.push(json!({
                        "display_name": display,
                        "version": version.ok(),
                        "publisher": publisher.ok(),
                        "install_date": install_date.ok(),
                        "install_location": install_location.ok(),
                        "registry_key": name,
                    }));
                }
            }
        }
        json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "product_count": products.len(),
            "products": products,
        })
    }
    #[cfg(not(windows))]
    {
        json!({"status": "NOT AVAILABLE"})
    }
}

fn collect_usb_history(ctx: &mut CollectContext) -> serde_json::Value {
    #[cfg(windows)]
    {
        let mut devices = Vec::new();
        match RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Enum\USBSTOR", KEY_READ)
        {
            Ok(stor) => {
                for device_class in stor.enum_keys() {
                    let Ok(class) = device_class else { continue };
                    let Ok(class_key) = stor.open_subkey_with_flags(&class, KEY_READ) else {
                        continue;
                    };
                    for instance in class_key.enum_keys() {
                        let Ok(serial) = instance else { continue };
                        devices.push(json!({
                            "device_class": class,
                            "serial": serial,
                        }));
                    }
                }
                json!({
                    "acquired_at": chrono::Local::now().to_rfc3339(),
                    "status": "ACQUIRED",
                    "device_count": devices.len(),
                    "devices": devices,
                })
            }
            Err(e) => {
                ctx.warn(format!("USBSTOR not readable (likely insufficient privileges): {}", e));
                json!({
                    "acquired_at": chrono::Local::now().to_rfc3339(),
                    "status": "NOT AVAILABLE",
                    "reason": format!("{}", e),
                    "action": "re-run elevated to acquire USB device history",
                })
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        json!({"status": "NOT AVAILABLE"})
    }
}

fn collect_network_profiles(ctx: &mut CollectContext) -> serde_json::Value {
    #[cfg(windows)]
    {
        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
            KEY_READ,
        ) {
            Ok(profiles) => {
                let mut entries = Vec::new();
                for guid in profiles.enum_keys() {
                    let Ok(guid) = guid else { continue };
                    let Ok(key) = profiles.open_subkey_with_flags(&guid, KEY_READ) else {
                        continue;
                    };
                    let name: std::io::Result<String> = key.get_value("ProfileName");
                    let category: std::io::Result<u32> = key.get_value("Category");
                    entries.push(json!({
                        "guid": guid,
                        "profile_name": name.ok(),
                        "category": category.ok(),
                    }));
                }
                json!({
                    "acquired_at": chrono::Local::now().to_rfc3339(),
                    "status": "ACQUIRED",
                    "profiles": entries,
                })
            }
            Err(e) => {
                ctx.warn(format!("NetworkList profiles not readable: {}", e));
                json!({
                    "acquired_at": chrono::Local::now().to_rfc3339(),
                    "status": "NOT AVAILABLE",
                    "reason": format!("{}", e),
                })
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        json!({"status": "NOT AVAILABLE"})
    }
}
