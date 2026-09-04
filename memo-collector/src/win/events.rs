//! Windows Event Log access via documented built-in mechanisms
//! (`Get-WinEvent` for structured records, `wevtutil` for raw XML).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::powershell::{as_array, run_capture, run_powershell_json};

/// A Windows Event Log channel targeted by the collector.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct EventChannel {
    pub name: &'static str,
    /// Folder inside the AIF container (`system`, `application`, ...).
    pub folder: &'static str,
    /// Requires administrator privileges in most configurations.
    pub typically_requires_admin: bool,
}

/// Channels acquired by default. Sysmon is included but gracefully skipped
/// when it is not installed - it must never be assumed to exist.
pub const CHANNELS: &[EventChannel] = &[
    EventChannel { name: "System", folder: "system", typically_requires_admin: false },
    EventChannel { name: "Application", folder: "application", typically_requires_admin: false },
    EventChannel { name: "Security", folder: "security", typically_requires_admin: true },
    EventChannel {
        name: "Microsoft-Windows-PowerShell/Operational",
        folder: "other/powershell",
        typically_requires_admin: false,
    },
    EventChannel {
        name: "Microsoft-Windows-Windows Defender/Operational",
        folder: "other/defender",
        typically_requires_admin: false,
    },
    EventChannel {
        name: "Microsoft-Windows-TaskScheduler/Operational",
        folder: "other/taskscheduler",
        typically_requires_admin: false,
    },
    EventChannel {
        name: "Microsoft-Windows-WMI-Activity/Operational",
        folder: "other/wmi",
        typically_requires_admin: false,
    },
    EventChannel {
        name: "Microsoft-Windows-Sysmon/Operational",
        folder: "other/sysmon",
        typically_requires_admin: false,
    },
];

/// Check whether a channel exists on this system (`wevtutil gli`).
pub fn channel_exists(name: &str) -> bool {
    run_capture("wevtutil.exe", &["gli", name], Duration::from_secs(15)).is_ok()
}

/// Query structured event records from a channel as JSON.
/// Message text is truncated to keep evidence size bounded.
pub fn query_events_json(channel: &str, max_events: usize) -> Result<Vec<serde_json::Value>, String> {
    let script = format!(
        "$events = Get-WinEvent -LogName '{channel}' -MaxEvents {max} -ErrorAction Stop; \
         $events | Select-Object \
             @{{n='TimeCreated';e={{ $_.TimeCreated.ToString('o') }}}}, \
             @{{n='EventId';e={{ $_.Id }}}}, \
             @{{n='Provider';e={{ $_.ProviderName }}}}, \
             @{{n='Level';e={{ $_.LevelDisplayName }}}}, \
             @{{n='RecordId';e={{ $_.RecordId }}}}, \
             @{{n='Message';e={{ if ($_.Message) {{ $_.Message.Substring(0,[Math]::Min(1000,$_.Message.Length)) }} else {{ $null }} }}}} \
         | ConvertTo-Json -Depth 3 -Compress",
        channel = channel.replace('\'', "''"),
        max = max_events,
    );
    let value = run_powershell_json(&script, Duration::from_secs(120))?;
    Ok(as_array(value))
}

/// Export raw event XML (`wevtutil qe ... /f:xml`) preserving original
/// event representation, not only simplified text.
pub fn query_events_xml(channel: &str, max_events: usize) -> Result<String, String> {
    run_capture(
        "wevtutil.exe",
        &[
            "qe",
            channel,
            &format!("/c:{}", max_events),
            "/f:xml",
        ],
        Duration::from_secs(120),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_list_is_consistent() {
        for channel in CHANNELS {
            assert!(!channel.name.is_empty());
            assert!(!channel.folder.is_empty());
        }
        // Sysmon must be present but must never be assumed installed.
        assert!(CHANNELS.iter().any(|c| c.name.contains("Sysmon")));
    }
}
