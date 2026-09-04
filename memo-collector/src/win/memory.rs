//! Physical memory statistics via documented Windows APIs.
//!
//! NOTE: user-mode applications cannot freely image physical RAM. This
//! module only exposes what Windows documents. Full physical memory
//! acquisition requires a dedicated, signed acquisition driver and is
//! reported as unavailable when no supported mechanism exists.

use serde::{Deserialize, Serialize};

/// Snapshot of `GlobalMemoryStatusEx`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MemoryStatus {
    pub memory_load_percent: u32,
    pub total_physical_bytes: u64,
    pub available_physical_bytes: u64,
    pub total_pagefile_bytes: u64,
    pub available_pagefile_bytes: u64,
    pub total_virtual_bytes: u64,
    pub available_virtual_bytes: u64,
}

/// Query global memory statistics. Returns `None` when the API is
/// unavailable (non-Windows platform or API failure).
pub fn memory_status() -> Option<MemoryStatus> {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

        unsafe {
            let mut status = MEMORYSTATUSEX::default();
            status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut status).is_ok() {
                return Some(MemoryStatus {
                    memory_load_percent: status.dwMemoryLoad,
                    total_physical_bytes: status.ullTotalPhys,
                    available_physical_bytes: status.ullAvailPhys,
                    total_pagefile_bytes: status.ullTotalPageFile,
                    available_pagefile_bytes: status.ullAvailPageFile,
                    total_virtual_bytes: status.ullTotalVirtual,
                    available_virtual_bytes: status.ullAvailVirtual,
                });
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Region protection flags in a form suitable for evidence metadata.
pub fn protection_to_string(protect: u32) -> String {
    // Common PAGE_* constants (documented Win32 memory protection values).
    let base = match protect & 0xFF {
        0x01 => "PAGE_NOACCESS",
        0x02 => "PAGE_READONLY",
        0x04 => "PAGE_READWRITE",
        0x08 => "PAGE_WRITECOPY",
        0x10 => "PAGE_EXECUTE",
        0x20 => "PAGE_EXECUTE_READ",
        0x40 => "PAGE_EXECUTE_READWRITE",
        0x80 => "PAGE_EXECUTE_WRITECOPY",
        other if other != 0 => return format!("0x{:08X}", protect),
        _ => "PAGE_UNKNOWN",
    };
    let mut extra = Vec::new();
    if protect & 0x100 != 0 {
        extra.push("GUARD");
    }
    if protect & 0x200 != 0 {
        extra.push("NOCACHE");
    }
    if protect & 0x400 != 0 {
        extra.push("WRITECOMBINE");
    }
    if extra.is_empty() {
        base.to_string()
    } else {
        format!("{} | {}", base, extra.join(" | "))
    }
}

/// Region state constants (MEM_COMMIT / MEM_FREE / MEM_RESERVE).
pub fn state_to_string(state: u32) -> &'static str {
    match state {
        0x1000 => "MEM_COMMIT",
        0x2000 => "MEM_RESERVE",
        0x10000 => "MEM_FREE",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_flags_describe() {
        assert_eq!(protection_to_string(0x04), "PAGE_READWRITE");
        assert_eq!(protection_to_string(0x20), "PAGE_EXECUTE_READ");
        assert!(protection_to_string(0x104).contains("GUARD"));
    }

    #[test]
    fn state_flags_describe() {
        assert_eq!(state_to_string(0x1000), "MEM_COMMIT");
        assert_eq!(state_to_string(0x10000), "MEM_FREE");
    }
}
