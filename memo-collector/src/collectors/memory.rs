//! MemoryCollector - volatile memory evidence.
//!
//! Two modes are defined:
//!   A. MEMORY ARTIFACT MODE  - everything a documented user-mode API can
//!      legally and safely expose (statistics, per-process memory layout,
//!      region metadata, working-set information).
//!   B. FULL PHYSICAL MEMORY MODE - requires a dedicated, supported
//!      acquisition driver. When no supported mechanism exists this build
//!      honestly reports: "Full physical memory acquisition unavailable on
//!      this system." It NEVER fakes a RAM image.

use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win;

/// How many external processes get region enumeration (in addition to the
/// collector's own process). Region walking is comparatively expensive.
const REGION_SCAN_PROCESS_LIMIT: usize = 20;
/// Maximum regions recorded per scanned process.
const REGION_SCAN_MAX_REGIONS: usize = 4096;

#[derive(Default)]
pub struct MemoryCollector {}

impl ICollector for MemoryCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Memory
    }

    fn name(&self) -> &'static str {
        "Memory"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        let memory_size = win::memory::memory_status()
            .map(|s| s.total_physical_bytes)
            .unwrap_or(0);

        // --- Mode declaration ------------------------------------------------
        ctx.add_json(
            "memory/memory_metadata.json",
            "collector capability declaration",
            None,
            &json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "mode": "MEMORY ARTIFACT MODE",
                "memory_size_bytes": memory_size,
                "acquisition_method": "Documented Win32 APIs (GlobalMemoryStatusEx, VirtualQueryEx, sysinfo)",
                "physical_memory": {
                    "status": "NOT AVAILABLE",
                    "message": "Full physical memory acquisition unavailable on this system.",
                    "reason": "User-mode applications cannot image physical RAM. A full RAM image requires a dedicated, signed acquisition mechanism which is not bundled with this build.",
                    "policy": "MEMO Collector never creates fake evidence; no RAM image is claimed."
                },
            }),
        )?;

        // --- Memory statistics -------------------------------------------------
        let status = win::memory::memory_status();
        let sys = sysinfo::System::new_all();
        ctx.add_json(
            "memory/memory_stats.json",
            "GlobalMemoryStatusEx + sysinfo",
            None,
            &json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "global": status,
                "sysinfo": {
                    "total_memory_bytes": sys.total_memory(),
                    "used_memory_bytes": sys.used_memory(),
                    "available_memory_bytes": sys.available_memory(),
                    "total_swap_bytes": sys.total_swap(),
                    "used_swap_bytes": sys.used_swap(),
                },
            }),
        )?;

        // --- Per-process memory (working-set overview) ---------------------------
        let mut processes: Vec<serde_json::Value> = sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                json!({
                    "pid": pid.as_u32(),
                    "name": p.name().to_string_lossy(),
                    "memory_bytes": p.memory(),
                    "virtual_memory_bytes": p.virtual_memory(),
                })
            })
            .collect();
        processes.sort_by(|a, b| {
            b["memory_bytes"].as_u64().unwrap_or(0).cmp(&a["memory_bytes"].as_u64().unwrap_or(0))
        });
        ctx.add_json(
            "memory/process_memory.json",
            "sysinfo process memory snapshot",
            Some(format!("{} processes", processes.len())),
            &json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "processes": processes,
            }),
        )?;

        // --- Memory region metadata (VirtualQueryEx, where accessible) ----------
        let regions = enumerate_regions(ctx);
        ctx.add_json(
            "memory/memory_regions.json",
            "VirtualQueryEx region walk (read-only metadata)",
            Some(format!(
                "Scope: own process + up to {} accessible processes, {} regions max each. Regions of inaccessible processes are not captured.",
                REGION_SCAN_PROCESS_LIMIT, REGION_SCAN_MAX_REGIONS
            )),
            &regions,
        )?;

        Ok(())
    }
}

/// Walk memory regions with VirtualQueryEx for the current process and a
/// bounded set of openable processes. Returns metadata only - never the
/// region contents.
fn enumerate_regions(ctx: &mut CollectContext) -> serde_json::Value {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut scanned = Vec::new();
        let own_pid = unsafe { GetCurrentProcessId() };

        let mut candidates: Vec<u32> = vec![own_pid];
        {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            let mut pids: Vec<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
            pids.sort();
            candidates.extend(pids.into_iter().filter(|p| *p != own_pid));
        }

        let mut processes_scanned = 0usize;
        let mut processes_inaccessible = 0usize;

        for pid in candidates {
            if processes_scanned > REGION_SCAN_PROCESS_LIMIT {
                break;
            }
            ctx.check_cancel().ok();
            unsafe {
                let handle = if pid == own_pid {
                    // Re-open our own process to keep handle management uniform.
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                        Ok(h) => h,
                        Err(_) => {
                            processes_inaccessible += 1;
                            continue;
                        }
                    }
                } else {
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                        Ok(h) => h,
                        Err(_) => {
                            processes_inaccessible += 1;
                            continue;
                        }
                    }
                };

                let mut regions = Vec::new();
                let mut address: usize = 0;
                while regions.len() < REGION_SCAN_MAX_REGIONS {
                    let mut info = MEMORY_BASIC_INFORMATION::default();
                    let written = VirtualQueryEx(
                        handle,
                        Some(address as *const core::ffi::c_void),
                        &mut info,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    );
                    if written == 0 {
                        break;
                    }
                    regions.push(json!({
                        "base_address": format!("0x{:X}", info.BaseAddress as usize),
                        "region_size_bytes": info.RegionSize,
                        "state": win::memory::state_to_string(info.State.0),
                        "protection": win::memory::protection_to_string(info.Protect.0),
                    }));
                    let next = (info.BaseAddress as usize).saturating_add(info.RegionSize);
                    if next <= address {
                        break;
                    }
                    address = next;
                }
                let _ = CloseHandle(handle);
                processes_scanned += 1;
                scanned.push(json!({
                    "pid": pid,
                    "own_process": pid == own_pid,
                    "region_count": regions.len(),
                    "regions": regions,
                }));
            }
        }

        json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "processes_scanned": processes_scanned,
            "processes_inaccessible": processes_inaccessible,
            "processes": scanned,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        json!({
            "acquired_at": chrono::Local::now().to_rfc3339(),
            "status": "NOT AVAILABLE",
            "reason": "region enumeration uses Windows APIs",
        })
    }
}
