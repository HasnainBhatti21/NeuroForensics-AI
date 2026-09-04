//! Process-level evidence helpers built on documented Win32 APIs:
//! Toolhelp snapshots, PSAPI module enumeration and token queries.

use serde::{Deserialize, Serialize};

/// A loaded module (DLL/EXE) of a process, where accessible.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
}

/// Enumerate loaded modules of a process. Requires
/// `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access; returns `None`
/// when the process cannot be opened (protected / higher privilege).
pub fn process_modules(pid: u32, max_modules: usize) -> Option<Vec<ModuleInfo>> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };
            let mut modules = vec![HMODULE::default(); max_modules.min(2048)];
            let mut needed: u32 = 0;
            let ok = EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
            .is_ok();
            let mut result = Vec::new();
            if ok {
                let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
                for module in &modules[..count] {
                    let mut name_buf = [0u16; 1024];
                    let len = GetModuleFileNameExW(Some(handle), Some(*module), &mut name_buf);
                    if len > 0 {
                        let path = String::from_utf16_lossy(&name_buf[..len as usize]);
                        let name = std::path::Path::new(&path)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        result.push(ModuleInfo { name, path });
                    }
                }
            }
            let _ = CloseHandle(handle);
            Some(result)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, max_modules);
        None
    }
}

/// Count threads per process using a Toolhelp thread snapshot.
pub fn thread_counts() -> std::collections::HashMap<u32, u32> {
    let mut counts = std::collections::HashMap::new();
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
            THREADENTRY32,
        };

        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut entry = THREADENTRY32::default();
                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        *counts.entry(entry.th32OwnerProcessID).or_insert(0) += 1;
                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }
    }
    counts
}

/// Handle count of a process (requires PROCESS_QUERY_INFORMATION).
pub fn handle_count(pid: u32) -> Option<u32> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetProcessHandleCount, OpenProcess, PROCESS_QUERY_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
            let mut count = 0u32;
            let ok = GetProcessHandleCount(handle, &mut count).is_ok();
            let _ = CloseHandle(handle);
            ok.then_some(count)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

/// Integrity level label of a process token, where accessible.
pub fn integrity_level(pid: u32) -> Option<String> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
            TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
                let _ = CloseHandle(process);
                return None;
            }
            let _ = CloseHandle(process);

            let mut needed: u32 = 0;
            let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed);
            if needed == 0 {
                let _ = CloseHandle(token);
                return None;
            }
            let mut buffer = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TokenIntegrityLevel,
                Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
                needed,
                &mut needed,
            )
            .is_ok();
            let _ = CloseHandle(token);
            if !ok {
                return None;
            }

            let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            if sid.0.is_null() {
                return None;
            }
            let sub_count = GetSidSubAuthorityCount(sid);
            if sub_count.is_null() || *sub_count == 0 {
                return None;
            }
            let rid_ptr = GetSidSubAuthority(sid, (*sub_count - 1) as u32);
            if rid_ptr.is_null() {
                return None;
            }
            Some(match *rid_ptr {
                0x0000_1000 => "Low".to_string(),
                0x0000_2000 => "Medium".to_string(),
                0x0000_2100 => "Medium Plus".to_string(),
                0x0000_3000 => "High".to_string(),
                0x0000_4000 => "System".to_string(),
                other => format!("Unknown (RID 0x{:X})", other),
            })
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}
