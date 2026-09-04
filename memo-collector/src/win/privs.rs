//! Privilege detection and elevation.
//!
//! MEMO Collector never bypasses Windows security. If elevation is needed it
//! asks the user through the standard UAC "run as administrator" verb.

/// Returns true if the current process is running elevated (administrator).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Restart the current executable elevated through the standard UAC prompt.
/// Fails gracefully if the user declines.
pub fn restart_as_admin() -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let exe = std::env::current_exe()?;
        let exe_w = HSTRING::from(exe.to_string_lossy().as_ref());
        let verb = HSTRING::from("runas");
        unsafe {
            let result = ShellExecuteW(
                Some(HWND::default()),
                &verb,
                &exe_w,
                None,
                None,
                SW_SHOWNORMAL,
            );
            // ShellExecuteW returns > 32 on success.
            if result.0 as isize <= 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Elevation request failed (code {})", result.0 as isize),
                ));
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Elevation is only supported on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_check_does_not_panic() {
        // Result depends on the runtime environment; only assert it runs.
        let _ = is_elevated();
    }
}
