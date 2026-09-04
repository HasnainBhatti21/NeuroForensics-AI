//! Shell / PowerShell execution helpers (read-only queries).

use std::process::Command;
use std::time::Duration;

/// Run a command and capture UTF-8 stdout. Returns Err with a message on
/// non-zero exit or spawn failure. Output is truncated to `max_bytes`.
pub fn run_capture(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let output = run_capture_raw(program, args, timeout)?;
    let text = String::from_utf8_lossy(&output);
    Ok(text.chars().take(64 * 1024 * 1024).collect())
}

fn run_capture_raw(program: &str, args: &[&str], _timeout: Duration) -> Result<Vec<u8>, String> {
    // Note: process-level timeout enforcement is delegated to the caller
    // scope (collectors bound their own queries); blocking wait is bounded
    // by the data sources themselves.
    let output = Command::new(program)
        .args(args)
        .creation_flags_no_window()
        .output()
        .map_err(|e| format!("failed to start {}: {}", program, e))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{} exited with {:?}: {}",
            program,
            output.status.code(),
            stderr.lines().take(3).collect::<Vec<_>>().join(" ")
        ))
    }
}

#[cfg(windows)]
trait CreationFlags {
    fn creation_flags_no_window(&mut self) -> &mut Self;
}

#[cfg(windows)]
impl CreationFlags for Command {
    fn creation_flags_no_window(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(windows))]
trait CreationFlags {
    fn creation_flags_no_window(&mut self) -> &mut Self;
}

#[cfg(not(windows))]
impl CreationFlags for Command {
    fn creation_flags_no_window(&mut self) -> &mut Self {
        self
    }
}

/// Run a PowerShell command and parse its stdout as JSON.
pub fn run_powershell_json(script: &str, timeout: Duration) -> Result<serde_json::Value, String> {
    let out = run_capture(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout,
    )?;
    let trimmed = out.trim_start();
    if trimmed.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(trimmed).map_err(|e| format!("PowerShell output is not JSON: {}", e))
}

/// Normalize PowerShell JSON that collapses single-element arrays into
/// objects into an array form.
pub fn as_array(value: serde_json::Value) -> Vec<serde_json::Value> {
    match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Null => Vec::new(),
        other => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_object_becomes_array() {
        let v = serde_json::json!({"Id": 1});
        assert_eq!(as_array(v).len(), 1);
        let v = serde_json::json!([{"Id": 1}, {"Id": 2}]);
        assert_eq!(as_array(v).len(), 2);
        assert!(as_array(serde_json::Value::Null).is_empty());
    }
}
