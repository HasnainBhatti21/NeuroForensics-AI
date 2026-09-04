//! Application settings persistence (spec §15, §47): theme, workspace
//! root and optional external AI endpoint, stored under %APPDATA%.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::gui::theme::ThemeMode;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default = "default_theme")]
    pub theme: ThemeMode,
    /// Where per-case analysis workspaces are created.
    #[serde(default = "default_workspace_root")]
    pub workspace_root: String,
    /// Optional external AI endpoint (spec §47). Empty = local/offline.
    #[serde(default)]
    pub ai_endpoint: String,
    /// Endpoint protocol selection (§32): "auto" (detect from URL),
    /// "openai", "alibaba" or "custom".
    #[serde(default = "default_ai_flavor")]
    pub ai_flavor: String,
    /// Recent case paths (newest first), display only.
    #[serde(default)]
    pub recent_cases: Vec<String>,
}

fn default_theme() -> ThemeMode {
    // Light (§38B Autopsy-style tokens) is the primary/default theme;
    // Dark remains available as a secondary toggle.
    ThemeMode::Light
}

fn default_ai_flavor() -> String {
    "auto".to_string()
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            workspace_root: default_workspace_root(),
            ai_endpoint: String::new(),
            ai_flavor: default_ai_flavor(),
            recent_cases: Vec::new(),
        }
    }
}

fn default_workspace_root() -> String {
    let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    format!("{base}\\NeuroForensicsAI_Workspaces")
}

fn settings_path() -> Option<PathBuf> {
    let appdata = std::env::var("APPDATA").ok()?;
    Some(PathBuf::from(appdata).join("NeuroForensicsAI").join("settings.json"))
}

impl AppSettings {
    pub fn load() -> Self {
        settings_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = settings_path().ok_or_else(|| "APPDATA not available".to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    pub fn workspace_root_path(&self) -> PathBuf {
        PathBuf::from(&self.workspace_root)
    }

    pub fn remember_case(&mut self, path: &str) {
        self.recent_cases.retain(|p| p != path);
        self.recent_cases.insert(0, path.to_string());
        self.recent_cases.truncate(8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_json() {
        let s = AppSettings {
            theme: ThemeMode::Light,
            workspace_root: "C:\\cases".into(),
            ai_endpoint: "https://example/api".into(),
            ai_flavor: "custom".into(),
            recent_cases: vec!["a.aif".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.theme, ThemeMode::Light);
        assert_eq!(back.workspace_root, "C:\\cases");
        assert_eq!(back.ai_flavor, "custom");
        // Legacy settings files without ai_flavor keep working.
        let legacy = serde_json::from_str::<AppSettings>(
            r#"{"theme":"Dark","workspace_root":"x","ai_endpoint":"","recent_cases":[]}"#,
        )
        .unwrap();
        assert_eq!(legacy.ai_flavor, "auto");
    }
}
