//! Shared workstation state — the single struct threaded through every
//! screen. All forensic data in here comes from the case database or an
//! ingested AIF image; nothing is synthesized.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use crate::analysis::assistant::AssistantAnswer;
use crate::analysis::AnalysisReport;
use crate::appsettings::AppSettings;
use crate::casemgmt::db::{CaseDatabase, CaseMeta};
use crate::casemgmt::{CaseFolder, CaseSummary, NewCaseForm};
use crate::ingest::index::FieldEntry;
use crate::ingest::{ExaminedCase, ValidationFailure, ValidationReport};

use super::theme::ThemeMode;
use super::timeline::TimelineEntry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Landing,
    Workstation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainView {
    Explorer,
    Timeline,
    Correlations,
    Network,
    Findings,
    Evidence,
}

impl MainView {
    pub fn label(self) -> &'static str {
        match self {
            MainView::Explorer => "Explorer",
            MainView::Timeline => "Timeline",
            MainView::Correlations => "Correlations",
            MainView::Network => "Network",
            MainView::Findings => "Findings",
            MainView::Evidence => "Evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewerTab {
    Parsed,
    Hex,
    Strings,
    Metadata,
    Ai,
}

impl ViewerTab {
    pub const ALL: [ViewerTab; 5] = [
        ViewerTab::Parsed,
        ViewerTab::Hex,
        ViewerTab::Strings,
        ViewerTab::Metadata,
        ViewerTab::Ai,
    ];
    pub fn label(self) -> &'static str {
        match self {
            ViewerTab::Parsed => "Parsed View",
            ViewerTab::Hex => "Raw / Hex",
            ViewerTab::Strings => "Strings",
            ViewerTab::Metadata => "File Metadata",
            ViewerTab::Ai => "AI Analysis",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LandingTab {
    Create,
    Open,
    Recent,
}

#[derive(Clone)]
pub struct Toast {
    pub message: String,
    pub danger: bool,
    pub created: Instant,
}

pub struct AppState {
    pub theme: ThemeMode,
    pub screen: Screen,
    pub toasts: Vec<Toast>,
    pub landing: LandingState,
    pub session: Option<Session>,
    /// Evidence ingest running on a background thread.
    pub pending_ingest: Option<PendingIngest>,
    /// Pre-ingest validation (§7): pending result or final outcome.
    pub validation: Option<ValidationOutcome>,
    /// VERIFY EVIDENCE re-hash job running on a background thread.
    pub pending_verify: Option<PendingVerify>,
    pub show_case_info: bool,
    /// Reference modal patterns: Add Evidence wizard, keyword search
    /// modal and the report-export modal (open/closed flags).
    pub show_add_evidence: bool,
    pub show_search_modal: bool,
    pub show_report_modal: bool,
    /// Persisted application settings (%APPDATA%\NeuroForensicsAI).
    pub settings: AppSettings,
    pub show_settings: bool,
}

/// Lifecycle of the ADD EVIDENCE validation screen (§7).
pub enum ValidationOutcome {
    /// Validation running off the UI thread.
    Pending { path: PathBuf, rx: mpsc::Receiver<Result<ValidationReport, ValidationFailure>> },
    /// File rejected — the INVALID AIF EVIDENCE screen is shown.
    Failed(ValidationFailure),
    /// File validated — the examiner may commit to a full ingest.
    Passed(ValidationReport),
}

/// Result of one VERIFY EVIDENCE pass over a registered image.
pub struct VerifyOutcome {
    pub image_id: i64,
    pub file_name: String,
    pub container_sha256: String,
    pub hash_changed: bool,
    pub expected: Option<String>,
    pub verified: Option<bool>,
    pub artifacts_ok: usize,
    pub artifacts_failed: usize,
    pub artifacts_total: usize,
}

/// A VERIFY EVIDENCE job running off the UI thread.
pub struct PendingVerify {
    pub image_id: i64,
    pub file_name: String,
    pub rx: mpsc::Receiver<Result<VerifyOutcome, String>>,
}

impl AppState {
    pub fn new() -> Self {
        let settings = AppSettings::load();
        AppState {
            theme: settings.theme,
            screen: Screen::Landing,
            toasts: Vec::new(),
            landing: LandingState::new(),
            session: None,
            pending_ingest: None,
            validation: None,
            pending_verify: None,
            show_case_info: false,
            show_add_evidence: false,
            show_search_modal: false,
            show_report_modal: false,
            settings,
            show_settings: false,
        }
    }

    /// Switch theme and persist the choice so it survives restarts.
    pub fn toggle_theme(&mut self) {
        self.theme.toggle();
        self.settings.theme = self.theme;
        let _ = self.settings.save();
    }

    pub fn toast(&mut self, message: impl Into<String>, danger: bool) {
        self.toasts.push(Toast { message: message.into(), danger, created: Instant::now() });
    }

    /// Drop toasts older than 6 seconds.
    pub fn prune_toasts(&mut self) {
        self.toasts.retain(|t| t.created.elapsed().as_secs() < 6);
    }
}

pub struct LandingState {
    pub tab: LandingTab,
    pub form: NewCaseForm,
    pub dir_text: String,
    pub error: Option<String>,
    pub browse_root: PathBuf,
    pub browse_root_text: String,
    pub discovered: Vec<CaseFolder>,
    /// Summaries of the recently used cases (settings-driven, spec §3).
    pub recent: Vec<CaseSummary>,
}

impl LandingState {
    pub fn new() -> Self {
        let home = std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        LandingState {
            tab: LandingTab::Create,
            form: NewCaseForm::default(),
            dir_text: home.display().to_string(),
            error: None,
            browse_root: home.clone(),
            browse_root_text: home.display().to_string(),
            discovered: Vec::new(),
            recent: Vec::new(),
        }
    }

    pub fn refresh_discovered(&mut self) {
        self.discovered = crate::casemgmt::list_cases(&self.browse_root);
    }

    /// Resolve the persisted recent-case paths into readable summaries,
    /// silently dropping entries whose database no longer exists.
    pub fn refresh_recent(&mut self, settings: &AppSettings) {
        self.recent = settings
            .recent_cases
            .iter()
            .filter_map(|p| {
                let folder = crate::casemgmt::locate_case(std::path::Path::new(p)).ok()?;
                crate::casemgmt::summarize_case(&folder)
            })
            .collect();
    }
}

/// An ingest job running off the UI thread.
pub struct PendingIngest {
    pub path: PathBuf,
    pub started: Instant,
    pub rx: mpsc::Receiver<Result<ExaminedCase, String>>,
    /// Live pipeline-step messages (real progress, never simulated).
    pub progress_rx: mpsc::Receiver<String>,
    /// Latest received step message.
    pub latest_step: Option<String>,
    /// Every step message received so far, oldest first (ingest modal).
    pub steps: Vec<String>,
}

/// An opened case: persistent DB + (optionally) the ingested evidence.
pub struct Session {
    pub folder: CaseFolder,
    pub db: CaseDatabase,
    pub meta: CaseMeta,
    /// Currently ingested evidence image (None until one is opened).
    pub exam: Option<ExaminedCase>,
    /// Database row id of the currently ingested image, if registered.
    pub current_image_id: Option<i64>,
    pub report: Option<AnalysisReport>,
    pub view: MainView,
    // Explorer state
    pub tree_filter: String,
    pub selected_artifact: Option<String>,
    pub viewer_tab: ViewerTab,
    pub search_query: String,
    /// Field path to highlight/scroll to in the Parsed View tab (§21
    /// search-result jump). Cleared when the selection changes.
    pub parsed_focus: Option<String>,
    pub preview: PreviewCache,
    // AI assistant chat
    pub chat: Vec<ChatMessage>,
    pub chat_input: String,
    // Timeline state (§22)
    pub timeline_filter: String,
    /// Active category filter ("All categories" or one stream name).
    pub timeline_category: String,
    /// Built once per image (or restored from SQLite) — the timeline
    /// never re-scans streams on every repaint.
    pub timeline_cache: Option<Vec<TimelineEntry>>,
    /// §23 correlation report, built once per image.
    pub correlation_cache: Option<crate::correlation::CorrelationReport>,
    /// §29/§32 validated AI-layer output for the last analysis run
    /// (recomputed by Run Analysis; never restored from stale state).
    pub ai_analysis: Option<crate::ai::ValidatedAnalysis>,
    /// §35/§36 per-finding workflow status (finding_key -> status),
    /// mirrored from the case database.
    pub finding_workflow: std::collections::HashMap<String, crate::casemgmt::db::FindingStatus>,
    /// §36 investigator note edit buffers keyed by finding_key.
    pub finding_note_draft: std::collections::HashMap<String, String>,
    /// §21 field index restored from SQLite when no image is open —
    /// global search keeps working across restarts without re-ingest.
    pub db_field_index: Vec<FieldEntry>,
    // Evidence-management state (§6)
    pub evidence_selected: Option<i64>,
    /// Image id awaiting removal confirmation (two-step REMOVE).
    pub remove_confirm: Option<i64>,
}

impl Session {
    pub fn new(folder: CaseFolder, db: CaseDatabase) -> Session {
        let meta = db.meta();
        Session {
            folder,
            db,
            meta,
            exam: None,
            current_image_id: None,
            report: None,
            view: MainView::Explorer,
            tree_filter: String::new(),
            selected_artifact: None,
            viewer_tab: ViewerTab::Parsed,
            search_query: String::new(),
            parsed_focus: None,
            preview: PreviewCache::default(),
            chat: Vec::new(),
            chat_input: String::new(),
            timeline_filter: String::new(),
            timeline_category: super::timeline::ALL_CATEGORIES.to_string(),
            timeline_cache: None,
            correlation_cache: None,
            ai_analysis: None,
            finding_workflow: std::collections::HashMap::new(),
            finding_note_draft: std::collections::HashMap::new(),
            db_field_index: Vec::new(),
            evidence_selected: None,
            remove_confirm: None,
        }
    }

    pub fn case_title(&self) -> String {
        format!("{} — {}", self.meta.case_number, self.meta.case_name)
    }

    /// Restore the latest persisted analysis (if the case was examined
    /// in a previous run).
    pub fn restore_findings(&mut self) {
        if let Some(payload) = self.db.latest_findings() {
            self.report = AnalysisReport::from_payload(&payload).ok();
        }
    }

    /// Reload the persisted §35 finding workflow (status + notes) into
    /// memory so the Findings panel and report show the investigator's
    /// recorded state after restart.
    pub fn refresh_finding_workflow(&mut self) {
        self.finding_workflow.clear();
        self.finding_note_draft.clear();
        let Some(image_id) = self.current_image_id.or_else(|| self.db.latest_image_id()) else {
            return;
        };
        for row in self.db.finding_rows(image_id) {
            self.finding_workflow.insert(row.finding_key.clone(), row.status);
            if !row.investigator_note.is_empty() {
                self.finding_note_draft.insert(row.finding_key.clone(), row.investigator_note);
            }
        }
    }

    /// Restore the §21 field index and §22 timeline from SQLite for the
    /// most recently registered image — search and timeline survive
    /// restarts without touching the original AIF.
    pub fn restore_persistent_index(&mut self) {
        let Some(image_id) = self.db.latest_image_id() else { return };
        if self.timeline_cache.is_none() {
            let records = self.db.timeline_events(image_id);
            if !records.is_empty() {
                self.timeline_cache = Some(super::timeline::from_records(records));
            }
        }
        if self.db_field_index.is_empty() {
            self.db_field_index = self
                .db
                .field_index_rows(image_id)
                .into_iter()
                .map(|r| FieldEntry {
                    artifact_id: r.artifact_id,
                    field: r.field,
                    value: r.value,
                    haystack: r.haystack,
                })
                .collect();
        }
    }
}

/// Cached bytes of the currently previewed container entry (hex view,
/// strings). Multi-GB entries are never fully loaded: only the first
/// `PREVIEW_CAP` bytes are read for the viewer.
#[derive(Default)]
pub struct PreviewCache {
    pub entry_path: String,
    pub bytes: Vec<u8>,
    pub total_size: u64,
    pub truncated: bool,
    pub load_error: Option<String>,
}

pub const PREVIEW_CAP: usize = 1024 * 1024; // 1 MiB viewer window

pub struct ChatMessage {
    pub question: String,
    pub answer: AssistantAnswer,
}