//! Explorer view: artifact result table + central evidence viewer with
//! Hex / Strings / File Metadata / AI Analysis tabs. Every row traces
//! to a collector artifact ID; absent data is labeled honestly.

use std::collections::HashMap;
use std::io::Read;

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, RichText, Stroke, StrokeKind, Ui};

use crate::analysis::rules::Severity;
use crate::ingest::index::{category_label, category_key, FieldEntry};

use super::parsed;
use super::state::{AppState, PreviewCache, Session, ViewerTab, PREVIEW_CAP};
use super::theme::{self, palette, risk_badge, severity_color, Palette, RiskTone, ThemeMode};

// ---------------------------------------------------------------------
// Unified row model (live exam or restored case database)
// ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ArtifactRow {
    pub artifact_id: String,
    pub display_name: String,
    pub relative_path: String,
    pub category: &'static str,
    pub size: u64,
    pub acquisition_time: String,
    pub status: String,
    pub synthetic: bool,
    pub hash_verified: Option<bool>,
    /// Live entry access possible (image currently open)?
    pub opened: bool,
}

pub fn build_rows(session: &Session) -> Vec<ArtifactRow> {
    if let Some(exam) = &session.exam {
        exam.artifacts
            .iter()
            .map(|a| ArtifactRow {
                artifact_id: a.artifact_id.clone(),
                display_name: a.display_name().to_string(),
                relative_path: a.relative_path.clone(),
                category: a.category,
                size: a.size,
                acquisition_time: a.acquisition_time.clone(),
                status: a.status.label().to_string(),
                synthetic: a.synthetic,
                hash_verified: a.hash_verified,
                opened: a.present,
            })
            .collect()
    } else {
        session
            .db
            .all_artifacts()
            .iter()
            .map(|s| {
                let r = &s.reference;
                ArtifactRow {
                    artifact_id: r.artifact_id.clone(),
                    display_name: r
                        .relative_path
                        .rsplit('/')
                        .next()
                        .unwrap_or(&r.relative_path)
                        .to_string(),
                    relative_path: r.relative_path.clone(),
                    category: category_key(&r.collector),
                    size: r.size,
                    acquisition_time: r.acquisition_time.clone(),
                    status: r.status.clone(),
                    synthetic: r.synthetic,
                    hash_verified: r.hash_verified,
                    opened: false,
                }
            })
            .collect()
    }
}

/// Highest finding severity referencing each artifact ID.
pub fn risk_map(session: &Session) -> HashMap<String, Severity> {
    let mut map = HashMap::new();
    if let Some(report) = &session.report {
        for finding in &report.findings {
            for id in &finding.supporting_artifacts {
                let entry = map.entry(id.clone()).or_insert(finding.severity);
                if finding.severity > *entry {
                    *entry = finding.severity;
                }
            }
        }
    }
    map
}

/// Exact evidence values detection rules flagged inside one artifact
/// (§20 byte/field highlighting in Hex and Parsed View).
pub fn flagged_values_for(session: &Session, artifact_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(report) = &session.report {
        for finding in &report.findings {
            if finding.supporting_artifacts.iter().any(|a| a == artifact_id) {
                for value in &finding.flagged_values {
                    if value.len() >= 2 && !out.contains(value) {
                        out.push(value.clone());
                    }
                }
            }
        }
    }
    out
}

/// Case-insensitive byte ranges of the flagged values inside `bytes`
/// (cap per value so pathological values cannot stall the UI).
pub fn flagged_byte_ranges(bytes: &[u8], flagged: &[String]) -> Vec<std::ops::Range<usize>> {
    if flagged.is_empty() || bytes.is_empty() {
        return Vec::new();
    }
    let haystack: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut ranges = Vec::new();
    for value in flagged {
        if value.len() < 2 {
            continue;
        }
        let needle: Vec<u8> = value.bytes().map(|b| b.to_ascii_lowercase()).collect();
        let mut start = 0usize;
        let mut hits = 0;
        while start + needle.len() <= haystack.len() && hits < 64 {
            match haystack[start..].windows(needle.len()).position(|w| w == needle.as_slice()) {
                Some(pos) => {
                    let abs = start + pos;
                    ranges.push(abs..abs + needle.len());
                    start = abs + needle.len();
                    hits += 1;
                }
                None => break,
            }
        }
    }
    ranges.sort_by_key(|r| r.start);
    ranges
}

// ---------------------------------------------------------------------
// Preview loading (streamed, capped — never loads whole large entries)
// ---------------------------------------------------------------------

pub fn load_preview(session: &mut Session, entry_path: &str) {
    if session.preview.entry_path == entry_path && !session.preview.bytes.is_empty() {
        return;
    }
    session.preview = PreviewCache {
        entry_path: entry_path.to_string(),
        ..Default::default()
    };
    let Some(exam) = &mut session.exam else {
        session.preview.load_error =
            Some("Open the evidence image to view raw content.".into());
        return;
    };
    let total = exam
        .artifacts
        .iter()
        .find(|a| a.relative_path == entry_path)
        .map(|a| a.size)
        .unwrap_or(0);
    let mut buf = Vec::new();
    let result = exam.aif.with_entry_reader(entry_path, |reader| {
        reader
            .take(PREVIEW_CAP as u64)
            .read_to_end(&mut buf)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    match result {
        Ok(()) => {
            session.preview.truncated = (buf.len() as u64) < total && total > PREVIEW_CAP as u64;
            session.preview.total_size = total.max(buf.len() as u64);
            session.preview.bytes = buf;
        }
        Err(e) => session.preview.load_error = Some(e),
    }
}

// ---------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);
    let Some(session) = &mut app.session else { return };

    let rows = build_rows(session);
    let risks = risk_map(session);

    // Keep the selected artifact valid.
    if let Some(sel) = &session.selected_artifact {
        if !rows.iter().any(|r| &r.artifact_id == sel) {
            session.selected_artifact = None;
            session.parsed_focus = None;
        }
    }

    let selected_id = session.selected_artifact.clone();
    let selected_row = rows
        .iter()
        .find(|r| selected_id.as_deref() == Some(r.artifact_id.as_str()))
        .cloned();

    // Load preview bytes for the selection (streamed + capped).
    if let Some(row) = &selected_row {
        if row.opened {
            let path = row.relative_path.clone();
            load_preview(session, &path);
        } else {
            session.preview = PreviewCache {
                entry_path: row.relative_path.clone(),
                load_error: Some(
                    "Entry content unavailable — open the evidence image (Ingest ▸ Open evidence image) to stream raw bytes.".into(),
                ),
                ..Default::default()
            };
        }
    }

    // §21: field-value search results between table and viewer.
    let query = session.search_query.trim().to_string();
    let hits: Vec<FieldEntry> = if query.is_empty() {
        Vec::new()
    } else {
        search_field_values(session, &query)
    };

    // Reference panel strip above the result table.
    let listing = session
        .exam
        .as_ref()
        .map(|e| e.image_name.clone())
        .unwrap_or_else(|| "case database".to_string());
    let (strip_rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 26.0),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(strip_rect) {
        let painter = ui.painter();
        painter.rect_filled(strip_rect, 0.0, p.panel_deep);
        painter.text(
            egui::pos2(strip_rect.min.x + 10.0, strip_rect.center().y),
            egui::Align2::LEFT_CENTER,
            "Listing:",
            egui::FontId::new(11.5, egui::FontFamily::Proportional),
            p.text_muted,
        );
        painter.text(
            egui::pos2(strip_rect.min.x + 58.0, strip_rect.center().y),
            egui::Align2::LEFT_CENTER,
            listing,
            egui::FontId::new(11.5, egui::FontFamily::Monospace),
            p.text,
        );
        painter.text(
            egui::pos2(strip_rect.max.x - 10.0, strip_rect.center().y),
            egui::Align2::RIGHT_CENTER,
            format!("{} artifact(s)", rows.len()),
            egui::FontId::new(10.5, egui::FontFamily::Monospace),
            p.text_muted,
        );
        painter.hline(
            strip_rect.x_range(),
            strip_rect.max.y - 0.5,
            Stroke::new(1.0_f32, p.border),
        );
    }

    // Top: result table. Bottom: content viewer.
    let table_height = (ui.available_height() * 0.42).max(140.0);
    ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), table_height), Layout::top_down(Align::LEFT), |ui| {
        draw_table(app, ui, &p, &rows, &risks, &query, &hits);
    });
    if !query.is_empty() {
        ui.separator();
        draw_search_results(app, ui, &p, &query, &hits);
    }
    ui.separator();
    draw_viewer(app, ui, &p, selected_row.as_ref(), &risks);
}

/// §21 global search over the ingest-time field index. Runs against
/// prebuilt haystacks — never re-reads container entries. When no
/// image is open the SQLite-restored index is used, so search keeps
/// working across restarts without a re-ingest.
pub fn search_field_values(session: &Session, query: &str) -> Vec<FieldEntry> {
    let index: &Vec<FieldEntry> = match &session.exam {
        Some(exam) => &exam.field_index,
        None => &session.db_field_index,
    };
    let q = query.to_ascii_lowercase();
    let mut hits: Vec<&FieldEntry> = index
        .iter()
        .filter(|e| e.haystack.contains(&q))
        .collect();
    hits.sort_by(|a, b| b.value.len().cmp(&a.value.len()));
    hits.into_iter().take(400).cloned().collect()
}

fn draw_table(
    app: &mut AppState,
    ui: &mut Ui,
    p: &Palette,
    rows: &[ArtifactRow],
    risks: &HashMap<String, Severity>,
    query: &str,
    hits: &[FieldEntry],
) {
    let q = query.to_ascii_lowercase();
    // Artifacts whose parsed field values match (§21) stay visible too.
    let value_matches: std::collections::HashSet<&str> =
        hits.iter().map(|h| h.artifact_id.as_str()).collect();
    let filtered: Vec<&ArtifactRow> = rows
        .iter()
        .filter(|r| {
            q.is_empty()
                || r.display_name.to_ascii_lowercase().contains(&q)
                || r.relative_path.to_ascii_lowercase().contains(&q)
                || r.artifact_id.to_ascii_lowercase().contains(&q)
                || category_label(r.category).to_ascii_lowercase().contains(&q)
                || value_matches.contains(r.artifact_id.as_str())
        })
        .collect();

    egui::ScrollArea::vertical().id_salt("artifact_table").show_rows(
        ui,
        24.0,
        filtered.len() + 1,
        |ui, range| {
            for i in range {
                if i == 0 {
                    table_header_row(ui, p);
                    continue;
                }
                table_data_row(app, ui, p, filtered[i - 1], risks);
            }
        },
    );
}

/// Column widths — Name flexes, the rest mirror the reference mix:
/// Name / Category / Risk / AI Verdict / Size / Collected (UTC).
fn table_columns(total: f32) -> [f32; 6] {
    let category = 150.0;
    let risk = 92.0;
    let verdict = 112.0;
    let size = 80.0;
    let collected = 150.0;
    let name = (total - category - risk - verdict - size - collected - 58.0).max(120.0);
    [name, category, risk, verdict, size, collected]
}

fn table_header_row(ui: &mut Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 24.0),
        egui::Sense::hover(),
    );
    if !ui.is_rect_visible(rect) {
        return;
    }
    ui.painter().rect_filled(rect, 0.0, p.thead);
    ui.painter().hline(
        rect.min.x..=rect.max.x,
        rect.max.y - 0.5,
        egui::Stroke::new(1.0_f32, p.border_strong),
    );
    let cols = table_columns(rect.width());
    let font = egui::FontId::new(10.0, egui::FontFamily::Proportional);
    let mut x = rect.min.x + 10.0;
    for (label, w) in ["NAME", "CATEGORY", "RISK", "AI VERDICT", "SIZE", "COLLECTED (UTC)"]
        .iter()
        .zip(cols)
    {
        ui.painter().text(
            egui::pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            *label,
            font.clone(),
            p.text_muted,
        );
        x += w + 8.0;
    }
}

fn table_data_row(
    app: &mut AppState,
    ui: &mut Ui,
    p: &Palette,
    row: &ArtifactRow,
    risks: &HashMap<String, Severity>,
) {
    let selected = app
        .session
        .as_ref()
        .and_then(|s| s.selected_artifact.as_deref())
        == Some(row.artifact_id.as_str());
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 24.0),
        egui::Sense::click(),
    );
    // Same-frame hover: response known before painting. Hover and
    // selection ease in/out (reference row motion).
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
    child.set_clip_rect(rect);
    let painter = child.painter();
    let ctx = ui.ctx().clone();
    let hov = theme::anim(&ctx, response.id.with("hov"), response.hovered(), theme::HOVER_TIME);
    let sel = theme::anim(&ctx, response.id.with("sel"), selected, theme::SELECT_TIME);
    let fill = theme::mix(theme::mix(Color32::TRANSPARENT, p.grid_stripe, hov), p.selection, sel);
    if fill != Color32::TRANSPARENT {
        painter.rect_filled(rect, 0.0, fill);
    }
    painter.hline(
        rect.min.x..=rect.max.x,
        rect.max.y - 0.5,
        egui::Stroke::new(1.0_f32, p.row_border),
    );
    let cols = table_columns(rect.width());
    let cy = rect.center().y;
    let mut x = rect.min.x + 10.0;
    // NAME (monospace).
    painter.text(
        egui::pos2(x, cy),
        egui::Align2::LEFT_CENTER,
        row.display_name.clone(),
        egui::FontId::new(11.5, egui::FontFamily::Monospace),
        p.text,
    );
    x += cols[0] + 8.0;
    // CATEGORY.
    painter.text(
        egui::pos2(x, cy),
        egui::Align2::LEFT_CENTER,
        category_label(row.category).to_string(),
        egui::FontId::new(11.5, egui::FontFamily::Proportional),
        p.text,
    );
    x += cols[1] + 8.0;
    // RISK — reference badge triple.
    let severity = risks.get(&row.artifact_id);
    let tone = severity
        .copied()
        .map(RiskTone::from_severity)
        .unwrap_or(RiskTone::Clean);
    let badge_text = severity
        .map(|s| s.label().to_string())
        .unwrap_or_else(|| "CLEAN".to_string());
    let badge_galley = painter.layout_no_wrap(
        badge_text.clone(),
        egui::FontId::new(9.5, egui::FontFamily::Monospace),
        Color32::PLACEHOLDER,
    );
    let _ = theme::paint_risk_badge(
        &child,
        egui::pos2(x, cy),
        app.theme,
        p,
        tone,
        &badge_text,
    );
    x += cols[2].max(badge_galley.size().x + 14.0) + 8.0;
    // AI VERDICT — indicator grounded on this artifact, or clean.
    let (verdict_text, verdict_color) = if severity.is_some() {
        ("⚑ FLAGGED".to_string(), p.danger)
    } else {
        ("✓ CLEAN".to_string(), p.good)
    };
    painter.text(
        egui::pos2(x, cy),
        egui::Align2::LEFT_CENTER,
        verdict_text,
        egui::FontId::new(10.5, egui::FontFamily::Monospace),
        verdict_color,
    );
    x += cols[3] + 8.0;
    // SIZE.
    painter.text(
        egui::pos2(x, cy),
        egui::Align2::LEFT_CENTER,
        crate::gui::fmt_bytes(row.size),
        egui::FontId::new(10.5, egui::FontFamily::Monospace),
        p.text_dim,
    );
    x += cols[4] + 8.0;
    // COLLECTED (UTC).
    painter.text(
        egui::pos2(x, cy),
        egui::Align2::LEFT_CENTER,
        row.acquisition_time.clone(),
        egui::FontId::new(10.5, egui::FontFamily::Monospace),
        p.text_dim,
    );

    if response.clicked() {
        if let Some(s) = &mut app.session {
            s.selected_artifact = Some(row.artifact_id.clone());
            s.parsed_focus = None;
        }
    }
}

/// §21 search-result list: artifact, category and the matching
/// field/value snippet. Clicking jumps straight to the artifact with
/// the matching field focused in the Parsed View tab.
fn draw_search_results(
    app: &mut AppState,
    ui: &mut Ui,
    p: &Palette,
    query: &str,
    hits: &[FieldEntry],
) {
    let rows_by_id: HashMap<String, ArtifactRow> = app
        .session
        .as_ref()
        .map(|s| {
            build_rows(s)
                .into_iter()
                .map(|r| (r.artifact_id.clone(), r))
                .collect()
        })
        .unwrap_or_default();

    ui.label(
        RichText::new(format!(
            "SEARCH RESULTS — {} field match(es) for \"{query}\" across indexed artifacts",
            hits.len()
        ))
        .color(p.text_dim)
        .strong()
        .size(11.5),
    );
    if hits.is_empty() {
        ui.label(
            RichText::new("No parsed field values match. The artifact table above still matches filenames, paths, IDs and categories.")
                .color(p.text_dim)
                .size(11.5),
        );
        return;
    }

    let q = query.to_ascii_lowercase();
    egui::ScrollArea::vertical()
        .id_salt("search_results")
        .max_height(130.0)
        .show(ui, |ui| {
            for (i, hit) in hits.iter().take(100).enumerate() {
                let Some(row) = rows_by_id.get(&hit.artifact_id) else {
                    continue;
                };
                let response = egui::Frame::default()
                    .fill(if i % 2 == 0 { Color32::TRANSPARENT } else { p.grid_stripe })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&row.display_name).strong().size(12.0));
                            ui.label(RichText::new(category_label(row.category)).weak().size(11.0));
                            ui.label(RichText::new(&hit.field).monospace().color(p.accent).size(11.0));
                            ui.label(highlight_snippet(&hit.value, &q, p));
                        });
                    })
                    .response;
                if response.clicked() {
                    if let Some(s) = &mut app.session {
                        s.selected_artifact = Some(hit.artifact_id.clone());
                        s.viewer_tab = ViewerTab::Parsed;
                        s.parsed_focus = Some(hit.field.clone());
                        s.view = super::state::MainView::Explorer;
                    }
                }
            }
            if hits.len() > 100 {
                ui.label(
                    RichText::new(format!("…and {} more match(es) — refine the keyword to narrow down.", hits.len() - 100))
                        .color(p.text_dim)
                        .size(11.0),
                );
            }
        });
}

/// Snippet text with the match visually marked.
fn highlight_snippet(value: &str, q: &str, p: &Palette) -> RichText {
    let lower = value.to_ascii_lowercase();
    match lower.find(q) {
        Some(pos) => {
            let from = char_floor(value, pos);
            let to = char_ceil(value, pos + q.len());
            RichText::new(format!("…{}[{}]{}…", &value[..from], &value[from..to], &value[to..]))
                .monospace()
                .size(11.0)
                .color(p.text)
        }
        None => RichText::new(value).monospace().size(11.0).color(p.text),
    }
}

fn char_floor(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn char_ceil(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn draw_viewer(
    app: &mut AppState,
    ui: &mut Ui,
    p: &Palette,
    row: Option<&ArtifactRow>,
    risks: &HashMap<String, Severity>,
) {
    let mode = app.theme;
    let Some(session) = &mut app.session else { return };
    let Some(row) = row else {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(RichText::new("Select an artifact to inspect its evidence.").color(p.text_dim));
            ui.label(RichText::new("Nothing is shown until real evidence is present.").color(p.text_dim).size(11.5));
        });
        return;
    };

    // Reference cv-tabs: strip fill, active tab merges into the body
    // below (top rounded, side borders, bottom border erased under it).
    let (strip_rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 32.0),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    let tab_font = egui::FontId::new(12.0, egui::FontFamily::Proportional);
    let mut x = strip_rect.min.x + 8.0;
    let mut clicked_tab: Option<ViewerTab> = None;
    let mut active_rect: Option<egui::Rect> = None;
    let mut tab_items: Vec<(ViewerTab, egui::Rect, egui::Response)> = Vec::new();
    for tab in ViewerTab::ALL {
        let galley = painter.layout_no_wrap(tab.label().to_string(), tab_font.clone(), Color32::PLACEHOLDER);
        let rect = egui::Rect::from_min_size(
            egui::pos2(x, strip_rect.min.y),
            egui::vec2(galley.size().x + 28.0, strip_rect.height()),
        );
        let response = ui.interact(rect, ui.id().with("cv_tab").with(tab.label()), egui::Sense::click());
        if response.clicked() {
            clicked_tab = Some(tab);
        }
        if session.viewer_tab == tab {
            active_rect = Some(rect);
        }
        x = rect.max.x;
        tab_items.push((tab, rect, response));
    }
    if ui.is_rect_visible(strip_rect) {
        painter.rect_filled(strip_rect, 0.0, p.panel_deep);
        // Active tab first so the split bottom border never crosses it.
        if let Some(ar) = active_rect {
            painter.rect(
                ar,
                CornerRadius { nw: 5, ne: 5, sw: 0, se: 0 },
                p.panel,
                Stroke::NONE,
                StrokeKind::Inside,
            );
            painter.vline(ar.min.x, ar.min.y..=ar.max.y, Stroke::new(1.0_f32, p.border));
            painter.vline(ar.max.x, ar.min.y..=ar.max.y, Stroke::new(1.0_f32, p.border));
            painter.hline(ar.min.x..=ar.max.x, ar.min.y + 0.5, Stroke::new(1.0_f32, p.border));
        }
        let line_y = strip_rect.max.y - 0.5;
        let border = Stroke::new(1.0_f32, p.border_strong);
        match active_rect {
            Some(ar) => {
                painter.hline(strip_rect.min.x..=ar.min.x, line_y, border);
                painter.hline(ar.max.x..=strip_rect.max.x, line_y, border);
            }
            None => {
                painter.hline(strip_rect.min.x..=strip_rect.max.x, line_y, border);
            }
        }
        // Artifact path on the right of the strip.
        painter.text(
            egui::pos2(strip_rect.max.x - 10.0, strip_rect.center().y),
            egui::Align2::RIGHT_CENTER,
            format!("{} · {}", row.artifact_id, row.relative_path),
            egui::FontId::new(10.5, egui::FontFamily::Monospace),
            p.text_muted,
        );
    }
    for (tab, rect, _response) in tab_items {
        if ui.is_rect_visible(rect) {
            let active = session.viewer_tab == tab;
            let color = if active { p.accent_deep } else { p.text_dim };
            let galley = painter.layout_no_wrap(tab.label().to_string(), tab_font.clone(), color);
            let mut pos = rect.center();
            pos.x -= galley.size().x / 2.0;
            pos.y -= galley.size().y / 2.0;
            painter.galley(pos, galley, color);
        }
    }
    if let Some(tab) = clicked_tab {
        session.viewer_tab = tab;
    }

    let tab = session.viewer_tab;
    let flagged = flagged_values_for(session, &row.artifact_id);
    match tab {
        ViewerTab::Parsed => parsed::draw(ui, p, session, row, &flagged),
        ViewerTab::Hex => draw_hex(ui, p, mode, session, row, &flagged),
        ViewerTab::Strings => draw_strings(ui, p, session),
        ViewerTab::Metadata => draw_metadata(ui, p, session, row),
        ViewerTab::Ai => draw_ai_analysis(ui, p, session, row, risks),
    }
}

fn draw_hex(
    ui: &mut Ui,
    p: &Palette,
    mode: ThemeMode,
    session: &mut Session,
    row: &ArtifactRow,
    flagged: &[String],
) {
    // Reference hex-toolbar: identity line left, legend right.
    let ranges = flagged_byte_ranges(&session.preview.bytes, flagged);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "{} · {} bytes · offset base 16",
                row.display_name,
                session.preview.total_size.max(session.preview.bytes.len() as u64)
            ))
            .monospace()
            .color(p.text_dim)
            .size(11.0),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let note = if ranges.is_empty() {
                "AI-flagged signature bytes".to_string()
            } else {
                format!("AI-flagged signature bytes · {} range(s)", ranges.len())
            };
            ui.label(RichText::new(note).color(p.text_dim).size(10.5));
            let (fg, bg, border) = risk_badge(p, mode, RiskTone::High);
            let (swatch, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
            ui.painter().rect(swatch, 2.0, bg, Stroke::new(1.0_f32, border), StrokeKind::Inside);
            ui.painter().rect_filled(swatch.shrink(3.0), 1.0, fg);
        });
    });
    ui.separator();

    egui::ScrollArea::both().id_salt("hex_view").show(ui, |ui| {
        if let Some(err) = &session.preview.load_error {
            ui.label(RichText::new(err).color(p.warn));
            return;
        }
        let bytes = &session.preview.bytes;
        if bytes.is_empty() {
            ui.label(RichText::new("Entry is empty (0 bytes).").color(p.text_dim));
            return;
        }
        if session.preview.truncated {
            ui.label(
                RichText::new(format!(
                    "Streaming preview — showing first {} of {} bytes (large evidence is never fully loaded into RAM).",
                    crate::gui::fmt_bytes(bytes.len() as u64),
                    crate::gui::fmt_bytes(session.preview.total_size)
                ))
                .color(p.warn)
                .size(11.5),
            );
            ui.add_space(4.0);
        }
        let max_rows = (bytes.len() + 15) / 16;
        let shown = max_rows.min(4096);
        let (flag_fg, flag_bg, _) = risk_badge(p, mode, RiskTone::High);
        egui::ScrollArea::vertical().id_salt("hex_rows").auto_shrink([false, true]).show_rows(
            ui,
            15.0,
            shown,
            |ui, range| {
                for r in range {
                    let start = r * 16;
                    let chunk = &bytes[start..bytes.len().min(start + 16)];
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{:08x}", start))
                                .monospace()
                                .color(p.accent_deep)
                                .strong(),
                        );
                        for (i, b) in chunk.iter().enumerate() {
                            let offset = start + i;
                            let is_flagged = ranges.iter().any(|rg| rg.contains(&offset));
                            let mut text = RichText::new(format!("{b:02x} ")).monospace();
                            if is_flagged {
                                text = text.color(flag_fg).background_color(flag_bg).strong();
                            } else {
                                text = text.color(p.text);
                            }
                            ui.label(text);
                        }
                        // ASCII column with per-char flagged highlighting.
                        ui.scope(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            for (i, b) in chunk.iter().enumerate() {
                                let offset = start + i;
                                let ch = if (0x20..0x7f).contains(b) { *b as char } else { '.' };
                                let is_flagged = ranges.iter().any(|rg| rg.contains(&offset));
                                let mut text = RichText::new(ch.to_string()).monospace();
                                if is_flagged {
                                    text = text.color(flag_fg).background_color(flag_bg).strong();
                                } else {
                                    text = text.color(p.accent);
                                }
                                ui.label(text);
                            }
                        });
                    });
                }
            },
        );
    });
}

fn draw_strings(ui: &mut Ui, p: &Palette, session: &mut Session) {
    egui::ScrollArea::vertical().id_salt("strings_view").show(ui, |ui| {
        if let Some(err) = &session.preview.load_error {
            ui.label(RichText::new(err).color(p.warn));
            return;
        }
        if session.preview.bytes.is_empty() {
            ui.label(RichText::new("No bytes available — entry is empty.").color(p.text_dim));
            return;
        }
        let strings = crate::ingest::streams::extract_strings(&session.preview.bytes, 4, 2000);
        if strings.is_empty() {
            ui.label(RichText::new("No printable ASCII strings (min length 4) in the preview window.").color(p.text_dim));
            return;
        }
        ui.label(RichText::new(format!("{} string(s) extracted from the raw entry bytes (min length 4):", strings.len()))
            .color(p.text_dim).size(11.5));
        ui.add_space(4.0);
        for (offset, s) in &strings {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{offset:08x}")).monospace().color(p.text_dim).size(12.0));
                ui.label(RichText::new(s).monospace().size(12.0).color(p.text));
            });
        }
    });
}

fn draw_metadata(ui: &mut Ui, p: &Palette, session: &Session, row: &ArtifactRow) {
    egui::ScrollArea::vertical().id_salt("meta_view").show(ui, |ui| {
        egui::Grid::new("artifact_metadata").min_col_width(190.0).spacing([10.0, 7.0]).show(ui, |ui| {
            let mut kv = |k: &str, v: String, mono: bool| {
                ui.label(RichText::new(k).color(p.text_dim).size(12.0));
                if mono {
                    ui.label(RichText::new(v).monospace().size(12.0));
                } else {
                    ui.label(RichText::new(v).size(12.0));
                }
                ui.end_row();
            };
            kv("Artifact ID", row.artifact_id.clone(), true);
            kv("Evidence stream", row.relative_path.clone(), true);
            kv("Category", category_label(row.category).to_string(), false);
            kv("Size", format!("{} bytes ({})", row.size, crate::gui::fmt_bytes(row.size)), false);
            kv("Acquisition time (UTC)", row.acquisition_time.clone(), true);
            kv("Collector status", row.status.clone(), false);
            kv("Synthetic (demo) flag", if row.synthetic { "YES — collector marked this synthetic" } else { "no" }.to_string(), false);
            kv(
                "SHA-256 re-verification",
                match row.hash_verified {
                    Some(true) => "VERIFIED — re-hash matches manifest".into(),
                    Some(false) => "FAILED — hash mismatch or missing entry".into(),
                    None => "Not verified in this session".into(),
                },
                false,
            );
            // Full provenance when the image is open.
            if let Some(exam) = &session.exam {
                if let Some(a) = exam.artifact_by_id(&row.artifact_id) {
                    kv("SHA-256 (manifest)", a.sha256.clone(), true);
                    kv("Source", a.source.clone(), false);
                    kv("Collector module", a.collector.clone(), false);
                    if let Some(notes) = &a.notes {
                        kv("Collector notes", notes.clone(), false);
                    }
                    ui.end_row();
                    ui.label(RichText::new("Provenance").color(p.text_dim).size(12.0));
                    ui.label(
                        RichText::new(format!(
                            "Acquired by MEMO Collector {} from host '{}' (case {}), recorded in manifest.json of {} (AIF v{}).",
                            exam.manifest.collector.version,
                            exam.manifest.host.hostname,
                            exam.case_doc.case.case_id,
                            exam.image_name,
                            exam.case_doc.format_version
                        ))
                        .size(12.0),
                    );
                    ui.end_row();
                }
            } else {
                ui.end_row();
                ui.label(RichText::new("Provenance").color(p.text_dim).size(12.0));
                ui.label(
                    RichText::new("Recorded in the case database from a previous ingest. Open the evidence image for full provenance and raw access.")
                        .color(p.text_dim).size(12.0),
                );
                ui.end_row();
            }
        });
    });
}

fn draw_ai_analysis(
    ui: &mut Ui,
    p: &Palette,
    session: &Session,
    row: &ArtifactRow,
    risks: &HashMap<String, Severity>,
) {
    egui::ScrollArea::vertical().id_salt("ai_view").show(ui, |ui| {
        let report = session.report.as_ref();
        let linked: Vec<&crate::analysis::rules::Finding> = report
            .map(|r| {
                r.findings
                    .iter()
                    .filter(|f| f.supporting_artifacts.iter().any(|a| a == &row.artifact_id))
                    .collect()
            })
            .unwrap_or_default();

        if linked.is_empty() {
            ui.label(
                RichText::new("No analytical indicators reference this artifact.").color(p.text_dim),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("The rule engine and the local isolation-forest model ran over the decoded evidence; nothing about this artifact stood out. This is an absence statement, not a clearance.")
                    .color(p.text_dim)
                    .size(11.5),
            );
        } else {
            ui.label(
                RichText::new(format!(
                    "{} indicator(s) grounded on this artifact:",
                    linked.len()
                ))
                .strong(),
            );
            ui.add_space(6.0);
            for finding in linked {
                egui::Frame::default()
                    .fill(p.panel_deep)
                    .corner_radius(6.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(finding.rule_id.clone())
                                    .monospace()
                                    .color(severity_color(p, finding.severity))
                                    .strong(),
                            );
                            ui.label(RichText::new(finding.severity.label()).color(severity_color(p, finding.severity)).size(11.0));
                            ui.label(RichText::new(finding.evidence_class.clone()).weak().size(11.0));
                            // §30: method + confidence always part of the card.
                            ui.label(
                                RichText::new(format!("{} · {}", finding.method.label(), finding.confidence_label()))
                                    .color(p.accent)
                                    .size(11.0),
                            );
                        });
                        ui.label(RichText::new(finding.title.clone()).strong().size(12.5));
                        ui.label(RichText::new(finding.summary.clone()).size(12.0));
                        ui.label(RichText::new(format!("Why flagged: {}", finding.indicators.join("; ")))
                            .color(p.text_dim).size(11.5));
                        // §30: evidence sources resolved from the case index.
                        if let Some(exam) = session.exam.as_ref() {
                            let sources = crate::analysis::xai::evidence_sources(exam, &finding.supporting_artifacts);
                            if !sources.is_empty() {
                                ui.label(
                                    RichText::new(format!("Evidence sources: {}", sources.join(", ")))
                                        .color(p.text_dim)
                                        .size(11.0),
                                );
                            }
                        }
                        ui.label(
                            RichText::new(format!("Limitations: {}", crate::analysis::xai::RULE_LIMITATION))
                                .color(p.text_dim)
                                .size(10.5)
                                .italics(),
                        );
                    });
                ui.add_space(6.0);
            }
        }

        // ML context for the process list artifact.
        if let Some(report) = report {
            if let Some(ps) = session.exam.as_ref().and_then(|e| e.streams.processes.as_ref()) {
                if ps.list_artifact.as_deref() == Some(row.artifact_id.as_str()) {
                    ui.separator();
                    ui.label(RichText::new("ML anomaly scoring (local isolation forest)").strong());
                    ui.label(
                        RichText::new(format!(
                            "Status: {} — {} process sample(s) scored, {} anomaly(ies) above threshold.",
                            report.ml.status.label(),
                            report.ml.samples_used,
                            report.ml.anomalies.len()
                        ))
                        .size(12.0),
                    );
                    for anomaly in &report.ml.anomalies {
                        ui.label(
                            RichText::new(format!(
                                "• pid {} ({}) score {:.3} — dominant: {}",
                                anomaly.pid,
                                anomaly.process_name,
                                anomaly.score,
                                anomaly.dominant_features.join(", ")
                            ))
                            .monospace()
                            .size(11.5),
                        );
                    }
                }
            }
        }

        if let Some(sev) = risks.get(&row.artifact_id) {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Overall risk flag for this artifact: {}", sev.label()))
                    .color(severity_color(p, *sev)),
            );
        }
    });
}