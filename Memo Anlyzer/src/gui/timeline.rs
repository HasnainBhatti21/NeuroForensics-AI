//! Investigation timeline (§22): every time-stamped fact from the
//! evidence, sorted newest first. Sources: artifact acquisition times,
//! process start times, hash computation times, Windows event records
//! and the manifest acquisition window. Streams that were never
//! acquired contribute nothing (honest absence); artifacts without a
//! timestamp are never given an invented one.
//!
//! Entries are cached per session and, at ingest time, persisted to
//! SQLite (`timeline_events`) so the timeline survives restarts.

use chrono::DateTime;
use eframe::egui::{self, Color32, Layout, RichText, Stroke, StrokeKind, Ui};

use super::explorer::risk_map;
use super::state::{AppState, MainView, ViewerTab};
use super::theme::{palette, severity_color, Palette};

#[derive(Clone, Debug)]
pub struct TimelineEntry {
    /// RFC 3339 timestamp exactly as it appears in the evidence.
    pub time: String,
    pub category: String,
    pub label: String,
    pub detail: String,
    pub artifact_id: Option<String>,
}

/// Parse the evidence timestamp for honest chronological sorting.
/// Newest-first ordering puts parseable timestamps first; unparseable
/// strings sort last (never silently re-dated).
fn sort_key(entry: &TimelineEntry) -> (bool, Option<DateTime<chrono::FixedOffset>>) {
    let parsed = DateTime::parse_from_rfc3339(&entry.time).ok();
    (parsed.is_some(), parsed)
}

/// Build the full timeline from one examined image. Only timestamps
/// physically present in the evidence appear — nothing is invented.
pub fn build_entries(exam: &crate::ingest::ExaminedCase) -> Vec<TimelineEntry> {
    let mut out = Vec::new();

    // Acquisition timestamp of every artifact.
    for a in &exam.artifacts {
        if a.acquisition_time.is_empty() {
            continue; // "Timestamp unavailable" — never invent one.
        }
        out.push(TimelineEntry {
            time: a.acquisition_time.clone(),
            category: a.category.to_string(),
            label: format!("Artifact acquired: {}", a.display_name()),
            detail: format!("{} · {} · collector '{}'", a.artifact_id, a.relative_path, a.collector),
            artifact_id: Some(a.artifact_id.clone()),
        });
    }

    // Process start times.
    if let Some(processes) = &exam.streams.processes {
        for p in &processes.processes {
            if p.start_time_rfc3339.is_empty() {
                continue;
            }
            out.push(TimelineEntry {
                time: p.start_time_rfc3339.clone(),
                category: "processes".to_string(),
                label: format!("Process started: {}", p.name),
                detail: format!("pid {} · {}", p.pid, truncate(&p.command_line, 140)),
                artifact_id: processes.list_artifact.clone(),
            });
        }
    }

    // Windows event timestamps (per-record times from events.json).
    if let Some(events) = &exam.streams.events {
        for channel in &events.channels {
            for event in &channel.events {
                if event.time_created.is_empty() {
                    continue;
                }
                out.push(TimelineEntry {
                    time: event.time_created.clone(),
                    category: "windows_events".to_string(),
                    label: format!("Event {} ({}) — {}", event.event_id, event.level, channel.label),
                    detail: format!(
                        "{} · record {} · provider '{}'",
                        truncate(&event.message, 120),
                        event.record_id,
                        event.provider
                    ),
                    artifact_id: channel.artifact_id.clone(),
                });
            }
        }
    }

    // Acquisition window from the manifest (collector-side events).
    let acq = &exam.manifest.acquisition;
    if !acq.start_time.is_empty() {
        out.push(TimelineEntry {
            time: acq.start_time.clone(),
            category: "system".to_string(),
            label: "Evidence acquisition started".into(),
            detail: format!("operator '{}' · method '{}'", acq.operator, acq.method),
            artifact_id: None,
        });
    }
    if !acq.end_time.is_empty() {
        out.push(TimelineEntry {
            time: acq.end_time.clone(),
            category: "system".to_string(),
            label: format!("Evidence acquisition finished ({})", acq.status),
            detail: format!("collector {}", exam.manifest.collector.version),
            artifact_id: None,
        });
    }

    out.sort_by(|a, b| sort_key(b).cmp(&sort_key(a))); // newest first
    out
}

fn truncate(s: &str, max: usize) -> String {
    let one_line: String = s.lines().next().unwrap_or(s).to_string();
    if one_line.len() <= max {
        one_line
    } else {
        format!("{}…", &one_line[..max])
    }
}

// ---------- persistence mapping (SQLite `timeline_events`) ----------

pub fn to_records(entries: &[TimelineEntry]) -> Vec<crate::casemgmt::db::TimelineEventRecord> {
    entries
        .iter()
        .map(|e| crate::casemgmt::db::TimelineEventRecord {
            ts: e.time.clone(),
            category: e.category.clone(),
            label: e.label.clone(),
            detail: e.detail.clone(),
            artifact_id: e.artifact_id.clone(),
        })
        .collect()
}

pub fn from_records(records: Vec<crate::casemgmt::db::TimelineEventRecord>) -> Vec<TimelineEntry> {
    let mut entries: Vec<TimelineEntry> = records
        .into_iter()
        .map(|r| TimelineEntry {
            time: r.ts,
            category: r.category,
            label: r.label,
            detail: r.detail,
            artifact_id: r.artifact_id,
        })
        .collect();
    entries.sort_by(|a, b| sort_key(b).cmp(&sort_key(a)));
    entries
}

pub const ALL_CATEGORIES: &str = "All categories";

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);

    // Lazy build/cache: from the open image when available; otherwise
    // the cache already restored from SQLite (or empty — honest).
    if let Some(session) = &mut app.session {
        if session.timeline_cache.is_none() {
            session.timeline_cache = session.exam.as_ref().map(build_entries);
        }
    }
    let entries: Vec<TimelineEntry> = app
        .session
        .as_ref()
        .and_then(|s| s.timeline_cache.clone())
        .unwrap_or_default();

    ui.horizontal(|ui| {
        ui.label(RichText::new("INVESTIGATION TIMELINE").strong().size(13.0));
        ui.label(RichText::new(format!("{} time-stamped event(s)", entries.len())).color(p.text_dim).size(11.5));
        if let Some(session) = &mut app.session {
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_sized(
                    [220.0, 24.0],
                    egui::TextEdit::singleline(&mut session.timeline_filter).hint_text("Filter timeline…"),
                );
                let mut categories: Vec<String> = vec![ALL_CATEGORIES.to_string()];
                for e in &entries {
                    if !categories.iter().any(|c| c == &e.category) {
                        categories.push(e.category.clone());
                    }
                }
                egui::ComboBox::from_id_salt("timeline_category")
                    .selected_text(&session.timeline_category)
                    .width(150.0)
                    .show_ui(ui, |ui| {
                        for c in categories {
                            ui.selectable_value(&mut session.timeline_category, c.clone(), c);
                        }
                    });
            });
        }
    });
    ui.separator();

    if entries.is_empty() {
        empty_note(ui, &p, app);
        return;
    }

    let (filter, category) = app
        .session
        .as_ref()
        .map(|s| (s.timeline_filter.to_ascii_lowercase(), s.timeline_category.clone()))
        .unwrap_or_default();
    let filtered: Vec<&TimelineEntry> = entries
        .iter()
        .filter(|e| category == ALL_CATEGORIES || e.category == category)
        .filter(|e| {
            filter.is_empty()
                || e.label.to_ascii_lowercase().contains(&filter)
                || e.detail.to_ascii_lowercase().contains(&filter)
                || e.category.contains(&filter)
        })
        .collect();

    if filtered.is_empty() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("No timeline entries match the current filter.").color(p.text_dim));
        });
        return;
    }

    // Virtualized rows — real cases carry thousands of entries.
    // Reference style: left line + risk-colored dots + hoverable cards.
    let risks = app
        .session
        .as_ref()
        .map(risk_map)
        .unwrap_or_default();
    let row_height = 72.0;
    let mut jumped: Option<String> = None;
    egui::ScrollArea::vertical().id_salt("timeline").show_rows(
        ui,
        row_height,
        filtered.len(),
        |ui, range| {
            for entry in filtered[range].iter() {
                if draw_entry_row(ui, &p, &risks, entry) {
                    if let Some(id) = &entry.artifact_id {
                        jumped = Some(id.clone());
                    }
                }
            }
        },
    );
    // Selecting an entry jumps to that artifact's detail
    // panel (§22 → §20 never-blank guarantee).
    if let Some(id) = jumped {
        if let Some(session) = &mut app.session {
            session.selected_artifact = Some(id);
            session.viewer_tab = ViewerTab::Parsed;
            session.parsed_focus = None;
            session.view = MainView::Explorer;
        }
    }
}

/// One timeline row: gutter line + dot colored by the linked artifact's
/// risk, then a card (time above, title, detail). Returns true when an
/// artifact-backed card was clicked.
fn draw_entry_row(
    ui: &mut Ui,
    p: &Palette,
    risks: &std::collections::HashMap<String, crate::analysis::rules::Severity>,
    entry: &TimelineEntry,
) -> bool {
    let row_height = 64.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), row_height),
        egui::Sense::click(),
    );
    let visible = ui.is_rect_visible(rect);
    // Gutter line spanning this row (extends past both edges so rows link).
    let gx = rect.min.x + 13.0;
    if visible {
        ui.painter().vline(
            gx,
            rect.min.y - 6.0..=rect.max.y + 6.0,
            Stroke::new(2.0_f32, p.border_strong),
        );
        let dot = match entry.artifact_id.as_ref().and_then(|id| risks.get(id)) {
            Some(sev) => severity_color(p, *sev),
            None if entry.category == "system" => p.accent,
            None => p.good,
        };
        let center = egui::pos2(gx, rect.center().y);
        ui.painter().circle_filled(center, 5.0, dot);
        ui.painter().circle_stroke(center, 7.5, Stroke::new(1.5_f32, Color32::from_rgba_unmultiplied(dot.r(), dot.g(), dot.b(), 90)));
    }
    // Card.
    let card = egui::Rect::from_min_max(egui::pos2(gx + 18.0, rect.min.y), egui::pos2(rect.max.x, rect.max.y));
    if visible {
        let (fill, stroke) = if response.hovered() {
            (p.hover_soft, Stroke::new(1.0_f32, p.accent))
        } else {
            (p.panel, Stroke::new(1.0_f32, p.border))
        };
        ui.painter().rect(card, 8.0, fill, stroke, StrokeKind::Inside);
    }
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(card));
    child.set_clip_rect(card);
    child.spacing_mut().item_spacing.y = 2.0;
    child.vertical(|ui| {
        ui.add_space(7.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new(&entry.time).monospace().color(p.text_muted).size(10.0));
        });
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new(&entry.label).strong().size(12.0));
            ui.label(RichText::new(format!("· {}", entry.category)).color(p.text_muted).size(10.5));
        });
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new(&entry.detail).color(p.text_dim).size(11.0));
        });
    });
    // Selecting an entry jumps to that artifact's detail
    // panel (§22 → §20 never-blank guarantee).
    response.clicked() && entry.artifact_id.is_some()
}

fn empty_note(ui: &mut Ui, p: &Palette, app: &AppState) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        let msg = match &app.session {
            Some(s) if s.exam.is_none() && s.timeline_cache.is_none() => {
                "No timeline persisted for this case yet. Add a .AIF image to build the timeline from real acquisition and event timestamps."
            }
            _ => "No time-stamped evidence is present in this case.",
        };
        ui.label(RichText::new(msg).color(p.text_dim));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sorting must be chronological by parsed timestamp — a mixed
    /// `Z` / `+02:00` set proves UTC normalization, not string order.
    #[test]
    fn entries_sort_newest_first_across_utc_offsets() {
        let mk = |ts: &str| TimelineEntry {
            time: ts.to_string(),
            category: "t".into(),
            label: ts.to_string(),
            detail: String::new(),
            artifact_id: None,
        };
        let mut entries = vec![
            mk("2026-08-26T16:00:00Z"),      // 16:00 UTC
            mk("2026-08-26T17:30:00+02:00"), // 15:30 UTC — earlier
            mk("2026-08-26T16:30:00Z"),      // 16:30 UTC
        ];
        entries.sort_by(|a, b| sort_key(b).cmp(&sort_key(a)));
        assert_eq!(entries[0].time, "2026-08-26T16:30:00Z");
        assert_eq!(entries[1].time, "2026-08-26T16:00:00Z");
        assert_eq!(entries[2].time, "2026-08-26T17:30:00+02:00");
    }

    /// Unparseable timestamps are never re-dated: they sort last.
    #[test]
    fn unparseable_timestamps_sort_last() {
        let mk = |ts: &str| TimelineEntry {
            time: ts.to_string(),
            category: "t".into(),
            label: ts.to_string(),
            detail: String::new(),
            artifact_id: None,
        };
        let mut entries = vec![mk("not-a-date"), mk("2026-08-26T16:00:00Z")];
        entries.sort_by(|a, b| sort_key(b).cmp(&sort_key(a)));
        assert_eq!(entries[0].time, "2026-08-26T16:00:00Z");
        assert_eq!(entries[1].time, "not-a-date");
    }

    /// §22 honesty over the real case: every timeline entry carries a
    /// parseable RFC 3339 timestamp copied verbatim from the evidence —
    /// nothing invented — and the list is genuinely chronological.
    #[test]
    fn real_case_timeline_uses_only_real_timestamps() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else {
            eprintln!("sample AIF not present - skipping");
            return;
        };
        let entries = build_entries(&exam);
        assert!(entries.len() > 1000, "real timeline is dense ({})", entries.len());

        // Sources represented in the real case.
        let categories: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.category.as_str()).collect();
        assert!(categories.contains("windows_events"), "event records on timeline");
        assert!(categories.contains("system"), "acquisition window on timeline");

        // Every entry timestamp parses as RFC 3339 and the ordering is
        // chronologically non-increasing.
        let mut prev: Option<DateTime<chrono::FixedOffset>> = None;
        for e in &entries {
            let parsed = DateTime::parse_from_rfc3339(&e.time)
                .unwrap_or_else(|_| panic!("unparseable timeline timestamp: '{}'", e.time));
            if let Some(p) = prev {
                assert!(parsed <= p, "timeline not newest-first at '{}'", e.time);
            }
            prev = Some(parsed);
        }

        // Roundtrip through the persistent layer: write to a throwaway
        // case.db, "restart", read back — identical entries.
        let db_path = std::env::temp_dir().join(format!(
            "nf-timeline-real-{}.db",
            chrono::Local::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let meta = crate::casemgmt::db::CaseMeta {
            case_number: exam.case_id().to_string(),
            case_dir: db_path.to_string_lossy().to_string(),
            ..Default::default()
        };
        let mut db = crate::casemgmt::db::CaseDatabase::create(&db_path, &meta).expect("create db");
        let image_id = db
            .add_evidence_image(&crate::casemgmt::db::EvidenceImageRecord {
                path: exam.image_path.display().to_string(),
                file_name: exam.image_name.clone(),
                size_bytes: exam.size_bytes,
                container_sha256: exam.aif.container_sha256.clone(),
                expected_sha256: None,
                container_verified: None,
                case_id: Some(exam.case_id().to_string()),
                format_version: None,
                demo_mode: false,
                added_at: chrono::Local::now().to_rfc3339(),
            })
            .expect("add image");
        db.replace_timeline_events(image_id, &to_records(&entries))
            .expect("persist timeline");
        drop(db);

        let db2 = crate::casemgmt::db::CaseDatabase::open(&db_path).expect("reopen");
        let restored = from_records(db2.timeline_events(image_id));
        assert_eq!(restored.len(), entries.len(), "every entry survives restart");
        assert_eq!(restored[0].time, entries[0].time, "order preserved");
        std::fs::remove_file(&db_path).ok();
    }
}
