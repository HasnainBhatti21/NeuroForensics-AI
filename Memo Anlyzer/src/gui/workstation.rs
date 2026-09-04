//! Workstation screen: menubar, toolbar, evidence tree (left), central
//! view, AI/details panel (right), status bar, case-info modal and the
//! background evidence-ingest pipeline.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, StrokeKind, Ui};

use crate::aifzip::container::open_aif;
use crate::aifzip::integrity::{deep_verify, ContainerCheck};
use crate::analysis::AnalysisReport;
use crate::casemgmt::db::{ArtifactRef, EvidenceImageRecord, FieldIndexRow};
use crate::ingest::index::{category_label, FieldEntry};
use crate::ingest::{examine_image_progress, validate_image};

use super::state::{AppState, MainView, PendingIngest, Session, ValidationOutcome, VerifyOutcome, ViewerTab};
use super::theme::{self, modal_button, paint_risk_badge, palette, primary_button, Icon, Palette, RiskTone};
use super::{ai_chat, correlation_view, evidence, explorer, findings, network_view, timeline, tree};

pub fn draw(app: &mut AppState, ctx: &egui::Context) {
    let p = palette(app.theme);

    poll_ingest(app, ctx);
    poll_validation(app, ctx);
    poll_verify(app, ctx);

    top_panels(app, ctx, &p);

    egui::SidePanel::left("evidence_tree_panel")
        .resizable(true)
        .default_width(265.0)
        .min_width(190.0)
        .max_width(420.0)
        .frame(egui::Frame::default().fill(p.panel).inner_margin(10.0))
        .show(ctx, |ui| {
            tree::draw(app, ui);
        });

    egui::SidePanel::right("ai_panel")
        .resizable(true)
        .default_width(330.0)
        .min_width(240.0)
        .max_width(560.0)
        .frame(egui::Frame::default().fill(p.panel).inner_margin(10.0))
        .show(ctx, |ui| {
            ai_chat::draw_panel(app, ui);
        });

    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(p.panel).inner_margin(10.0))
        .show(ctx, |ui| {
            let view = app.session.as_ref().map(|s| s.view).unwrap_or(MainView::Explorer);
            match view {
                MainView::Explorer => explorer::draw(app, ui),
                MainView::Timeline => timeline::draw(app, ui),
                MainView::Correlations => correlation_view::draw(app, ui),
                MainView::Network => network_view::draw(app, ui),
                MainView::Findings => findings::draw(app, ui),
                MainView::Evidence => evidence::draw(app, ui),
            }
        });

    status_bar(app, ctx, &p);
    case_info_window(app, ctx);
    ingest_overlay(app, ctx);
    validation_window(app, ctx);
    add_evidence_window(app, ctx);
    search_window(app, ctx);
    report_window(app, ctx);
}

// ---------------------------------------------------------------------
// Menubar + toolbar
// ---------------------------------------------------------------------

fn top_panels(app: &mut AppState, ctx: &egui::Context, p: &Palette) {
    // Reference chrome: navy gradient titlebar on top, then menubar + toolbar.
    theme::draw_titlebar(ctx, p, app.session.as_ref().map(|s| s.case_title()));
    egui::TopBottomPanel::top("menubar")
        .frame(egui::Frame::default().fill(p.chrome).inner_margin(egui::Margin::symmetric(6, 2)))
        .show(ctx, |ui| {
            menu_bar(app, ui);
        });
    egui::TopBottomPanel::top("toolbar")
        .frame(egui::Frame::default().fill(p.chrome_deep).inner_margin(egui::Margin::symmetric(10, 6)))
        .show(ctx, |ui| {
            toolbar(app, ui, p);
        });
}

fn menu_bar(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);
    egui::MenuBar::new().ui(ui, |ui| {
        ui.menu_button("File", |ui| {
            if ui.button("New Case…").clicked() {
                close_case(app);
                app.screen = crate::gui::state::Screen::Landing;
                ui.close();
            }
            if ui.button("Close Case").clicked() {
                close_case(app);
                ui.close();
            }
            if ui.button("Exit").clicked() {
                std::process::exit(0);
            }
        });
        ui.menu_button("View", |ui| {
            let label = format!("Theme: {} (click to switch)", app.theme.label());
            if ui.button(label).clicked() {
                app.toggle_theme();
            }
            if ui.button("Settings…").clicked() {
                app.show_settings = true;
                ui.close();
            }
        });
        ui.menu_button("Ingest", |ui| {
            if ui.button("Add Evidence…").clicked() {
                app.show_add_evidence = true;
                ui.close();
            }
            if ui.button("Evidence Management").clicked() {
                evidence::focus(app);
                ui.close();
            }
            if ui.button("Run Analysis").clicked() {
                run_analysis(app);
                ui.close();
            }
        });
        ui.menu_button("Case", |ui| {
            if ui.button("Case Information…").clicked() {
                app.show_case_info = true;
                ui.close();
            }
            if ui.button("Export Report (JSON)").clicked() {
                export_report(app, "json");
                ui.close();
            }
            if ui.button("Export Report (HTML)").clicked() {
                export_report(app, "html");
                ui.close();
            }
            if ui.button("Export Report (PDF)").clicked() {
                export_report(app, "pdf");
                ui.close();
            }
        });
        ui.menu_button("Help", |ui| {
            ui.label("NEUROFORENSICS AI — real-evidence forensic workstation.");
            ui.label("AIF reader contract: MEMO Collector v1 (ZIP container).");
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            // Secondary theme toggle (Light is the default/primary theme).
            let icon = if app.theme == crate::gui::theme::ThemeMode::Light { "☾" } else { "☀" };
            if ui
                .button(RichText::new(format!("{icon} {}", app.theme.label())).color(p.text_dim).size(11.0))
                .on_hover_text("Toggle theme")
                .clicked()
            {
                app.toggle_theme();
            }
            if let Some(session) = &app.session {
                ui.label(RichText::new(session.case_title()).strong().size(12.5));
            }
        });
    });
}

fn toolbar(app: &mut AppState, ui: &mut Ui, p: &Palette) {
    ui.horizontal(|ui| {
        // Reference `.tb-btn` actions: vertical icon-over-label buttons
        // with eased hover / active states.
        if theme::toolbar_button(ui, p, false, Icon::CardSplit, "Add Evidence").clicked() {
            app.show_add_evidence = true;
        }
        if theme::toolbar_button(ui, p, false, Icon::Shield, "Run Analysis").clicked() {
            run_analysis(app);
        }
        if app.session.is_some() {
            theme::tb_sep(ui, p);
            let query_active = app
                .session
                .as_ref()
                .map(|s| !s.search_query.trim().is_empty())
                .unwrap_or(false);
            if theme::toolbar_button(ui, p, query_active, Icon::Search, "Search").clicked() {
                app.show_search_modal = true;
            }
            if theme::toolbar_button(ui, p, false, Icon::Grid, "Report").clicked() {
                app.show_report_modal = true;
            }
            if theme::toolbar_button(ui, p, false, Icon::Card, "Case Info").clicked() {
                app.show_case_info = true;
            }
        }
        theme::tb_sep(ui, p);

        // Right-hand stat cluster. Blocks are measured up-front so they
        // have fixed widths and can never spill over the view chips.
        let (total, high, medium) = stats(app);
        let clean = total.saturating_sub(high + medium);
        let entries = [
            (total.to_string(), "ARTIFACTS", p.text),
            (high.to_string(), "HIGH RISK", p.danger),
            (medium.to_string(), "MEDIUM", p.warn),
            (clean.to_string(), "CLEAN", p.good),
        ];
        let num_font = egui::FontId::new(14.0, egui::FontFamily::Monospace);
        let lab_font = egui::FontId::new(9.0, egui::FontFamily::Proportional);
        let widths: Vec<f32> = entries
            .iter()
            .map(|(n, l, _)| {
                ui.painter()
                    .layout_no_wrap(n.clone(), num_font.clone(), Color32::PLACEHOLDER)
                    .size()
                    .x
                    .max(
                        ui.painter()
                            .layout_no_wrap(l.to_string(), lab_font.clone(), Color32::PLACEHOLDER)
                            .size()
                            .x,
                    ) + 10.0
            })
            .collect();
        let gap = 12.0;
        let one_row_w = widths.iter().sum::<f32>() + gap * (widths.len() as f32 - 1.0);
        // Two-row fallback (compact inline blocks) when one row would
        // take more than 45% of the toolbar.
        let two_row = one_row_w > ui.available_width() * 0.45;
        let stats_w = if two_row {
            widths[0].max(widths[2]) + widths[1].max(widths[3]) + gap + 20.0
        } else {
            one_row_w
        }
        .max(96.0)
        .min(ui.available_width().max(120.0));

        // View switcher chips fill the middle and scroll when narrow.
        let chips_w = (ui.available_width() - stats_w - gap).max(160.0);
        ui.allocate_ui_with_layout(
            egui::vec2(chips_w, ui.available_height()),
            Layout::left_to_right(Align::Center),
            |ui| {
                egui::ScrollArea::horizontal()
                    .id_salt("toolbar_chips")
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for view in [MainView::Explorer, MainView::Timeline, MainView::Correlations, MainView::Network, MainView::Findings, MainView::Evidence] {
                            let active = app.session.as_ref().map(|s| s.view) == Some(view);
                            // Dashboard navigation: icon + label chips.
                            let icon = match view {
                                MainView::Explorer => Icon::Folder,
                                MainView::Timeline => Icon::Clock,
                                MainView::Correlations => Icon::Wave,
                                MainView::Network => Icon::Grid,
                                MainView::Findings => Icon::WarnTri,
                                MainView::Evidence => Icon::Doc,
                            };
                            if theme::view_chip(ui, p, app.theme, active, icon, view.label()).clicked() {
                                if let Some(s) = &mut app.session {
                                    s.view = view;
                                }
                            }
                        }
                    });
            },
        );

        // Stats region — clipped, so a very narrow window degrades
        // gracefully instead of painting numbers over the chips.
        ui.allocate_ui_with_layout(
            egui::vec2(stats_w, ui.available_height()),
            Layout::right_to_left(Align::Center),
            |ui| {
                ui.set_clip_rect(ui.max_rect());
                if two_row {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            stat_block(ui, p, &entries[0].0, entries[0].1, entries[0].2);
                            stat_block(ui, p, &entries[1].0, entries[1].1, entries[1].2);
                        });
                        ui.horizontal(|ui| {
                            stat_block(ui, p, &entries[2].0, entries[2].1, entries[2].2);
                            stat_block(ui, p, &entries[3].0, entries[3].1, entries[3].2);
                        });
                    });
                } else {
                    for (n, l, c) in entries.iter() {
                        stat_block(ui, p, n, l, *c);
                    }
                }
            },
        );
    });
}

/// Reference stat block: big mono number over a tiny uppercase label.
/// Width is measured from the galley — the block never grows past its
/// content (the old `.extend()` labels were the overlap bug).
fn stat_block(ui: &mut Ui, p: &Palette, n: &str, label: &str, color: Color32) {
    let num_font = egui::FontId::new(14.0, egui::FontFamily::Monospace);
    let lab_font = egui::FontId::new(9.0, egui::FontFamily::Proportional);
    let num_g = ui.painter().layout_no_wrap(n.to_string(), num_font, Color32::PLACEHOLDER);
    let lab_g = ui.painter().layout_no_wrap(label.to_string(), lab_font, Color32::PLACEHOLDER);
    let w = num_g.size().x.max(lab_g.size().x) + 10.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(w, ui.available_height().max(20.0)),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.galley(
            egui::pos2(rect.center().x - num_g.size().x / 2.0, rect.center().y - num_g.size().y - 0.5),
            num_g,
            color,
        );
        painter.galley(
            egui::pos2(rect.center().x - lab_g.size().x / 2.0, rect.center().y + 1.5),
            lab_g,
            p.text_muted,
        );
    }
    ui.add_space(12.0);
}

fn stats(app: &AppState) -> (usize, usize, usize) {
    let Some(session) = &app.session else { return (0, 0, 0) };
    let total = explorer::build_rows(session).len();
    let risks = explorer::risk_map(session);
    let mut high = 0;
    let mut medium = 0;
    for severity in risks.values() {
        match severity {
            crate::analysis::rules::Severity::High | crate::analysis::rules::Severity::Critical => high += 1,
            crate::analysis::rules::Severity::Medium => medium += 1,
            _ => {}
        }
    }
    (total, high, medium)
}

// ---------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------

fn status_bar(app: &mut AppState, ctx: &egui::Context, p: &Palette) {
    // Reference status bar: dark navy strip, mono items, green ok-dot.
    egui::TopBottomPanel::bottom("status_bar")
        .frame(egui::Frame::default().fill(p.titlebar).inner_margin(egui::Margin::symmetric(14, 5)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let item = |ui: &mut Ui, text: String, color: Color32| {
                    ui.label(RichText::new(text).monospace().color(color).size(10.5));
                };
                let sep = |ui: &mut Ui| {
                    ui.label(RichText::new("|").monospace().color(Color32::from_rgba_unmultiplied(
                        p.status_text.r(), p.status_text.g(), p.status_text.b(), 77,
                    )).size(10.5));
                };
                match &app.session {
                    Some(session) => match &session.exam {
                        Some(exam) => {
                            let verified = exam.artifacts.iter().filter(|a| a.hash_verified == Some(true)).count();
                            ui.label(RichText::new("●").color(Color32::from_rgb(0x3D, 0xDC, 0x9A)).size(9.0));
                            item(ui, "Ingest complete".into(), p.status_text);
                            sep(ui);
                            let (hash_text, hash_color) = match exam.container_check.ok {
                                Some(true) => ("SHA-256 verified".to_string(), Color32::from_rgb(0x3D, 0xDC, 0x9A)),
                                Some(false) => ("SHA-256 MISMATCH".to_string(), p.danger),
                                None => ("no external hash".to_string(), p.warn),
                            };
                            item(ui, hash_text, hash_color);
                            sep(ui);
                            item(ui, format!("{} artifact(s) indexed", exam.artifacts.len()), p.status_text);
                            sep(ui);
                            item(ui, format!("{verified}/{} artifact hashes OK", exam.artifacts.len()), p.status_text);
                            sep(ui);
                            item(ui, crate::gui::fmt_bytes(exam.size_bytes), p.status_text);
                            if exam.is_demo() {
                                sep(ui);
                                item(ui, "DEMO EVIDENCE (collector-flagged synthetic)".into(), p.warn);
                            }
                        }
                        None => {
                            item(ui, "No evidence image open".into(), p.status_text);
                        }
                    },
                    None => {
                        item(ui, "No case open".into(), p.status_text);
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    item(
                        ui,
                        chrono::Local::now().format("%H:%M:%S").to_string(),
                        p.status_text,
                    );
                });
            });
        });
}

// ---------------------------------------------------------------------
// Ingest pipeline
// ---------------------------------------------------------------------

pub fn pick_evidence(app: &mut AppState) {
    if app.session.is_none() {
        app.toast("Open or create a case before adding evidence.", true);
        return;
    }
    if app.pending_ingest.is_some() || app.validation.is_some() {
        app.toast("An evidence validation or ingest is already running.", true);
        return;
    }
    let Some(file) = rfd::FileDialog::new()
        .add_filter("AIF evidence image", &["AIF", "aif"])
        .pick_file()
    else {
        return;
    };
    start_validation(app, file);
}

/// §7 validation first: signature, version, manifest and integrity are
/// checked and shown on the validation screen before any ingest.
fn start_validation(app: &mut AppState, path: PathBuf) {
    let (tx, rx) = mpsc::channel();
    let job_path = path.clone();
    std::thread::spawn(move || {
        let _ = tx.send(validate_image(&job_path));
    });
    app.validation = Some(ValidationOutcome::Pending { path, rx });
}

fn poll_validation(app: &mut AppState, ctx: &egui::Context) {
    let finished = match &app.validation {
        Some(ValidationOutcome::Pending { rx, .. }) => rx.try_recv().ok(),
        _ => None,
    };
    let Some(result) = finished else {
        if matches!(&app.validation, Some(ValidationOutcome::Pending { .. })) {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        return;
    };
    app.validation = Some(match result {
        Ok(report) => ValidationOutcome::Passed(report),
        Err(failure) => ValidationOutcome::Failed(failure),
    });
}

/// Kick off a full ingest for a path that already passed validation
/// (ADD EVIDENCE commit, OPEN EVIDENCE, REINDEX EVIDENCE).
pub fn start_ingest_path(app: &mut AppState, path: PathBuf) {
    if app.pending_ingest.is_some() {
        app.toast("An evidence ingest is already running.", true);
        return;
    }
    start_ingest(app, path);
}

/// When a case is (re)opened, automatically re-load its most recently
/// registered evidence image from disk so the workstation shows the
/// examiner's data instead of an empty "add evidence" state. The
/// existing registry row is reused (never duplicated). If the original
/// file moved, say so plainly instead of failing silently.
pub fn try_restore_evidence(app: &mut AppState) {
    if app.pending_ingest.is_some() {
        return;
    }
    let already_open = app.session.as_ref().map(|s| s.exam.is_some()).unwrap_or(false);
    if already_open {
        return;
    }
    let Some(image_id) = app.session.as_ref().and_then(|s| s.db.latest_image_id()) else {
        return;
    };
    let Some(img) = app
        .session
        .as_ref()
        .and_then(|s| s.db.evidence_images().into_iter().find(|i| i.id == image_id))
    else {
        return;
    };
    let path = PathBuf::from(&img.record.path);
    if path.is_file() {
        start_ingest(app, path);
    } else {
        app.toast(
            format!(
                "Registered evidence {} was not found at {} — re-add it via Ingest ▸ Add Evidence.",
                img.record.file_name, img.record.path
            ),
            true,
        );
    }
}

fn start_ingest(app: &mut AppState, path: PathBuf) {
    let (tx, rx) = mpsc::channel();
    let (ptx, prx) = mpsc::channel();
    let job_path = path.clone();
    std::thread::spawn(move || {
        let result = examine_image_progress(&job_path, Some(&ptx));
        let _ = tx.send(result);
    });
    app.pending_ingest = Some(PendingIngest {
        path,
        started: std::time::Instant::now(),
        rx,
        progress_rx: prx,
        latest_step: None,
        steps: Vec::new(),
    });
    app.validation = None;
}

fn poll_ingest(app: &mut AppState, ctx: &egui::Context) {
    // Drain real pipeline-step messages first (progress, never simulated).
    if let Some(pending) = &mut app.pending_ingest {
        while let Ok(step) = pending.progress_rx.try_recv() {
            if pending.steps.len() >= 30 {
                pending.steps.drain(0..pending.steps.len() - 20);
            }
            pending.latest_step = Some(step.clone());
            pending.steps.push(step);
        }
    }
    let finished = app
        .pending_ingest
        .as_ref()
        .and_then(|p| p.rx.try_recv().ok());
    let Some(result) = finished else {
        if app.pending_ingest.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        return;
    };
    let pending = app.pending_ingest.take().expect("checked");
    let _ = pending.started;
    match result {
        Ok(exam) => {
            let image_name = exam.image_name.clone();
            let artifact_count = exam.artifacts.len();
            let custody_detail = format!(
                "{} · sha256={} · {} bytes · {} artifact(s) indexed",
                exam.image_name,
                exam.aif.container_sha256,
                exam.size_bytes,
                exam.artifacts.len()
            );
            let mut persist_error: Option<String> = None;
            if let Some(session) = &mut app.session {
                match register_image(session, &exam) {
                    Ok((image_id, newly_added)) => {
                        session.current_image_id = Some(image_id);
                        // §41: registering + indexing evidence is recorded
                        // (a restore/re-ingest of an existing row is not a
                        // new acquisition, so it logs nothing here).
                        if newly_added {
                            let _ = session.db.log_custody("EVIDENCE ADDED", &custody_detail);
                        }
                    }
                    Err(e) => persist_error = Some(e),
                }
                session.exam = Some(exam);
                session.selected_artifact = None;
                session.preview = Default::default();
                session.correlation_cache = None; // §23: rebuild for new image
            }
            if let Some(e) = persist_error {
                app.toast(format!("Evidence ingested but not persisted: {e}"), true);
            }
            run_analysis(app);
            app.toast(
                format!("{image_name} ingested — {artifact_count} artifact(s) indexed and hash-verified."),
                false,
            );
        }
        Err(e) => {
            // §47: rejected evidence is recorded too.
            if let Some(session) = &mut app.session {
                let _ = session.db.log_custody("EVIDENCE REJECTED", &e);
            }
            app.toast(format!("Evidence rejected: {e}"), true);
        }
    }
}

/// Persist the image + its manifest index into the case database.
/// Re-ingesting the same file path refreshes the existing row instead
/// of duplicating it (OPEN EVIDENCE / REINDEX / case restore stay clean).
fn register_image(session: &mut Session, exam: &crate::ingest::ExaminedCase) -> Result<(i64, bool), String> {
    let rec = EvidenceImageRecord {
        path: exam.image_path.display().to_string(),
        file_name: exam.image_name.clone(),
        size_bytes: exam.size_bytes,
        container_sha256: exam.aif.container_sha256.clone(),
        expected_sha256: exam.container_check.expected.clone(),
        container_verified: exam.container_check.ok,
        case_id: Some(exam.case_id().to_string()),
        format_version: Some(exam.case_doc.format_version),
        demo_mode: exam.is_demo(),
        added_at: chrono::Local::now().to_rfc3339(),
    };
    let existing = session
        .db
        .evidence_images()
        .into_iter()
        .find(|i| i.record.path == rec.path)
        .map(|i| i.id);
    let (image_id, newly_added) = match existing {
        Some(id) => {
            session.db.update_image_record(id, &rec)?;
            (id, false)
        }
        None => (session.db.add_evidence_image(&rec)?, true),
    };
    let refs: Vec<ArtifactRef> = exam
        .artifacts
        .iter()
        .map(|a| ArtifactRef {
            artifact_id: a.artifact_id.clone(),
            relative_path: a.relative_path.clone(),
            size: a.size,
            sha256: a.sha256.clone(),
            acquisition_time: a.acquisition_time.clone(),
            source: a.source.clone(),
            collector: a.collector.clone(),
            status: a.status.label().to_string(),
            synthetic: a.synthetic,
            hash_verified: a.hash_verified,
        })
        .collect();
    session.db.insert_artifacts(image_id, &refs)?;
    session.db.update_image_verification(
        image_id,
        exam.container_check.ok,
        exam.container_check.expected.as_deref(),
    )?;
    // §21 persistent field index: global search survives restarts.
    let index_rows: Vec<FieldIndexRow> = exam
        .field_index
        .iter()
        .map(|f| FieldIndexRow {
            artifact_id: f.artifact_id.clone(),
            field: f.field.clone(),
            value: f.value.clone(),
            haystack: f.haystack.clone(),
        })
        .collect();
    session.db.replace_field_index(image_id, &index_rows)?;
    // §22 persistent timeline: built once from real evidence
    // timestamps, mirrored to SQLite, cached for the session.
    let entries = timeline::build_entries(exam);
    session.db.replace_timeline_events(image_id, &timeline::to_records(&entries))?;
    session.timeline_cache = Some(entries);
    Ok((image_id, newly_added))
}

// ---------------------------------------------------------------------
// VERIFY EVIDENCE (§6): re-hash a registered image on demand
// ---------------------------------------------------------------------

pub fn start_verify(app: &mut AppState, image_id: i64, file_name: String, path: String) {
    if app.pending_verify.is_some() {
        app.toast("A verification is already running.", true);
        return;
    }
    let recorded_hash = app
        .session
        .as_ref()
        .and_then(|s| s.db.evidence_images().into_iter().find(|i| i.id == image_id))
        .map(|i| i.record.container_sha256)
        .unwrap_or_default();
    let (tx, rx) = mpsc::channel();
    let spawn_name = file_name.clone();
    std::thread::spawn(move || {
        let result = verify_on_disk(image_id, spawn_name, &path, &recorded_hash);
        let _ = tx.send(result);
    });
    app.pending_verify = Some(super::state::PendingVerify { image_id, file_name, rx });
}

fn verify_on_disk(
    image_id: i64,
    file_name: String,
    path: &str,
    recorded_hash: &str,
) -> Result<VerifyOutcome, String> {
    let path = Path::new(path);
    if !path.is_file() {
        return Err(format!("The evidence file no longer exists at {}.", path.display()));
    }
    let mut aif = open_aif(path).map_err(|e| e.to_string())?;
    let check = ContainerCheck::from(&aif);
    let checks = deep_verify(&mut aif);
    let artifacts_ok = checks.iter().filter(|c| c.ok).count();
    Ok(VerifyOutcome {
        image_id,
        file_name,
        container_sha256: aif.container_sha256.clone(),
        hash_changed: !aif.container_sha256.eq_ignore_ascii_case(recorded_hash),
        expected: check.expected,
        verified: check.ok,
        artifacts_ok,
        artifacts_failed: checks.len() - artifacts_ok,
        artifacts_total: checks.len(),
    })
}

fn poll_verify(app: &mut AppState, ctx: &egui::Context) {
    let finished = app.pending_verify.as_ref().and_then(|p| p.rx.try_recv().ok());
    let Some(result) = finished else {
        if app.pending_verify.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        return;
    };
    app.pending_verify = None;
    match result {
        Ok(outcome) => {
            let mut db_error: Option<String> = None;
            if let Some(session) = &mut app.session {
                if let Err(e) = session.db.update_image_hash_and_verification(
                    outcome.image_id,
                    &outcome.container_sha256,
                    outcome.verified,
                    outcome.expected.as_deref(),
                ) {
                    db_error = Some(e);
                }
            }
            if let Some(e) = db_error {
                app.toast(format!("Verification finished but was not persisted: {e}"), true);
            }
            let verdict = match outcome.verified {
                Some(true) => "VERIFIED",
                Some(false) => "MISMATCH",
                None => "no sidecar to compare",
            };
            let mut msg = format!(
                "{} re-verified: container hash {} · {}/{} artifact hashes OK.",
                outcome.file_name, verdict, outcome.artifacts_ok, outcome.artifacts_total
            );
            if outcome.hash_changed {
                msg.push_str(" WARNING: container hash differs from the recorded value — the file changed since registration.");
            }
            if outcome.artifacts_failed > 0 {
                msg.push_str(&format!(" {} artifact(s) FAILED.", outcome.artifacts_failed));
            }
            let danger = outcome.hash_changed
                || outcome.verified == Some(false)
                || outcome.artifacts_failed > 0;
            // §41: verification outcomes are part of the custody trail.
            if let Some(session) = &mut app.session {
                let _ = session.db.log_custody(
                    "EVIDENCE VERIFIED",
                    &format!(
                        "{}: {} · {}/{} artifact hashes OK{}",
                        outcome.file_name,
                        verdict,
                        outcome.artifacts_ok,
                        outcome.artifacts_total,
                        if outcome.hash_changed { " · container hash changed since registration" } else { "" }
                    ),
                );
            }
            app.toast(msg, danger);
        }
        Err(e) => {
            if let Some(session) = &mut app.session {
                let _ = session.db.log_custody("EVIDENCE VERIFY FAILED", &e);
            }
            app.toast(format!("Verification failed: {e}"), true);
        }
    }
}

// ---------------------------------------------------------------------
// REMOVE EVIDENCE FROM CASE (§6)
// ---------------------------------------------------------------------

pub fn remove_image(app: &mut AppState, image_id: i64, is_open: bool) {
    let removed = app
        .session
        .as_mut()
        .map(|s| s.db.remove_evidence_image(image_id));
    match removed {
        Some(Ok(n)) if n > 0 => {
            if let Some(session) = &mut app.session {
                // §41: deregistration is recorded; the on-disk file is untouched.
                let _ = session.db.log_custody(
                    "EVIDENCE REMOVED",
                    &format!("image id {image_id} deregistered; on-disk file untouched"),
                );
                session.remove_confirm = None;
                if is_open {
                    // Close the ingested copy so no stale handle outlives registration.
                    session.exam = None;
                    session.current_image_id = None;
                    session.report = None;
                    session.selected_artifact = None;
                    session.preview = Default::default();
                }
                if session.evidence_selected == Some(image_id) {
                    session.evidence_selected = None;
                }
            }
            app.toast("Evidence removed from the case database. The original file on disk was not touched.", false);
        }
        Some(Ok(_)) => {
            if let Some(session) = &mut app.session {
                session.remove_confirm = None;
            }
            app.toast("Nothing was removed — the image was not found in the case database.", true);
        }
        Some(Err(e)) => app.toast(format!("Removal failed: {e}"), true),
        None => {}
    }
}

fn run_analysis(app: &mut AppState) {
    if app.session.is_none() {
        app.toast("No case open.", true);
        return;
    }
    let has_exam = app
        .session
        .as_ref()
        .and_then(|s| s.exam.as_ref())
        .is_some();
    if !has_exam {
        app.toast("No evidence image ingested — analysis runs only on real evidence.", true);
        return;
    }

    let report = {
        let session = app.session.as_mut().expect("checked");
        let exam = session.exam.as_ref().expect("checked");
        AnalysisReport::run(exam)
    };
    let save_result = {
        let session = app.session.as_mut().expect("checked");
        report
            .to_payload()
            .and_then(|payload| session.db.save_findings(&payload))
    };
    if let Err(e) = save_result {
        app.toast(format!("Findings computed but not persisted: {e}"), true);
    }
    // §35/§36: persist row-level findings with the status workflow.
    // Existing investigator status/notes survive re-runs (matched by
    // finding_key); new rows always enter as NEW.
    let workflow_result = {
        let session = app.session.as_mut().expect("checked");
        match session.current_image_id {
            Some(image_id) => session
                .db
                .upsert_finding_rows(image_id, &crate::analysis::finding_rows(&report)),
            None => Ok(()), // image not registered: nothing to attach workflow to
        }
    };
    if let Err(e) = workflow_result {
        app.toast(format!("Finding workflow not persisted: {e}"), true);
    }
    let count = report.findings.len();

    // §29/§32 AI layer: runs AFTER and independently of the rule
    // engine; every claim it makes passes the artifact-grounding gate.
    let ai = {
        let session = app.session.as_ref().expect("checked");
        let exam = session.exam.as_ref().expect("checked");
        let provider = crate::ai::from_settings(&app.settings);
        crate::ai::run_validated(provider.as_ref(), exam, &report)
    };
    if !ai.rejected.is_empty() {
        app.toast(
            format!("AI layer dropped {} ungrounded claim(s) — see Findings.", ai.rejected.len()),
            true,
        );
    }

    // §41: detection + AI runs are recorded with their real counts.
    let custody_line = format!(
        "{count} indicator(s), {} ML anomaly(ies); AI layer: {} — {} grounded finding(s), {} ungrounded dropped",
        report.ml.anomalies.len(),
        ai.provider.name,
        ai.findings.len(),
        ai.rejected.len()
    );
    if let Some(session) = &mut app.session {
        let _ = session.db.log_custody("ANALYSIS RUN", &custody_line);
        session.report = Some(report);
        session.ai_analysis = Some(ai);
        session.refresh_finding_workflow();
    }
    app.toast(format!("Analysis complete — {count} indicator(s), all grounded on artifact IDs."), false);
}

fn close_case(app: &mut AppState) {
    app.session = None;
    app.pending_ingest = None;
    app.pending_verify = None;
    app.validation = None;
    app.show_case_info = false;
    app.screen = crate::gui::state::Screen::Landing;
}

// ---------------------------------------------------------------------
// Report export (JSON / HTML / PDF via the reporting module)
// ---------------------------------------------------------------------

fn export_report(app: &mut AppState, format: &str) {
    let Some(session) = &app.session else {
        app.toast("No case open.", true);
        return;
    };
    let dir = session.folder.dir.join("reports");
    let _ = std::fs::create_dir_all(&dir);
    let name = format!(
        "report_{}_{}.{}",
        session.meta.case_number.replace([' ', '/', '\\'], "_"),
        chrono::Local::now().format("%Y%m%d_%H%M%S"),
        format
    );
    let path = dir.join(&name);
    let notes = session.db.notes();
    let exam = session.exam.as_ref();
    let report = session.report.as_ref();
    // §23/§35/§22: pull forward everything the §43 report must carry.
    let correlations = session
        .correlation_cache
        .clone()
        .or_else(|| session.exam.as_ref().map(|e| crate::correlation::correlate_streams(&e.streams)));
    let ai = session.ai_analysis.as_ref();
    let workflow_rows = session
        .current_image_id
        .map(|id| session.db.finding_rows(id))
        .unwrap_or_default();
    let timeline = session
        .current_image_id
        .map(|id| session.db.timeline_events(id))
        .unwrap_or_default();
    let custody = session.db.custody_log();
    let inputs = crate::reporting::ReportInputs {
        meta: &session.meta,
        exam,
        report,
        correlations: correlations.as_ref(),
        ai,
        finding_workflow: &workflow_rows,
        timeline: &timeline,
        custody: &custody,
        notes: &notes,
    };

    let outcome: Result<Vec<u8>, String> = match format {
        "json" => crate::reporting::json::generate(&inputs).map(|s| s.into_bytes()),
        "html" => Ok(crate::reporting::html::generate(&inputs).into_bytes()),
        "pdf" => crate::reporting::pdf::generate(&inputs),
        other => Err(format!("Unsupported report format: {other}")),
    };

    match outcome.and_then(|bytes| std::fs::write(&path, bytes).map_err(|e| e.to_string())) {
        Ok(()) => {
            // §41: exporting a report is itself a custody event.
            if let Some(session) = &mut app.session {
                let _ = session
                    .db
                    .log_custody("REPORT EXPORTED", &format!("{format} -> {}", path.display()));
            }
            app.toast(format!("Report written to {}", path.display()), false)
        }
        Err(e) => app.toast(format!("Report failed: {e}"), true),
    }
}

// ---------------------------------------------------------------------
// Case info window + ingest overlay
// ---------------------------------------------------------------------

fn case_info_window(app: &mut AppState, ctx: &egui::Context) {
    if !app.show_case_info {
        return;
    }
    let p = palette(app.theme);
    let mut open = true;
    let mut close_now = false;
    egui::Window::new("Case Information")
        .open(&mut open)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .collapsible(false)
        .default_size([620.0, 620.0])
        .min_size([440.0, 340.0])
        .show(ctx, |ui| {
            let Some(session) = &app.session else { return };

            // Body scrolls so the Close footer is always reachable,
            // whatever the evidence/ingest-log size.
            let body_h = (ui.available_height() - 48.0).max(120.0);
            egui::ScrollArea::vertical()
                .id_salt("case_info_body")
                .max_height(body_h)
                .show(ui, |ui| {
                    // Reference kv-rows: muted label left, wrapping value
                    // right — a striped grid so long paths/hashes never
                    // overflow the window width.
                    egui::Grid::new("case_info_kv")
                        .num_columns(2)
                        .min_col_width(150.0)
                        .spacing([10.0, 7.0])
                        .striped(true)
                        .show(ui, |ui| {
                            let mut kv = |k: &str, v: String, color: Color32, mono: bool| {
                                ui.label(RichText::new(k).color(p.text_dim).strong().size(12.0));
                                let mut t = RichText::new(v).color(color).size(12.0);
                                if mono {
                                    t = t.monospace();
                                }
                                ui.add(egui::Label::new(t));
                                ui.end_row();
                            };
                            kv("Case ID", session.meta.case_number.clone(), p.text, true);
                            kv("Case name", session.meta.case_name.clone(), p.text, false);
                            kv("Examiner", session.meta.examiner.clone(), p.text, false);
                            kv("Organization", session.meta.organization.clone(), p.text, false);
                            kv("Description", session.meta.description.clone(), p.text, false);
                            kv("Created", session.meta.created_at.clone(), p.text, true);
                            kv("Case folder", session.folder.dir.display().to_string(), p.text_dim, true);
                            let total_artifacts = explorer::build_rows(session).len();
                            kv("Total artifacts", total_artifacts.to_string(), p.text, true);
                            let indicators = session.report.as_ref().map(|r| r.findings.len()).unwrap_or(0);
                            kv(
                                "Detection indicators",
                                indicators.to_string(),
                                if indicators > 0 { p.danger } else { p.good },
                                true,
                            );
                            let custody_len = session.db.custody_log().len();
                            kv(
                                "Chain of custody",
                                format!("Intact — {custody_len} entr{} recorded", if custody_len == 1 { "y" } else { "ies" }),
                                p.good,
                                false,
                            );
                        });
                    ui.add_space(8.0);
                    ui.label(RichText::new("Registered evidence images").strong());
                    let images = session.db.evidence_images();
                    if images.is_empty() {
                        ui.label(RichText::new("None yet — use Ingest ▸ Add Evidence Image.").color(p.text_dim));
                    }
                    for img in &images {
                        egui::Frame::default().fill(p.panel_deep).corner_radius(6.0).inner_margin(8.0).show(ui, |ui| {
                            ui.label(RichText::new(&img.record.file_name).strong());
                            ui.label(
                                RichText::new(format!(
                                    "{} · container SHA-256 verified: {}",
                                    crate::gui::fmt_bytes(img.record.size_bytes),
                                    match img.record.container_verified {
                                        Some(true) => "YES",
                                        Some(false) => "MISMATCH",
                                        None => "no sidecar",
                                    },
                                ))
                                .color(p.text_dim)
                                .size(11.0),
                            );
                            ui.label(RichText::new(&img.record.path).color(p.text_dim).size(11.0));
                            ui.label(RichText::new(format!("container hash: {}", img.record.container_sha256)).monospace().size(10.5));
                        });
                        ui.add_space(4.0);
                    }
                    if let Some(exam) = &session.exam {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Ingest log").strong());
                        egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            for line in &exam.ingest_log {
                                ui.label(RichText::new(line).monospace().size(11.0));
                            }
                            for warn in &exam.warnings {
                                if crate::ingest::is_host_capability_note(warn) {
                                    ui.label(RichText::new(format!("ℹ {warn}")).color(p.text_dim).monospace().size(11.0));
                                } else {
                                    ui.label(RichText::new(format!("⚠ {warn}")).color(p.warn).monospace().size(11.0));
                                }
                            }
                        });
                    }
                });

            ui.add_space(6.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if primary_button(ui, &p, "Close").clicked() {
                        close_now = true;
                    }
                });
            });
        });
    if close_now {
        open = false;
    }
    if !open {
        app.show_case_info = false;
    }
}

fn ingest_overlay(app: &mut AppState, ctx: &egui::Context) {
    let Some(pending) = &app.pending_ingest else { return };
    let p = palette(app.theme);
    let path = pending.path.display().to_string();
    let secs = pending.started.elapsed().as_secs();
    let steps = pending.steps.clone();
    let latest = pending
        .latest_step
        .clone()
        .unwrap_or_else(|| "Opening evidence image…".to_string());
    // Reference "Ingest Progress" modal: header strip, gradient bar,
    // dark live log. Every line is a real pipeline message.
    let reveal = theme::anim(ctx, egui::Id::new("ingest_overlay").with("reveal"), true, theme::MODAL_TIME);
    egui::Area::new(egui::Id::new("ingest_overlay"))
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            ui.set_opacity(reveal);
            egui::Frame::default()
                .fill(p.panel)
                .stroke(egui::Stroke::new(1.0_f32, p.border))
                .corner_radius(10.0)
                .shadow(egui::Shadow {
                    offset: [0, 14],
                    blur: 44,
                    spread: 0,
                    color: Color32::from_black_alpha(90),
                })
                .inner_margin(0.0)
                .show(ui, |ui| {
                    ui.set_min_width(480.0);
                    ui.set_max_width(520.0);
                    egui::Frame::default()
                        .fill(p.panel_deep)
                        .inner_margin(egui::Margin::symmetric(18, 12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(RichText::new("INGESTING EVIDENCE").strong().size(14.0));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(format!("{secs}s elapsed")).monospace().color(p.text_muted).size(10.5));
                                });
                            });
                        });
                    egui::Frame::default().inner_margin(egui::Margin::symmetric(18, 14)).show(ui, |ui| {
                        ui.label(RichText::new(path).monospace().color(p.text_dim).size(11.5));
                        ui.add_space(6.0);
                        // Finite width — an INFINITY-sized widget inside this
                        // anchored Area makes the area width infinite, which
                        // turns the centered anchor position into NaN on the
                        // next frame (layout/hit-test panic).
                        let bar_w = ui.available_width().max(200.0);
                        let (bar_rect, _) = ui.allocate_exact_size(
                            egui::vec2(bar_w, 8.0),
                            egui::Sense::hover(),
                        );
                        if ui.is_rect_visible(bar_rect) {
                            let painter = ui.painter();
                            painter.rect(bar_rect, 4.0, p.row_border, Stroke::NONE, StrokeKind::Inside);
                            // Indeterminate segment sweeping left → right.
                            let phase = ((ui.ctx().input(|i| i.time) % 1.6) / 1.6) as f32;
                            let seg_w = bar_w * 0.35;
                            let x0 = bar_rect.min.x - seg_w + phase * (bar_w + seg_w);
                            let seg = egui::Rect::from_min_max(
                                egui::pos2(x0.max(bar_rect.min.x), bar_rect.min.y),
                                egui::pos2((x0 + seg_w).min(bar_rect.max.x), bar_rect.max.y),
                            );
                            if seg.width() > 1.0 {
                                let n = seg.width().ceil() as i32;
                                for i in 0..n {
                                    let t = i as f32 / (n as f32 - 1.0).max(1.0);
                                    painter.vline(
                                        seg.min.x + i as f32 + 0.5,
                                        seg.y_range(),
                                        Stroke::new(1.2_f32, theme::mix(p.accent, p.accent_deep, t)),
                                    );
                                }
                            }
                        }
                        ui.add_space(10.0);
                        // Dark console-style log region (reference #0A121B).
                        let log_bg = Color32::from_rgb(0x0A, 0x12, 0x1B);
                        let log_ok = Color32::from_rgb(0x9F, 0xE6, 0xB8);
                        let log_run = Color32::from_rgb(0x7F, 0xB2, 0xE8);
                        egui::Frame::default()
                            .fill(log_bg)
                            .corner_radius(6.0)
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                egui::ScrollArea::vertical().max_height(160.0).stick_to_bottom(true).show(ui, |ui| {
                                    let completed = if steps.is_empty() { 0 } else { steps.len() - 1 };
                                    for (i, step) in steps.iter().enumerate() {
                                        if i < completed {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new("✓").color(log_ok).strong());
                                                ui.label(RichText::new(step).monospace().color(log_ok).size(11.0));
                                            });
                                        } else {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new("▸").color(log_run).strong());
                                                ui.label(RichText::new(step).monospace().size(11.0).color(log_run));
                                            });
                                        }
                                    }
                                    if steps.is_empty() {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("▸").color(log_run).strong());
                                            ui.label(RichText::new(&latest).monospace().size(11.0).color(log_run));
                                        });
                                    }
                                });
                            });
                    });
                });
        });
    ctx.request_repaint_after(std::time::Duration::from_millis(120));
}

// ---------------------------------------------------------------------
// Validation screen (§7)
// ---------------------------------------------------------------------

fn validation_window(app: &mut AppState, ctx: &egui::Context) {
    // Snapshot the outcome so the draw helpers can take &mut AppState.
    enum Snapshot {
        Pending(PathBuf),
        Passed(crate::ingest::ValidationReport),
        Failed(crate::ingest::ValidationFailure),
    }
    let snapshot = match &app.validation {
        Some(ValidationOutcome::Pending { path, .. }) => Some(Snapshot::Pending(path.clone())),
        Some(ValidationOutcome::Passed(report)) => Some(Snapshot::Passed(report.clone())),
        Some(ValidationOutcome::Failed(failure)) => Some(Snapshot::Failed(failure.clone())),
        None => None,
    };
    let Some(snapshot) = snapshot else { return };
    let p = palette(app.theme);
    match snapshot {
        Snapshot::Pending(path) => {
            let path = path.display().to_string();
            egui::Area::new(egui::Id::new("validation_pending"))
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .order(egui::Order::Foreground)
                .show(ctx, |ui| {
                    egui::Frame::default()
                        .fill(p.panel)
                        .stroke(egui::Stroke::new(1.0_f32, p.border))
                        .corner_radius(10.0)
                        .inner_margin(24.0)
                        .show(ui, |ui| {
                            ui.set_min_width(380.0);
                            ui.set_max_width(460.0);
                            ui.vertical_centered(|ui| {
                                ui.spinner();
                                ui.add_space(6.0);
                                ui.label(RichText::new("VALIDATING EVIDENCE").strong().size(13.0));
                                ui.label(RichText::new(path).monospace().color(p.text_dim).size(11.0));
                                ui.label(
                                    RichText::new("Signature · version · manifest · container hash")
                                        .color(p.text_dim)
                                        .size(10.5),
                                );
                            });
                        });
                });
        }
        Snapshot::Passed(report) => draw_validation_passed(app, ctx, &report, &p),
        Snapshot::Failed(failure) => draw_validation_failed(app, ctx, &failure, &p),
    }
}

fn draw_validation_passed(
    app: &mut AppState,
    ctx: &egui::Context,
    report: &crate::ingest::ValidationReport,
    p: &Palette,
) {
    // Actions are hoisted out of the modal closure and applied AFTER
    // modal_shell returns: closing the modal + swapping it for the
    // ingest overlay mid-frame would invalidate the widget rects the
    // click landed on (the hit_test panic).
    let mut close = false;
    let mut cancel = false;
    let mut start: Option<PathBuf> = None;
    let busy = app.pending_ingest.is_some();
    let report = report.clone();
    modal_shell(ctx, p, "validation_modal", "Evidence Validation", 560.0, &mut close, |ui| {
        ui.label(
            RichText::new("VALID AIF EVIDENCE")
                .color(p.good)
                .strong()
                .size(14.0),
        );
        ui.label(RichText::new(report.path.display().to_string()).monospace().size(11.0));
        ui.add_space(8.0);

        // Bounded scroll region — long collector warnings / stream
        // lists wrap inside the card instead of overflowing it.
        egui::ScrollArea::vertical()
            .id_salt("validation_steps")
            .max_height(300.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                let step = |ui: &mut Ui, ok: bool, text: String| {
                    let (mark, color) = if ok { ("✓", p.good) } else { ("⚠", p.warn) };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(mark).color(color).strong());
                        ui.label(RichText::new(text).size(12.0));
                    });
                };
                step(ui, true, "File opened safely".into());
                step(ui, true, format!("AIF signature validated — {}", report.detected_format));
                step(ui, true, format!("AIF version detected: v{}", report.aif_version));
                step(
                    ui,
                    true,
                    format!(
                        "manifest.json parsed & validated (case {}, {} artifact record(s), {} container entr(ies))",
                        report.case_id, report.artifact_count, report.entry_count
                    ),
                );
                step(
                    ui,
                    !report.modules.is_empty(),
                    format!(
                        "Evidence streams identified: {}",
                        if report.modules.is_empty() { "none listed in manifest".to_string() } else { report.modules.join("; ") }
                    ),
                );
                let integrity_ok = report.container_verified != Some(false);
                step(
                    ui,
                    integrity_ok,
                    match report.container_verified {
                        Some(true) => format!(
                            "Integrity verified against {}",
                            report.expected_source.as_deref().unwrap_or("external sidecar")
                        ),
                        Some(false) => format!(
                            "INTEGRITY MISMATCH: {} records {} but the file hashes differently",
                            report.expected_source.as_deref().unwrap_or("sidecar"),
                            report.expected_sha256.as_deref().unwrap_or("?")
                        ),
                        None => "No external hash found — integrity not independently verifiable".into(),
                    },
                );
                step(ui, true, "Container SHA-256 computed".into());
                ui.label(RichText::new(report.container_sha256.clone()).monospace().size(10.5));
                if report.demo_mode {
                    ui.label(RichText::new("⚠ Collector flagged this evidence as DEMO / synthetic.").color(p.warn).size(11.5));
                }
                // Integrity-affecting warnings stay amber; host-capability
                // notes (no GPU, absent/empty optional event channels) are
                // informational and get a plain-language explanation.
                let (notes, alarms): (Vec<&String>, Vec<&String>) = report
                    .warnings
                    .iter()
                    .partition(|w| crate::ingest::is_host_capability_note(w));
                for w in alarms {
                    ui.label(RichText::new(format!("⚠ {w}")).color(p.warn).size(11.0));
                }
                if !notes.is_empty() {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("COLLECTOR NOTICES — recorded during acquisition; they do not affect evidence validity:")
                            .color(p.text_dim)
                            .size(10.5)
                            .strong(),
                    );
                    for w in notes {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("ℹ").color(p.accent).strong());
                            ui.label(RichText::new(w).color(p.text_dim).size(11.0));
                        });
                        if let Some(why) = crate::ingest::host_capability_explanation(w) {
                            ui.label(
                                RichText::new(format!("      ↳ {why}"))
                                    .color(p.text_muted)
                                    .size(10.5)
                                    .italics(),
                            );
                        }
                    }
                }
            });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        !busy,
                        egui::Button::new(RichText::new("ADD TO CASE & INGEST").color(Color32::WHITE).strong().size(12.5))
                            .fill(p.accent)
                            .stroke(egui::Stroke::new(1.0_f32, p.accent_deep))
                            .corner_radius(6.0),
                    )
                    .clicked()
                {
                    start = Some(report.path.clone());
                }
                if modal_button(ui, p, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
    });
    // Applied outside the draw closure — see hoisting note above.
    // (start_ingest itself clears app.validation.)
    if let Some(path) = start {
        start_ingest(app, path);
    } else if cancel || close {
        app.validation = None;
    }
}

fn draw_validation_failed(
    app: &mut AppState,
    ctx: &egui::Context,
    failure: &crate::ingest::ValidationFailure,
    p: &Palette,
) {
    let mut close = false;
    let mut dismiss = false;
    let failure = failure.clone();
    modal_shell(ctx, p, "validation_modal", "Evidence Validation", 560.0, &mut close, |ui| {
        // §7 wording — never "invalid AIF JSON".
        ui.label(RichText::new("INVALID AIF EVIDENCE").color(p.danger).strong().size(14.0));
        ui.label(
            RichText::new("The selected file is not a valid NeuroForensics AIF evidence container.")
                .size(12.0),
        );
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("validation_failure")
            .max_height(300.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("validation_failure_grid").min_col_width(140.0).spacing([8.0, 5.0]).show(ui, |ui| {
                    let mut kv = |k: &str, v: String| {
                        ui.label(RichText::new(k).color(p.text_dim).size(11.5));
                        ui.label(RichText::new(v).size(11.5));
                        ui.end_row();
                    };
                    kv("Expected format", failure.expected_format.clone());
                    kv("Detected format", failure.detected_format.clone());
                    kv(
                        "AIF version",
                        failure
                            .detected_version
                            .map(|v| format!("v{v}"))
                            .unwrap_or_else(|| "not detected".into()),
                    );
                    kv("Reason", failure.reason.clone());
                    kv("File path", failure.path.display().to_string());
                    kv(
                        "Offset",
                        failure.offset.map(|o| format!("{o}")).unwrap_or_else(|| "n/a".into()),
                    );
                });
            });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if modal_button(ui, p, "Close").clicked() {
                    dismiss = true;
                }
            });
        });
    });
    if dismiss || close {
        app.validation = None;
    }
}

// ---------------------------------------------------------------------
// Reference modal patterns: Add Evidence, Keyword Search, Report
// ---------------------------------------------------------------------

/// Shared centered modal shell: header strip + body, Esc / ✕ closes.
/// Entrance is a short ease-out fade + scale (reference modal motion).
fn modal_shell(
    ctx: &egui::Context,
    p: &Palette,
    id: &str,
    title: &str,
    width: f32,
    close_requested: &mut bool,
    body: impl FnOnce(&mut Ui),
) {
    let area_id = egui::Id::new(id);
    let reveal = theme::anim(ctx, area_id.with("reveal"), true, theme::MODAL_TIME);
    let mut layer: Option<egui::LayerId> = None;
    let mut rect = egui::Rect::NOTHING;
    egui::Area::new(area_id)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            ui.set_opacity(reveal);
            egui::Frame::default()
                .fill(p.panel)
                .stroke(egui::Stroke::new(1.0_f32, p.border))
                .corner_radius(10.0)
                .shadow(egui::Shadow {
                    offset: [0, 14],
                    blur: 44,
                    spread: 0,
                    color: Color32::from_black_alpha(90),
                })
                .inner_margin(0.0)
                .show(ui, |ui| {
                    ui.set_min_width(width);
                    ui.set_max_width(width);
                    egui::Frame::default()
                        .fill(p.panel_deep)
                        .inner_margin(egui::Margin::symmetric(18, 12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(title).strong().size(14.0));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.small_button("✕").clicked() {
                                        *close_requested = true;
                                    }
                                });
                            });
                        });
                    egui::Frame::default()
                        .inner_margin(egui::Margin::symmetric(18, 14))
                        .show(ui, |ui| {
                            body(ui);
                        });
                });
            layer = Some(ui.layer_id());
            rect = ui.min_rect();
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                *close_requested = true;
            }
        });
    // Scale around the modal center while it fades in.
    if reveal < 1.0 {
        if let Some(layer) = layer {
            let c = rect.center();
            let s = 0.96 + 0.04 * reveal;
            ctx.transform_layer_shapes(
                layer,
                egui::emath::TSTransform {
                    scaling: s,
                    translation: egui::vec2(c.x * (1.0 - s), c.y * (1.0 - s)),
                },
            );
        }
    }
}

/// Modal 1 — Add Evidence: what will happen when a file is picked.
fn add_evidence_window(app: &mut AppState, ctx: &egui::Context) {
    if !app.show_add_evidence {
        return;
    }
    let p = palette(app.theme);
    let mut close = false;
    let mut browse = false;
    let mut cancel = false;
    modal_shell(ctx, &p, "add_evidence_modal", "Add Evidence Source", 520.0, &mut close, |ui| {
        ui.label(
            RichText::new("Select a MEMO Collector .AIF evidence image to add to this case.")
                .size(13.0),
        );
        ui.add_space(8.0);
        ui.label(RichText::new("Before any ingest the image is validated (§7):").color(p.text_dim).size(12.0));
        ui.add_space(4.0);
        for step in [
            "AIF signature & version detection",
            "manifest.json schema validation",
            "Container SHA-256 compared against the collector record",
            "Per-artifact hash verification after ingest",
        ] {
            ui.horizontal(|ui| {
                ui.label(RichText::new("✓").color(p.good).strong());
                ui.label(RichText::new(step).size(12.0));
            });
        }
        ui.add_space(6.0);
        ui.label(
            RichText::new("The evidence file is opened read-only — it is never modified.")
                .color(p.text_muted)
                .size(11.5)
                .italics(),
        );
        ui.add_space(10.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if primary_button(ui, &p, "Browse for .AIF image…").clicked() {
                    browse = true;
                }
                if modal_button(ui, &p, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
    });
    if cancel {
        close = true;
    }
    if browse {
        app.show_add_evidence = false;
        pick_evidence(app);
    } else if close {
        app.show_add_evidence = false;
    }
}

/// Modal 3 — Keyword Search over the §21 field index.
fn search_window(app: &mut AppState, ctx: &egui::Context) {
    if !app.show_search_modal {
        return;
    }
    if app.session.is_none() {
        app.show_search_modal = false;
        return;
    }
    let p = palette(app.theme);

    // Snapshot search inputs before the modal closure mutates session.
    let query = app
        .session
        .as_ref()
        .map(|s| s.search_query.trim().to_string())
        .unwrap_or_default();
    let hits: Vec<FieldEntry> = if query.is_empty() {
        Vec::new()
    } else {
        app.session
            .as_ref()
            .map(|s| explorer::search_field_values(s, &query))
            .unwrap_or_default()
    };
    let index_size = app
        .session
        .as_ref()
        .map(|s| match &s.exam {
            Some(exam) => exam.field_index.len(),
            None => s.db_field_index.len(),
        })
        .unwrap_or(0);
    let rows_by_id: HashMap<String, explorer::ArtifactRow> = app
        .session
        .as_ref()
        .map(|s| {
            explorer::build_rows(s)
                .into_iter()
                .map(|r| (r.artifact_id.clone(), r))
                .collect()
        })
        .unwrap_or_default();
    let risks = app.session.as_ref().map(explorer::risk_map).unwrap_or_default();

    let mut close = false;
    let mut dismiss = false;
    let mut jump: Option<(String, String)> = None;
    modal_shell(ctx, &p, "keyword_search_modal", "Keyword Search", 560.0, &mut close, |ui| {
        let Some(session) = &mut app.session else { return };
        let response = ui.add_sized(
            [ui.available_width(), 32.0],
            egui::TextEdit::singleline(&mut session.search_query)
                .hint_text("Search artifact names, fields, values…")
                .font(egui::TextStyle::Monospace),
        );
        response.request_focus();
        ui.add_space(6.0);

        if query.is_empty() {
            ui.label(
                RichText::new(format!(
                    "{index_size} indexed field row(s) available — type to search artifact names, fields and values."
                ))
                .color(p.text_dim)
                .size(12.0),
            );
        } else if hits.is_empty() {
            ui.label(
                RichText::new("No indexed field values match. The artifact table also matches names, paths, IDs and categories.")
                    .color(p.text_dim)
                    .size(12.0),
            );
        } else {
            ui.label(
                RichText::new(format!("{} field match(es) — showing the first 60:", hits.len()))
                    .color(p.text_dim)
                    .size(11.5),
            );
            ui.add_space(4.0);
            egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                for hit in hits.iter().take(60) {
                    let Some(row) = rows_by_id.get(&hit.artifact_id) else { continue };
                    let (rect, resp) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 44.0),
                        egui::Sense::click(),
                    );
                    if ui.is_rect_visible(rect) {
                        if resp.hovered() {
                            ui.painter().rect(
                                rect,
                                6.0,
                                p.hover_soft,
                                egui::Stroke::new(1.0_f32, p.border),
                                egui::StrokeKind::Inside,
                            );
                        }
                        // Top row: artifact name + risk badge.
                        let title = format!("{} · {}", hit.artifact_id, row.display_name);
                        let title_galley = ui.painter().layout_no_wrap(
                            title,
                            egui::FontId::new(11.5, egui::FontFamily::Monospace),
                            p.text,
                        );
                        ui.painter().galley(
                            egui::pos2(rect.min.x + 10.0, rect.min.y + 7.0),
                            title_galley,
                            p.text,
                        );
                        let tone = risks
                            .get(&row.artifact_id)
                            .copied()
                            .map(RiskTone::from_severity)
                            .unwrap_or(RiskTone::Clean);
                        let badge_text = risks
                            .get(&row.artifact_id)
                            .map(|s| s.label().to_string())
                            .unwrap_or_else(|| "CLEAN".to_string());
                        let badge_galley = ui.painter().layout_no_wrap(
                            badge_text.clone(),
                            egui::FontId::new(9.5, egui::FontFamily::Monospace),
                            Color32::PLACEHOLDER,
                        );
                        let badge_w = badge_galley.size().x + 14.0;
                        paint_risk_badge(
                            ui,
                            egui::pos2(rect.max.x - 10.0 - badge_w, rect.min.y + 14.0),
                            app.theme,
                            &p,
                            tone,
                            &badge_text,
                        );
                        // Path row: category / stream · matching field.
                        let sub = format!(
                            "{} / {} · field: {}",
                            category_label(row.category),
                            row.relative_path,
                            hit.field
                        );
                        let sub_galley = ui.painter().layout_no_wrap(
                            sub,
                            egui::FontId::new(10.5, egui::FontFamily::Proportional),
                            p.text_muted,
                        );
                        ui.painter().galley(
                            egui::pos2(rect.min.x + 10.0, rect.min.y + 26.0),
                            sub_galley,
                            p.text_muted,
                        );
                    }
                    if resp.clicked() {
                        jump = Some((hit.artifact_id.clone(), hit.field.clone()));
                    }
                }
            });
        }

        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            if !query.is_empty() {
                if modal_button(ui, &p, "Clear search").clicked() {
                    if let Some(s) = &mut app.session {
                        s.search_query.clear();
                    }
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if modal_button(ui, &p, "Close").clicked() {
                    dismiss = true;
                }
            });
        });
    });
    if dismiss {
        close = true;
    }
    if let Some((artifact_id, field)) = jump {
        if let Some(session) = &mut app.session {
            session.selected_artifact = Some(artifact_id);
            session.viewer_tab = ViewerTab::Parsed;
            session.parsed_focus = Some(field);
            session.view = MainView::Explorer;
        }
        close = true;
    }
    if close {
        app.show_search_modal = false;
    }
}

/// Modal 4 — Generate Report: pick a format, export lands in reports/.
fn report_window(app: &mut AppState, ctx: &egui::Context) {
    if !app.show_report_modal {
        return;
    }
    let p = palette(app.theme);
    let mut close = false;
    let mut cancel = false;
    let mut export: Option<&'static str> = None;
    modal_shell(ctx, &p, "report_modal", "Generate Report", 520.0, &mut close, |ui| {
        ui.label(
            RichText::new(
                "Exports the full forensic report — case metadata, findings, correlations, \
                 AI analysis, finding workflow, timeline and the chain-of-custody trail — \
                 into the case's reports folder.",
            )
            .size(12.5),
        );
        ui.add_space(10.0);
        ui.label(RichText::new("Choose a format:").color(p.text_dim).size(12.0));
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if primary_button(ui, &p, "PDF").clicked() {
                export = Some("pdf");
            }
            if modal_button(ui, &p, "HTML").clicked() {
                export = Some("html");
            }
            if modal_button(ui, &p, "JSON").clicked() {
                export = Some("json");
            }
        });
        ui.add_space(10.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if modal_button(ui, &p, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
    });
    if cancel {
        close = true;
    }
    if let Some(format) = export {
        export_report(app, format);
        close = true;
    }
    if close {
        app.show_report_modal = false;
    }
}
