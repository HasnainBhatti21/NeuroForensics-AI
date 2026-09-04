//! EVIDENCE MANAGEMENT view (spec §6): the examiner-facing registry of
//! every .AIF image attached to the case, with ADD / REMOVE / VERIFY /
//! OPEN / REINDEX plus metadata, hash and acquisition inspection.
//!
//! Everything rendered here comes from the case database or the real
//! files on disk — nothing is synthesized.

use eframe::egui::{self, RichText, Ui};

use crate::casemgmt::db::StoredEvidenceImage;

use super::state::{AppState, MainView};
use super::theme::{palette, Palette};

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);

    ui.horizontal(|ui| {
        ui.label(RichText::new("EVIDENCE MANAGEMENT").strong().size(14.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("＋ ADD EVIDENCE").clicked() {
                super::workstation::pick_evidence(app);
            }
        });
    });
    ui.label(
        RichText::new(
            "Registered .AIF evidence images for this case. Original files stay at their location; \
             only paths, sizes and integrity values are recorded here.",
        )
        .color(p.text_dim)
        .size(11.5),
    );
    ui.add_space(8.0);

    let Some(session) = &mut app.session else {
        ui.label(RichText::new("No case open.").color(p.text_dim));
        return;
    };

    let images = session.db.evidence_images();
    if images.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.label(RichText::new("No evidence registered in this case yet.").size(13.0));
            ui.label(RichText::new("Use ADD EVIDENCE to validate and ingest an .AIF container produced by MEMO Collector.").color(p.text_dim).size(11.5));
        });
        return;
    }

    // Keep a valid selection.
    if !images.iter().any(|i| Some(i.id) == session.evidence_selected) {
        session.evidence_selected = Some(images[0].id);
    }
    let selected_id = session.evidence_selected.unwrap_or(images[0].id);

    ui.columns(2, |cols| {
        cols[0].set_min_width(260.0);
        draw_image_list(&mut cols[0], app, &images, selected_id, &p);
        cols[1].separator();
        draw_image_detail(&mut cols[1], app, &images, selected_id, &p);
    });
}

fn draw_image_list(
    ui: &mut Ui,
    app: &mut AppState,
    images: &[StoredEvidenceImage],
    selected_id: i64,
    p: &Palette,
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        for img in images {
            let selected = img.id == selected_id;
            let is_open = app
                .session
                .as_ref()
                .and_then(|s| s.current_image_id)
                .map(|id| id == img.id)
                .unwrap_or(false);
            let fill = if selected { p.selection } else { egui::Color32::TRANSPARENT };
            let response = egui::Frame::default()
                .fill(fill)
                .corner_radius(6.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (badge, badge_color) = match img.record.container_verified {
                            Some(true) => ("VERIFIED", p.good),
                            Some(false) => ("MISMATCH", p.danger),
                            None => ("NO SIDE CAR", p.warn),
                        };
                        ui.label(RichText::new("🗎").color(p.accent));
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&img.record.file_name).strong().size(12.0));
                                if is_open {
                                    ui.label(RichText::new("OPEN").color(p.accent).size(10.0));
                                }
                            });
                            ui.label(
                                RichText::new(format!(
                                    "{} · added {} · {}",
                                    crate::gui::fmt_bytes(img.record.size_bytes),
                                    img.record.added_at,
                                    badge
                                ))
                                .color(badge_color)
                                .size(10.5),
                            );
                        });
                    });
                });
            if response.response.clicked() {
                if let Some(s) = &mut app.session {
                    s.evidence_selected = Some(img.id);
                    s.remove_confirm = None;
                }
            }
            ui.add_space(2.0);
        }
    });
}

fn draw_image_detail(
    ui: &mut Ui,
    app: &mut AppState,
    images: &[StoredEvidenceImage],
    selected_id: i64,
    p: &Palette,
) {
    let Some(img) = images.iter().find(|i| i.id == selected_id) else { return };
    let rec = &img.record;

    let is_open = app
        .session
        .as_ref()
        .and_then(|s| s.current_image_id)
        .map(|id| id == selected_id)
        .unwrap_or(false);

    // ---- actions (§6) ----
    ui.horizontal(|ui| {
        let busy = app.pending_verify.is_some() || app.pending_ingest.is_some();
        if ui
            .add_enabled(!busy, egui::Button::new("VERIFY EVIDENCE"))
            .on_hover_text("Re-hash the file on disk and compare against recorded SHA-256 values")
            .clicked()
        {
            super::workstation::start_verify(app, img.id, rec.file_name.clone(), rec.path.clone());
        }
        if ui
            .add_enabled(!busy, egui::Button::new("OPEN EVIDENCE"))
            .on_hover_text("Ingest this registered image into the examiner workspace")
            .clicked()
        {
            super::workstation::start_ingest_path(app, std::path::PathBuf::from(&rec.path));
        }
        if ui
            .add_enabled(!busy, egui::Button::new("REINDEX EVIDENCE"))
            .on_hover_text("Rebuild the artifact index from the file on disk")
            .clicked()
        {
            super::workstation::start_ingest_path(app, std::path::PathBuf::from(&rec.path));
        }
        // Two-step REMOVE: ask, then confirm.
        let confirming = app.session.as_ref().and_then(|s| s.remove_confirm) == Some(img.id);
        if !confirming {
            if ui
                .add_enabled(!busy, egui::Button::new(RichText::new("REMOVE FROM CASE").color(p.danger)))
                .clicked()
            {
                if let Some(s) = &mut app.session {
                    s.remove_confirm = Some(img.id);
                }
            }
        } else {
            if ui.button(RichText::new("CONFIRM REMOVE").color(p.danger).strong()).clicked() {
                super::workstation::remove_image(app, img.id, is_open);
            }
            if ui.button("Cancel").clicked() {
                if let Some(s) = &mut app.session {
                    s.remove_confirm = None;
                }
            }
        }
    });
    if app.session.as_ref().and_then(|s| s.remove_confirm) == Some(img.id) {
        ui.label(
            RichText::new("Removing deregisters this image and its indexed artifacts from the case database. The original file on disk is never touched.")
                .color(p.warn)
                .size(11.0),
        );
    }
    ui.add_space(10.0);
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        // ---- metadata (§6 VIEW EVIDENCE METADATA) ----
        ui.label(RichText::new("METADATA").color(p.text_dim).strong().size(11.0));
        egui::Grid::new("ev_meta").min_col_width(160.0).spacing([8.0, 5.0]).show(ui, |ui| {
            let mut kv = |k: &str, v: String| {
                ui.label(RichText::new(k).color(p.text_dim).size(11.5));
                ui.label(RichText::new(v).size(11.5));
                ui.end_row();
            };
            kv("File", rec.file_name.clone());
            kv("Path", rec.path.clone());
            kv("Size", crate::gui::fmt_bytes(rec.size_bytes));
            kv("Format version", rec.format_version.map(|v| format!("AIF v{v}")).unwrap_or_else(|| "unknown".into()));
            kv("Collector case id", rec.case_id.clone().unwrap_or_else(|| "unknown".into()));
            kv("Demo / synthetic", if rec.demo_mode { "YES (collector-flagged)".into() } else { "no".into() });
            kv("Registered", rec.added_at.clone());
        });
        if let Some(session) = &app.session {
            let count = session.db.artifact_count(img.id);
            ui.label(RichText::new(format!("Indexed artifacts: {count}")).size(11.5));
        }
        ui.add_space(8.0);

        // ---- hashes (§6 VIEW HASH) ----
        ui.label(RichText::new("CONTAINER HASH").color(p.text_dim).strong().size(11.0));
        ui.label(RichText::new(rec.container_sha256.clone()).monospace().size(10.5));
        match rec.container_verified {
            Some(true) => {
                ui.label(RichText::new("✓ VERIFIED against external sidecar").color(p.good).size(11.0));
            }
            Some(false) => {
                ui.label(RichText::new("✗ MISMATCH against external sidecar").color(p.danger).size(11.0));
                if let Some(exp) = &rec.expected_sha256 {
                    ui.label(RichText::new(format!("expected: {exp}")).monospace().size(10.5));
                }
            }
            None => {
                ui.label(
                    RichText::new("No external .AIF.sha256 / custody sidecar found — independent verification not possible.")
                        .color(p.warn)
                        .size(11.0),
                );
            }
        }
        ui.add_space(8.0);

        // ---- acquisition (§6 VIEW ACQUISITION INFORMATION) ----
        ui.label(RichText::new("ACQUISITION INFORMATION").color(p.text_dim).strong().size(11.0));
        let open_exam = app.session.as_ref().and_then(|s| s.exam.as_ref()).filter(|_| is_open);
        match open_exam {
            Some(exam) => {
                let c = &exam.case_doc.case;
                let a = &exam.manifest.acquisition;
                egui::Grid::new("ev_acq").min_col_width(160.0).spacing([8.0, 5.0]).show(ui, |ui| {
                    let mut kv = |k: &str, v: &str| {
                        ui.label(RichText::new(k).color(p.text_dim).size(11.5));
                        ui.label(RichText::new(v.to_string()).size(11.5));
                        ui.end_row();
                    };
                    kv("Case (inside AIF)", &c.case_name);
                    kv("Investigator", &c.investigator_name);
                    kv("Organization", &c.organization);
                    kv("Acquired by", &a.operator);
                    kv("Method", &a.method);
                    kv("Start", &a.start_time);
                    kv("End", &a.end_time);
                });
            }
            None => {
                ui.label(
                    RichText::new("Not loaded — OPEN EVIDENCE to read acquisition details from case.json.")
                        .color(p.text_dim)
                        .size(11.0),
                );
            }
        }
    });
}

/// Switches to this view (used by toolbar / other panels).
#[allow(dead_code)]
pub fn focus(app: &mut AppState) {
    if let Some(s) = &mut app.session {
        s.view = MainView::Evidence;
    }
}
