//! §23 Correlations view: every traceable cross-stream evidence link,
//! grouped into per-process activity chains. Clicking either side of a
//! link opens that artifact's real detail panel (§20 never-blank).
//!
//! Honest degradation: with too few cross-stream links the view says
//! so — it never forces a graph into existence.

use eframe::egui::{self, Color32, RichText, Stroke, Ui};

use crate::correlation::CorrelationLink;

use super::state::{AppState, MainView, ViewerTab};
use super::theme::{paint_icon, palette, Icon, Palette};

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);

    // Build once per image; lazy on first visit.
    if let Some(session) = &mut app.session {
        if session.correlation_cache.is_none() {
            session.correlation_cache = session
                .exam
                .as_ref()
                .map(crate::correlation::build);
        }
    }

    let exam_open = app.session.as_ref().map(|s| s.exam.is_some()).unwrap_or(false);
    let links: Vec<CorrelationLink> = app
        .session
        .as_ref()
        .and_then(|s| s.correlation_cache.as_ref())
        .map(|r| r.links.clone())
        .unwrap_or_default();
    let activity_count = app
        .session
        .as_ref()
        .and_then(|s| s.correlation_cache.as_ref())
        .map(|r| r.activities.len())
        .unwrap_or(0);

    // ---- header: icon, title and stat cards --------------------------
    ui.horizontal(|ui| {
        let (irect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
        paint_icon(ui.painter(), irect, Icon::Wave, p.accent, 1.8);
        ui.label(RichText::new("EVIDENCE CORRELATIONS").strong().size(14.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            stat_card(ui, &p, &links.len().to_string(), "LINKED PAIRS", p.accent);
            ui.add_space(8.0);
            stat_card(ui, &p, &activity_count.to_string(), "ACTIVITY CHAINS", p.accent_ai);
        });
    });
    ui.label(
        RichText::new(
            "Cross-stream links matched on real identifiers (pids, paths, names) recorded in the evidence. \
             Click any artifact chip to open its detail panel.",
        )
        .color(p.text_dim)
        .size(11.5),
    );
    ui.add_space(4.0);
    ui.separator();

    if !exam_open {
        empty_note(ui, &p, Icon::CardSplit, "No evidence image is open. Correlations are built from decoded streams — add a .AIF image first.");
        return;
    }
    if links.is_empty() {
        empty_note(ui, &p, Icon::CheckCircle, "No correlated evidence in this case — the acquired streams share no traceable identifiers (pids, paths, names). Nothing is inferred.");
        return;
    }

    egui::ScrollArea::vertical().id_salt("correlations").show(ui, |ui| {
        // Activity chains (§23: PROCESS + … = CORRELATED ACTIVITY).
        section_head(ui, &p, Icon::Wave, "CORRELATED ACTIVITY CHAINS", &format!("{} chain(s)", activity_count));
        let activities: Vec<crate::correlation::CorrelatedActivity> = app
            .session
            .as_ref()
            .and_then(|s| s.correlation_cache.as_ref())
            .map(|r| r.activities.clone())
            .unwrap_or_default();
        for act in &activities {
            egui::Frame::default()
                .fill(p.block)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    // Chain header: process anchor + kind badges.
                    ui.horizontal(|ui| {
                        let (grect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                        paint_icon(ui.painter(), grect, Icon::Grid, p.accent_ai, 1.6);
                        ui.label(
                            RichText::new(format!("{} (pid {})", act.process_name, act.process_pid))
                                .strong()
                                .size(12.0),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            for kind in act.kinds.iter().rev() {
                                kind_badge(ui, &p, kind);
                            }
                        });
                    });
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        if artifact_chip(ui, &p, &act.process_artifact, &format!("{}", act.process_name)) {
                            jump_to(app, &act.process_artifact);
                        }
                        ui.label(RichText::new("→").color(p.text_muted).size(12.0));
                        for partner in &act.partners {
                            let label = partner_label(app, partner);
                            if artifact_chip(ui, &p, partner, &label) {
                                jump_to(app, partner);
                            }
                        }
                    });
                });
            ui.add_space(6.0);
        }

        ui.add_space(10.0);
        section_head(ui, &p, Icon::CardSplit, "EVIDENCE PAIRS", &format!("{} linked pair(s)", links.len()));
        for link in &links {
            egui::Frame::default()
                .fill(p.panel)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        kind_badge(ui, &p, link.kind.label());
                        ui.label(RichText::new("·").color(p.text_muted));
                        ui.vertical(|ui| {
                            ui.horizontal_wrapped(|ui| {
                                if artifact_chip(ui, &p, &link.a.artifact_id, &link.a.label) {
                                    jump_to(app, &link.a.artifact_id);
                                }
                                ui.label(RichText::new("↔").color(p.accent).strong());
                                if artifact_chip(ui, &p, &link.b.artifact_id, &link.b.label) {
                                    jump_to(app, &link.b.artifact_id);
                                }
                            });
                            ui.label(
                                RichText::new(format!("shared evidence: {}", truncate(&link.matched, 140)))
                                    .monospace()
                                    .color(p.text_dim)
                                    .size(10.5),
                            );
                        });
                    });
                });
            ui.add_space(6.0);
        }
    });
}

/// Small header for one sub-section: accent icon + caps title + count.
fn section_head(ui: &mut Ui, p: &Palette, icon: Icon, title: &str, count: &str) {
    ui.horizontal(|ui| {
        let (irect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
        paint_icon(ui.painter(), irect, icon, p.accent, 1.7);
        ui.label(RichText::new(title).strong().color(p.accent_deep).size(12.0));
        ui.label(RichText::new(count).color(p.text_muted).size(11.0));
    });
    ui.add_space(4.0);
}

/// Compact number card (right-hand header stats).
fn stat_card(ui: &mut Ui, p: &Palette, number: &str, label: &str, color: Color32) {
    egui::Frame::default()
        .fill(p.block)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(number).monospace().strong().color(color).size(14.0));
                ui.label(RichText::new(label).color(p.text_muted).size(9.0));
            });
        });
}

/// Pill badge for one correlation kind.
fn kind_badge(ui: &mut Ui, p: &Palette, kind: &str) {
    egui::Frame::default()
        .fill(p.accent_dim)
        .stroke(Stroke::new(1.0_f32, p.active_border))
        .corner_radius(9.0)
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(kind).monospace().color(p.accent_deep).size(9.5));
        });
}

/// Clickable artifact chip: framed pill, ID badge + readable label.
fn artifact_chip(ui: &mut Ui, p: &Palette, artifact_id: &str, label: &str) -> bool {
    ui.add(
        egui::Button::new(
            RichText::new(format!("{artifact_id} · {label}")).color(p.accent_deep).size(11.0),
        )
        .fill(p.accent_dim)
        .stroke(Stroke::new(1.0_f32, p.active_border))
        .corner_radius(10.0),
    )
    .on_hover_text("Open this artifact's detail panel")
    .clicked()
}

/// Resolve a short human label for an artifact from the index.
fn partner_label(app: &AppState, artifact_id: &str) -> String {
    app.session
        .as_ref()
        .and_then(|s| s.exam.as_ref())
        .and_then(|exam| exam.artifact_by_id(artifact_id))
        .map(|a| a.relative_path.clone())
        .unwrap_or_else(|| artifact_id.to_string())
}

/// Jump into the Explorer with the artifact's Parsed View (§22 → §20).
fn jump_to(app: &mut AppState, artifact_id: &str) {
    if let Some(session) = &mut app.session {
        session.selected_artifact = Some(artifact_id.to_string());
        session.viewer_tab = ViewerTab::Parsed;
        session.parsed_focus = None;
        session.view = MainView::Explorer;
    }
}

/// Char-safe single-line truncation (byte slicing would panic on
/// multi-byte paths).
fn truncate(s: &str, max: usize) -> String {
    let one_line: String = s.lines().next().unwrap_or(s).to_string();
    let count = one_line.chars().count();
    if count <= max {
        one_line
    } else {
        let cut: String = one_line.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn empty_note(ui: &mut Ui, p: &Palette, icon: Icon, msg: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(46.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(28.0, 28.0), egui::Sense::hover());
        paint_icon(ui.painter(), rect, icon, p.text_muted, 1.8);
        ui.add_space(8.0);
        ui.label(RichText::new(msg).color(p.text_dim).size(12.0));
    });
}
