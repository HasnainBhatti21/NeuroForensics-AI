//! ACQUISITION screen - live progress, pause/cancel, completion summary.

use std::sync::atomic::Ordering;

use eframe::egui;

use super::{card, section_heading, state_color, theme};
use crate::app::state::{format_bytes, format_duration, open_file, reveal_path, AppState};
use crate::collectors::ModuleState;

pub fn show(ui: &mut egui::Ui, state: &mut AppState, ctx: &egui::Context) {
    ui.heading(
        egui::RichText::new("LIVE FORENSIC ACQUISITION")
            .color(theme::TEXT)
            .strong()
            .size(20.0),
    );
    ui.add_space(8.0);

    let snapshot = state.progress.lock().unwrap().clone();

    if snapshot.modules.is_empty() && !snapshot.running {
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new("No acquisition in progress. Create a new case to begin.")
                    .color(theme::TEXT_DIM),
            );
        });
        return;
    }

    // Lazy-load the manifest once a finished case is available.
    if let Some(outcome) = &snapshot.outcome {
        if state.last_manifest.is_none() {
            if let Ok(manifest) = crate::evidence::aif::read_manifest(&outcome.aif_path) {
                state.last_manifest = Some(manifest);
                state.last_aif = Some(outcome.aif_path.clone());
            }
        }
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        if snapshot.demo_mode {
            ui.colored_label(
                theme::YELLOW,
                "⚠ DEMO MODE ACTIVE - SYNTHETIC DEMONSTRATION DATA, NOT REAL EVIDENCE",
            );
            ui.add_space(4.0);
        }

        // ---------------- OVERALL STATUS ----------------
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(&snapshot.phase)
                            .color(theme::ACCENT)
                            .strong()
                            .size(14.0),
                    );
                    if snapshot.paused {
                        ui.colored_label(theme::YELLOW, "PAUSED");
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    if snapshot.running {
                        let paused = state.control.pause.load(Ordering::SeqCst);
                        if ui
                            .button(if paused { "RESUME" } else { "PAUSE" })
                            .clicked()
                        {
                            state.control.pause.store(!paused, Ordering::SeqCst);
                        }
                        if ui
                            .button(egui::RichText::new("CANCEL ACQUISITION").color(theme::RED))
                            .clicked()
                        {
                            state.control.cancel.store(true, Ordering::SeqCst);
                        }
                    }
                });
            });
            ui.add_space(6.0);
            let bar = egui::ProgressBar::new(snapshot.total_fraction())
                .fill(theme::ACCENT)
                .text(format!(
                    "{} / {} modules",
                    snapshot
                        .modules
                        .iter()
                        .filter(|m| m.state != ModuleState::Pending && m.state != ModuleState::Running)
                        .count(),
                    snapshot.modules.len()
                ));
            ui.add_sized(egui::vec2(ui.available_width(), 18.0), bar);

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                stat_chip(ui, "ITEMS", &snapshot.items_collected.to_string());
                stat_chip(ui, "BYTES", &format_bytes(snapshot.bytes_acquired));
                stat_chip(ui, "ELAPSED", &format_duration(snapshot.elapsed_seconds));
                stat_chip(
                    ui,
                    "THROUGHPUT",
                    &format!("{}/s", format_bytes(snapshot.throughput_bytes_per_sec)),
                );
                stat_chip(
                    ui,
                    "WARNINGS",
                    &snapshot.warnings.len().to_string(),
                );
            });
            if !snapshot.current_artifact.is_empty() && snapshot.running {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(format!("acquiring: {}", snapshot.current_artifact))
                        .color(theme::TEXT_DIM)
                        .size(12.0),
                );
            }
        });

        // ---------------- MODULE PROGRESS ----------------
        ui.add_space(10.0);
        section_heading(ui, "Acquisition Modules");
        card().show(ui, |ui| {
            for module in &snapshot.modules {
                let fraction = match module.state {
                    ModuleState::Completed | ModuleState::Skipped => 1.0,
                    ModuleState::Failed | ModuleState::Cancelled => 1.0,
                    ModuleState::Running => 0.5, // indeterminate-ish marker
                    ModuleState::Pending => 0.0,
                };
                ui.horizontal(|ui| {
                    ui.add_sized(
                        egui::vec2(230.0, 20.0),
                        egui::Label::new(
                            egui::RichText::new(module.name.clone())
                                .color(theme::TEXT)
                                .size(13.0),
                        ),
                    );
                    let bar = egui::ProgressBar::new(fraction)
                        .fill(state_color(module.state))
                        .text(format!(
                            "{}  {}  {}",
                            module.state.label(),
                            if module.artifacts > 0 {
                                format!("· {} artifacts", module.artifacts)
                            } else {
                                String::new()
                            },
                            if module.bytes > 0 {
                                format!("· {}", format_bytes(module.bytes))
                            } else {
                                String::new()
                            }
                        ));
                    ui.add_sized(egui::vec2(ui.available_width(), 18.0), bar);
                });
                ui.add_space(2.0);
            }
        });

        // ---------------- WARNINGS & ERRORS ----------------
        if !snapshot.warnings.is_empty() || !snapshot.errors.is_empty() {
            ui.add_space(10.0);
            section_heading(ui, "Warnings & Errors");
            card().show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .show(ui, |ui| {
                        for error in &snapshot.errors {
                            ui.colored_label(
                                theme::RED,
                                format!(
                                    "[{}] {} - {}: {}",
                                    error.timestamp, error.module, error.code, error.description
                                ),
                            );
                        }
                        for warning in &snapshot.warnings {
                            ui.colored_label(
                                theme::YELLOW,
                                format!("[{}] {}: {}", warning.timestamp, warning.module, warning.message),
                            );
                        }
                    });
            });
        }

        // ---------------- COMPLETION PANEL ----------------
        if let Some(outcome) = &snapshot.outcome {
            ui.add_space(12.0);
            section_heading(ui, "Acquisition Completed");
            card().show(ui, |ui| {
                ui.heading(
                    egui::RichText::new(&outcome.status)
                        .color(if outcome.status.contains("COMPLETED") {
                            theme::GREEN
                        } else {
                            theme::YELLOW
                        })
                        .strong(),
                );
                ui.add_space(6.0);
                ui.monospace(
                    egui::RichText::new(outcome.aif_path.display().to_string()).color(theme::ACCENT),
                );
                ui.add_space(6.0);
                egui::Grid::new("outcome_grid").num_columns(2).show(ui, |ui| {
                    ui.label("Evidence size:");
                    ui.monospace(format_bytes(outcome.total_evidence_bytes));
                    ui.end_row();
                    ui.label("Container size:");
                    ui.monospace(format_bytes(outcome.container_bytes));
                    ui.end_row();
                    ui.label("Artifacts:");
                    ui.monospace(outcome.artifact_count.to_string());
                    ui.end_row();
                    ui.label("SHA-256 (AIF):");
                    ui.monospace(&outcome.aif_sha256);
                    ui.end_row();
                    ui.label("Start:");
                    ui.monospace(&outcome.start_time);
                    ui.end_row();
                    ui.label("End:");
                    ui.monospace(&outcome.end_time);
                    ui.end_row();
                    ui.label("Warnings:");
                    ui.monospace(outcome.warnings.to_string());
                    ui.end_row();
                    ui.label("Failed modules:");
                    ui.monospace(if outcome.failed_modules.is_empty() {
                        "0".to_string()
                    } else {
                        outcome.failed_modules.join(", ")
                    });
                    ui.end_row();
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("OPEN CASE LOCATION").clicked() {
                        reveal_path(&outcome.aif_path);
                    }
                    if ui.button("VIEW MANIFEST").clicked() {
                        state.screen = crate::app::state::Screen::Evidence;
                    }
                    if ui.button("VERIFY INTEGRITY").clicked() {
                        state.verify_path = outcome.aif_path.display().to_string();
                        state.verify_expected = outcome.aif_sha256.clone();
                        state.verify_result = None;
                        state.verify_error = None;
                        state.screen = crate::app::state::Screen::Integrity;
                    }
                    if ui.button("CREATE ACQUISITION REPORT").clicked() {
                        open_file(&outcome.report_path);
                    }
                    if ui.button("CLOSE CASE").clicked() {
                        state.last_manifest = None;
                        state.last_aif = None;
                        *state.progress.lock().unwrap() =
                            crate::collectors::AcquisitionProgress::new();
                    }
                });
            });
        }
    });
    let _ = ctx;
}

fn stat_chip(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::new()
        .fill(theme::PANEL)
        .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(label).color(theme::TEXT_DIM).size(10.0));
                ui.label(egui::RichText::new(value).color(theme::TEXT).strong().size(13.0));
            });
        });
}
