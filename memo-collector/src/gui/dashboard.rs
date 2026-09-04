//! DASHBOARD screen - system status, acquisition status, quick actions.

use eframe::egui;

use super::{card, section_heading, status_row, theme};
use crate::app::state::{format_bytes, AppState, Screen};

pub fn show(ui: &mut egui::Ui, state: &mut AppState, ctx: &egui::Context) {
    ui.heading(
        egui::RichText::new("MEMO Collector")
            .color(theme::TEXT)
            .strong()
            .size(22.0),
    );
    ui.label(
        egui::RichText::new("Portable forensic evidence acquisition - NEUROFORENSICS AI")
            .color(theme::TEXT_DIM),
    );
    ui.add_space(10.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.columns(2, |cols| {
            // ---------------- SYSTEM STATUS ----------------
            cols[0].vertical(|ui| {
                section_heading(ui, "System Status");
                card().show(ui, |ui| {
                    ui.set_min_width(280.0);
                    let s = &state.status;
                    status_row(ui, "OS", &s.os, theme::TEXT);
                    ui.separator();
                    status_row(
                        ui,
                        "Administrator",
                        if s.admin { "YES" } else { "NO" },
                        if s.admin { theme::GREEN } else { theme::YELLOW },
                    );
                    ui.separator();
                    status_row(ui, "CPU", if s.cpu.is_empty() { "Detected" } else { &s.cpu }, theme::TEXT);
                    ui.separator();
                    status_row(
                        ui,
                        "GPU",
                        if s.gpu_detected { "Detected" } else { "Not Detected" },
                        if s.gpu_detected { theme::GREEN } else { theme::TEXT_DIM },
                    );
                    ui.separator();
                    status_row(ui, "RAM", &format!("{:.1} GB", s.ram_gb), theme::TEXT);
                    ui.separator();
                    status_row(
                        ui,
                        "Network",
                        if s.network_available { "Available" } else { "Unavailable" },
                        if s.network_available { theme::GREEN } else { theme::TEXT_DIM },
                    );
                    ui.separator();
                    status_row(
                        ui,
                        "Storage",
                        if s.storage_available { "Available" } else { "Unavailable" },
                        if s.storage_available { theme::GREEN } else { theme::TEXT_DIM },
                    );
                });

                if !state.status.admin {
                    ui.add_space(8.0);
                    card().show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Some forensic acquisition sources require elevated Windows privileges.",
                            )
                            .color(theme::YELLOW)
                            .size(12.5),
                        );
                        if ui
                            .button(egui::RichText::new("RESTART AS ADMINISTRATOR").color(theme::TEXT))
                            .clicked()
                        {
                            if crate::win::privs::restart_as_admin().is_ok() {
                                std::process::exit(0);
                            }
                        }
                    });
                }
            });

            // ---------------- ACQUISITION STATUS ----------------
            cols[1].vertical(|ui| {
                section_heading(ui, "Acquisition Status");
                let snapshot = state.progress.lock().unwrap().clone();
                card().show(ui, |ui| {
                    ui.set_min_width(280.0);
                    if snapshot.outcome.is_some() || snapshot.finished_at.is_some() {
                        if let Some(outcome) = &snapshot.outcome {
                            status_row(ui, "Status", &outcome.status, theme::GREEN);
                            ui.separator();
                            status_row(
                                ui,
                                "Case File",
                                &outcome
                                    .aif_path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default(),
                                theme::ACCENT,
                            );
                            ui.separator();
                            status_row(
                                ui,
                                "Artifacts",
                                &outcome.artifact_count.to_string(),
                                theme::TEXT,
                            );
                            ui.separator();
                            status_row(
                                ui,
                                "Evidence Size",
                                &format_bytes(outcome.total_evidence_bytes),
                                theme::TEXT,
                            );
                        } else {
                            status_row(ui, "Status", &snapshot.phase, theme::TEXT);
                        }
                    } else if snapshot.running {
                        status_row(ui, "Status", &format!("RUNNING - {}", snapshot.phase), theme::ACCENT);
                        ui.separator();
                        status_row(ui, "Items Collected", &snapshot.items_collected.to_string(), theme::TEXT);
                        ui.separator();
                        status_row(ui, "Bytes Acquired", &format_bytes(snapshot.bytes_acquired), theme::TEXT);
                        ui.add_space(4.0);
                        if ui.button("VIEW LIVE ACQUISITION").clicked() {
                            state.screen = Screen::Acquisition;
                        }
                    } else {
                        status_row(ui, "Status", "No active case", theme::TEXT_DIM);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "Create a new case to acquire volatile evidence from this endpoint.",
                            )
                            .color(theme::TEXT_DIM)
                            .size(12.0),
                        );
                    }
                });

                // ---------------- QUICK ACTIONS ----------------
                ui.add_space(12.0);
                section_heading(ui, "Quick Actions");
                card().show(ui, |ui| {
                    ui.set_min_width(280.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(egui::RichText::new("NEW CASE").color(theme::BG).strong())
                            .clicked()
                        {
                            state.screen = Screen::NewCase;
                        }
                        if ui.button("OPEN CASE").clicked() {
                            state.screen = Screen::CaseInfo;
                        }
                        if ui.button("VERIFY AIF").clicked() {
                            state.screen = Screen::Integrity;
                        }
                    });
                    if snapshot.running {
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new("Acquisition in progress...")
                                .color(theme::ACCENT)
                                .size(12.0),
                        );
                    }
                });
            });
        });

        // Scope reminder.
        ui.add_space(16.0);
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new("SCOPE").color(theme::PURPLE).strong().size(12.0),
            );
            ui.label(
                egui::RichText::new(
                    "MEMO Collector is an evidence acquisition engine only. It performs no malware \
                     detection, no threat scoring, no forensic conclusions and no destructive \
                     actions. Analysis is delegated to the future NEUROFORENSICS AI Analyzer, \
                     which consumes the .AIF case produced here.",
                )
                .color(theme::TEXT_DIM)
                .size(12.5),
            );
        });
    });
    let _ = ctx;
}
