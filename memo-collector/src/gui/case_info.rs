//! CASE INFO screen - metadata of the most recently created case.

use eframe::egui;

use super::{card, section_heading, theme};
use crate::app::state::{format_bytes, open_file, reveal_path, AppState};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading(
        egui::RichText::new("CASE INFO")
            .color(theme::TEXT)
            .strong()
            .size(20.0),
    );
    ui.add_space(8.0);

    let Some(manifest) = state.last_manifest.clone() else {
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "No case loaded. Create a new case or verify an existing AIF container.",
                )
                .color(theme::TEXT_DIM),
            );
        });
        return;
    };

    let last_aif = state.last_aif.clone();

    egui::ScrollArea::vertical().show(ui, |ui| {
        // ---------------- CASE DETAILS ----------------
        section_heading(ui, "Case Details");
        card().show(ui, |ui| {
            row(ui, "Case ID", &manifest.case_id);
            row(ui, "Case Name", &manifest.case_name);
            row(ui, "Investigator", &manifest.acquisition.operator);
            row(ui, "Acquisition Method", &manifest.acquisition.method);
            row(ui, "Acquisition Status", &manifest.acquisition.status);
            row(ui, "Start Time", &manifest.acquisition.start_time);
            row(ui, "End Time", &manifest.acquisition.end_time);
        });

        // ---------------- HOST ----------------
        ui.add_space(10.0);
        section_heading(ui, "Host Information");
        card().show(ui, |ui| {
            row(ui, "Hostname", &manifest.host.hostname);
            row(ui, "Operating System", &format!("{} {}", manifest.host.os, manifest.host.os_version));
            row(ui, "Architecture", &manifest.host.architecture);
            row(ui, "Kernel", &manifest.host.kernel_version);
            if let Some(boot) = &manifest.host.boot_time {
                row(ui, "Boot Time", boot);
            }
            row(ui, "User", &format!("{}\\{}", manifest.host.domain, manifest.host.username));
            row(
                ui,
                "Session",
                if manifest.host.elevated { "Elevated (administrator)" } else { "Standard" },
            );
        });

        // ---------------- COLLECTOR TOOL ----------------
        ui.add_space(10.0);
        section_heading(ui, "Acquisition Tool");
        card().show(ui, |ui| {
            row(ui, "Tool", &manifest.collector.name);
            row(ui, "Platform", &manifest.collector.platform);
            row(
                ui,
                "Version",
                &format!("{} (build {})", manifest.collector.version, manifest.collector.build),
            );
            row(ui, "Integrity Algorithm", &manifest.integrity.algorithm);
            if let Some(hash) = &manifest.integrity.aif_sha256 {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Container SHA-256").color(theme::TEXT_DIM).size(13.0));
                    ui.monospace(egui::RichText::new(hash).color(theme::ACCENT));
                });
            }
        });

        // ---------------- MODULE SUMMARY ----------------
        ui.add_space(10.0);
        section_heading(ui, "Modules Executed");
        card().show(ui, |ui| {
            for module in &manifest.modules {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&module.module_name)
                            .color(theme::TEXT)
                            .size(13.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "{} · {} artifacts · {}",
                                module.status,
                                module.artifacts,
                                format_bytes(module.bytes)
                            ))
                            .color(theme::TEXT_DIM)
                            .size(12.0),
                        );
                    });
                });
                if let Some(reason) = &module.reason {
                    if !reason.is_empty() {
                        ui.label(egui::RichText::new(format!("   {}", reason)).color(theme::TEXT_DIM).size(11.5));
                    }
                }
            }
        });

        // ---------------- ACTIONS ----------------
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if let Some(aif) = &last_aif {
                if ui.button("OPEN CASE LOCATION").clicked() {
                    reveal_path(aif);
                }
                let report = aif.with_extension("html");
                if ui.add_enabled(report.exists(), egui::Button::new("OPEN ACQUISITION REPORT")).clicked() {
                    open_file(&report);
                }
            }
            if ui.button("VIEW MANIFEST").clicked() {
                state.screen = crate::app::state::Screen::Evidence;
            }
            if ui.button("CLOSE CASE").clicked() {
                state.last_manifest = None;
                state.last_aif = None;
            }
        });
    });
}

fn row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            egui::vec2(180.0, 20.0),
            egui::Label::new(egui::RichText::new(key).color(theme::TEXT_DIM).size(13.0)),
        );
        ui.label(egui::RichText::new(value).color(theme::TEXT).size(13.0));
    });
}
