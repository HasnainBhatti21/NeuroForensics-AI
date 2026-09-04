//! EVIDENCE screen - artifact ledger of the last created case.

use eframe::egui;

use super::{card, theme};
use crate::app::state::{format_bytes, AppState};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading(
        egui::RichText::new("EVIDENCE")
            .color(theme::TEXT)
            .strong()
            .size(20.0),
    );
    ui.add_space(8.0);

    let Some(manifest) = state.last_manifest.clone() else {
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "No case loaded. Create a case or inspect one from the INTEGRITY screen.",
                )
                .color(theme::TEXT_DIM),
            );
        });
        return;
    };

    ui.label(
        egui::RichText::new(format!(
            "{} · {} artifacts · {} evidence",
            manifest.case_id,
            manifest.artifacts.len(),
            format_bytes(manifest.total_bytes())
        ))
        .color(theme::TEXT_DIM),
    );
    ui.add_space(8.0);

    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("artifact_ledger")
            .striped(true)
            .min_col_width(40.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("ARTIFACT ID").color(theme::ACCENT).strong());
                ui.label(egui::RichText::new("PATH").color(theme::ACCENT).strong());
                ui.label(egui::RichText::new("COLLECTOR").color(theme::ACCENT).strong());
                ui.label(egui::RichText::new("SIZE").color(theme::ACCENT).strong());
                ui.label(egui::RichText::new("SHA-256").color(theme::ACCENT).strong());
                ui.label(egui::RichText::new("STATUS").color(theme::ACCENT).strong());
                ui.end_row();

                for artifact in &manifest.artifacts {
                    ui.monospace(&artifact.artifact_id);
                    ui.monospace(&artifact.relative_path);
                    ui.label(&artifact.collector);
                    ui.monospace(format_bytes(artifact.size));
                    ui.monospace(&artifact.sha256);
                    ui.colored_label(
                        if artifact.synthetic { theme::YELLOW } else { theme::GREEN },
                        if artifact.synthetic {
                            "SYNTHETIC DEMO"
                        } else {
                            crate::app::engine::artifact_status_label(&artifact.status)
                        },
                    );
                    ui.end_row();
                }
            });
    });
}
