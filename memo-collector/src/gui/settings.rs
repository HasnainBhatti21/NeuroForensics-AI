//! SETTINGS screen - acquisition limits applied to the next case.

use eframe::egui;

use super::{card, section_heading, theme};
use crate::app::state::AppState;

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading(
        egui::RichText::new("SETTINGS")
            .color(theme::TEXT)
            .strong()
            .size(20.0),
    );
    ui.add_space(8.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        section_heading(ui, "Acquisition Limits");
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "These limits bound every acquisition. They protect long-running systems \
                     and keep containers reviewable. Values apply to the next case.",
                )
                .color(theme::TEXT_DIM)
                .size(12.5),
            );
            ui.add_space(10.0);

            // Events per channel.
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Events per channel").color(theme::TEXT));
                let mut value = state.settings.events_per_channel as i32;
                if ui
                    .add(egui::DragValue::new(&mut value).range(10..=100_000).speed(10))
                    .changed()
                {
                    state.settings.events_per_channel = value.max(10) as usize;
                }
                ui.label(
                    egui::RichText::new("maximum Windows event log entries acquired per channel")
                        .color(theme::TEXT_DIM)
                        .size(12.0),
                );
            });
            ui.add_space(6.0);

            // Executables to hash.
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Executables to hash").color(theme::TEXT));
                let mut value = state.settings.max_executables_to_hash as i32;
                if ui
                    .add(egui::DragValue::new(&mut value).range(1..=5000).speed(5))
                    .changed()
                {
                    state.settings.max_executables_to_hash = value.max(1) as usize;
                }
                ui.label(
                    egui::RichText::new("maximum unique process executables hashed")
                        .color(theme::TEXT_DIM)
                        .size(12.0),
                );
            });
            ui.add_space(6.0);

            // Max hash file size (MB).
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Max file size to hash").color(theme::TEXT));
                let mut mb = (state.settings.max_hash_file_bytes / (1024 * 1024)) as i32;
                if ui.add(egui::DragValue::new(&mut mb).range(1..=8192).speed(16)).changed() {
                    state.settings.max_hash_file_bytes = (mb.max(1) as u64) * 1024 * 1024;
                }
                ui.label(
                    egui::RichText::new("MB - files larger than this are skipped and noted")
                        .color(theme::TEXT_DIM)
                        .size(12.0),
                );
            });
        });

        ui.add_space(12.0);
        section_heading(ui, "Scope Reminder");
        card().show(ui, |ui| {
            for line in [
                "MEMO Collector acquires volatile evidence only. It never modifies host data,",
                "never terminates processes, and never draws forensic conclusions.",
                "Raw physical memory and VRAM acquisition are not part of this tool's scope;",
                "when unavailable, the tool records an honest NOT AVAILABLE statement instead.",
            ] {
                ui.label(egui::RichText::new(line).color(theme::TEXT_DIM).size(12.5));
            }
        });
    });
}
