//! NEW CASE screen - case details, destination, acquisition profile.

use std::sync::Arc;

use eframe::egui;

use super::{card, section_heading, theme};
use crate::app::engine::{self, AcquisitionParams};
use crate::app::state::{suggest_case_id, AppState, Screen};
use crate::collectors::{AcquisitionControl, AcquisitionProgress, CollectorId};

fn labeled_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            egui::vec2(170.0, 20.0),
            egui::Label::new(egui::RichText::new(label).color(theme::TEXT_DIM).size(13.0)),
        );
        let edit = egui::TextEdit::singleline(value)
            .hint_text(hint)
            .frame(true)
            .background_color(theme::PANEL)
            .text_color(theme::TEXT);
        ui.add_sized(egui::vec2(ui.available_width().max(200.0), 24.0), edit);
    });
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState, ctx: &egui::Context) {
    ui.heading(
        egui::RichText::new("CREATE NEW CASE")
            .color(theme::TEXT)
            .strong()
            .size(20.0),
    );
    ui.add_space(8.0);

    let running = state.acquisition_running();
    egui::ScrollArea::vertical().show(ui, |ui| {
        // ---------------- CASE DETAILS ----------------
        section_heading(ui, "Case Details");
        card().show(ui, |ui| {
            labeled_field(ui, "Case ID", &mut state.form.case_id, "CASE-2026-0001");
            if ui.small_button("regenerate id").clicked() {
                state.form.case_id = suggest_case_id();
            }
            labeled_field(ui, "Case Name", &mut state.form.case_name, "Short case title");
            labeled_field(
                ui,
                "Investigator Name",
                &mut state.form.investigator_name,
                "Operator acquiring the evidence",
            );
            labeled_field(ui, "Organization", &mut state.form.organization, "Optional");
            labeled_field(
                ui,
                "Reference Number",
                &mut state.form.reference_number,
                "Optional reference number",
            );
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Evidence Description").color(theme::TEXT_DIM).size(13.0));
            ui.add_sized(
                egui::vec2(ui.available_width(), 54.0),
                egui::TextEdit::multiline(&mut state.form.evidence_description)
                    .hint_text("What is being acquired and why")
                    .background_color(theme::PANEL)
                    .text_color(theme::TEXT),
            );
            ui.label(egui::RichText::new("Acquisition Notes").color(theme::TEXT_DIM).size(13.0));
            ui.add_sized(
                egui::vec2(ui.available_width(), 54.0),
                egui::TextEdit::multiline(&mut state.form.acquisition_notes)
                    .hint_text("Conditions, legal basis, observations")
                    .background_color(theme::PANEL)
                    .text_color(theme::TEXT),
            );
        });

        // ---------------- DESTINATION ----------------
        ui.add_space(10.0);
        section_heading(ui, "Evidence Location");
        card().show(ui, |ui| {
            ui.label(
                egui::RichText::new("Where should the evidence case be saved?")
                    .color(theme::TEXT)
                    .size(13.0),
            );
            ui.horizontal(|ui| {
                let edit = egui::TextEdit::singleline(&mut state.form.destination)
                    .hint_text("Destination folder")
                    .background_color(theme::PANEL)
                    .text_color(theme::TEXT);
                ui.add_sized(egui::vec2(ui.available_width() - 140.0, 24.0), edit);
                if ui.button("BROWSE...").clicked() {
                    if let Some(folder) = rfd::FileDialog::new()
                        .set_title("Select evidence destination folder")
                        .pick_folder()
                    {
                        state.form.destination = folder.to_string_lossy().into_owned();
                    }
                    ctx.request_repaint();
                }
            });
        });

        // ---------------- ACQUISITION PROFILE ----------------
        ui.add_space(10.0);
        section_heading(ui, "Acquisition Profile");
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("SELECT ALL").clicked() {
                    state.selected = CollectorId::all().iter().copied().collect();
                }
                if ui.button("SELECT RECOMMENDED").clicked() {
                    state.selected = CollectorId::recommended().into_iter().collect();
                }
                if ui.button("CLEAR ALL").clicked() {
                    state.selected.clear();
                }
            });
            ui.add_space(6.0);
            egui::Grid::new("module_grid")
                .num_columns(2)
                .spacing(egui::vec2(24.0, 6.0))
                .show(ui, |ui| {
                    for id in CollectorId::all() {
                        let mut checked = state.selected.contains(id);
                        let label = match id {
                            CollectorId::Memory => "Memory (artifact mode)",
                            other => other.display_name(),
                        };
                        if ui.checkbox(&mut checked, label).changed() {
                            if checked {
                                state.selected.insert(*id);
                            } else {
                                state.selected.remove(id);
                            }
                        }
                        ui.end_row();
                    }
                });
            ui.add_space(6.0);
            let demo = ui.checkbox(
                &mut state.form.demo_mode,
                egui::RichText::new("DEMO MODE - SYNTHETIC DEMONSTRATION DATA (not real evidence)")
                    .color(theme::YELLOW),
            );
            let _ = demo;
        });

        // ---------------- START ----------------
        ui.add_space(12.0);
        let form = state.form.to_case_info();
        let valid = form.is_valid() && !state.selected.is_empty() && !running;
        let mut message = String::new();
        if running {
            message = "An acquisition is already running.".to_string();
        } else if state.form.case_id.trim().is_empty() {
            message = "Case ID is required.".to_string();
        } else if state.form.case_name.trim().is_empty() {
            message = "Case Name is required.".to_string();
        } else if state.form.investigator_name.trim().is_empty() {
            message = "Investigator Name is required.".to_string();
        } else if state.form.destination.trim().is_empty() {
            message = "Choose a destination folder.".to_string();
        } else if state.selected.is_empty() {
            message = "Select at least one acquisition module.".to_string();
        }

        ui.horizontal(|ui| {
            let start = ui.add_enabled(
                valid,
                egui::Button::new(
                    egui::RichText::new("START ACQUISITION")
                        .color(theme::BG)
                        .strong()
                        .size(14.0),
                )
                .fill(theme::ACCENT)
                .min_size(egui::vec2(220.0, 40.0)),
            );
            if !message.is_empty() {
                ui.label(egui::RichText::new(message).color(theme::YELLOW).size(12.5));
            }
            if start.clicked() {
                // Reset shared state and launch the engine worker thread.
                *state.progress.lock().unwrap() = AcquisitionProgress::new();
                state.control = Arc::new(AcquisitionControl::new());
                state.last_manifest = None;
                state.last_aif = None;
                state.banner = None;

                let params = AcquisitionParams {
                    case: form,
                    modules: CollectorId::all()
                        .iter()
                        .copied()
                        .filter(|id| state.selected.contains(id))
                        .collect(),
                    settings: state.settings.clone(),
                };
                let progress = Arc::clone(&state.progress);
                let control = Arc::clone(&state.control);
                std::thread::spawn(move || {
                    engine::run_acquisition(params, progress, control);
                });
                state.screen = Screen::Acquisition;
                ctx.request_repaint();
            }
        });
    });
}
