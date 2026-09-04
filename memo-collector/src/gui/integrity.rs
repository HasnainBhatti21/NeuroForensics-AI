//! INTEGRITY screen - VERIFY AIF (container hash + deep artifact check).

use eframe::egui;

use super::{card, section_heading, theme};
use crate::app::engine;
use crate::app::state::AppState;

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading(
        egui::RichText::new("INTEGRITY VERIFICATION")
            .color(theme::TEXT)
            .strong()
            .size(20.0),
    );
    ui.add_space(8.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        section_heading(ui, "Verify AIF");
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("AIF file").color(theme::TEXT_DIM));
                let edit = egui::TextEdit::singleline(&mut state.verify_path)
                    .hint_text("path to CASE-XXXX.AIF")
                    .background_color(theme::PANEL)
                    .text_color(theme::TEXT);
                ui.add_sized(egui::vec2(ui.available_width() - 200.0, 24.0), edit);
                if ui.button("BROWSE...").clicked() {
                    if let Some(file) = rfd::FileDialog::new()
                        .set_title("Select AIF case container")
                        .add_filter("AIF case", &["AIF", "aif"])
                        .pick_file()
                    {
                        state.verify_path = file.display().to_string();
                        // Auto-load the sidecar hash when present.
                        let sidecar = format!("{}.sha256", state.verify_path);
                        if let Ok(content) = std::fs::read_to_string(&sidecar) {
                            if let Some(hash) = content.split_whitespace().next() {
                                state.verify_expected = hash.to_string();
                            }
                        }
                    }
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Expected hash").color(theme::TEXT_DIM));
                let edit = egui::TextEdit::singleline(&mut state.verify_expected)
                    .hint_text("SHA-256 from the .sha256 sidecar or custody record")
                    .font(egui::TextStyle::Monospace)
                    .background_color(theme::PANEL)
                    .text_color(theme::TEXT);
                ui.add_sized(egui::vec2(ui.available_width(), 24.0), edit);
            });
            ui.add_space(8.0);
            let ready = !state.verify_path.trim().is_empty() && !state.verify_expected.trim().is_empty();
            if ui
                .add_enabled(ready, egui::Button::new("VERIFY AIF").min_size(egui::vec2(160.0, 32.0)))
                .clicked()
            {
                state.verify_result = None;
                state.verify_error = None;
                let path = std::path::PathBuf::from(state.verify_path.trim());
                let expected = state.verify_expected.trim().to_string();
                match engine::verify_case(&path, &expected) {
                    Ok((container, artifacts)) => {
                        state.verify_result = Some(crate::app::state::VerifyResult {
                            path,
                            container,
                            artifacts,
                        });
                    }
                    Err(e) => state.verify_error = Some(e),
                }
            }
        });

        if let Some(error) = &state.verify_error {
            ui.add_space(8.0);
            card().show(ui, |ui| {
                ui.colored_label(theme::RED, format!("✗ {}", error));
            });
        }

        if let Some(result) = &state.verify_result {
            ui.add_space(12.0);
            section_heading(ui, "Verification Result");
            card().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Expected Hash:").color(theme::TEXT_DIM));
                    ui.monospace(&result.container.expected);
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Calculated Hash:").color(theme::TEXT_DIM));
                    ui.monospace(&result.container.calculated);
                });
                ui.add_space(6.0);
                if result.container.verified {
                    ui.colored_label(theme::GREEN, "✓ INTEGRITY VERIFIED (container SHA-256)");
                } else {
                    ui.colored_label(theme::RED, "✗ INTEGRITY MISMATCH (container SHA-256)");
                }

                ui.add_space(8.0);
                let ok = result.artifacts.iter().filter(|a| a.verified).count();
                let total = result.artifacts.len();
                if result.artifacts_ok() {
                    ui.colored_label(
                        theme::GREEN,
                        format!("✓ ALL {} MANIFEST ARTIFACT HASHES VERIFIED", total),
                    );
                } else {
                    ui.colored_label(
                        theme::RED,
                        format!("✗ ARTIFICAT INTEGRITY MISMATCH: {} / {} verified", ok, total),
                    );
                    egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                        for artifact in &result.artifacts {
                            if !artifact.verified {
                                ui.colored_label(
                                    theme::RED,
                                    format!(
                                        "{} {} expected {} got {}",
                                        artifact.artifact_id,
                                        artifact.relative_path,
                                        &artifact.expected,
                                        if artifact.calculated.is_empty() {
                                            "(missing)"
                                        } else {
                                            &artifact.calculated
                                        }
                                    ),
                                );
                            }
                        }
                    });
                }
            });
        }
    });
}
