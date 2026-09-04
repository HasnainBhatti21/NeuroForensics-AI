//! SETTINGS dialog: theme, workspace root and external AI endpoint.
//!
//! All values persist through [`AppSettings`] (%APPDATA%\NeuroForensicsAI
//! \settings.json). The AI endpoint is display/configuration only — the
//! analyzer core works fully offline and never calls it implicitly.

use eframe::egui::{self, RichText};

use super::state::AppState;
use super::theme::{palette, ThemeMode};

pub fn draw(app: &mut AppState, ctx: &egui::Context) {
    if !app.show_settings {
        return;
    }
    let p = palette(app.theme);
    let mut open = true;
    egui::Window::new("Settings")
        .open(&mut open)
        .resizable(true)
        .default_width(520.0)
        .show(ctx, |ui| {
            ui.label(RichText::new("APPEARANCE").color(p.text_dim).strong().size(11.0));
            ui.horizontal(|ui| {
                ui.label("Theme");
                for mode in [ThemeMode::Dark, ThemeMode::Light] {
                    if ui
                        .selectable_label(app.theme == mode, mode.label())
                        .clicked()
                        && app.theme != mode
                    {
                        app.toggle_theme();
                    }
                }
            });
            ui.add_space(8.0);

            ui.label(RichText::new("WORKSPACE").color(p.text_dim).strong().size(11.0));
            ui.horizontal(|ui| {
                ui.label("Workspace root");
                ui.add_sized(
                    [ui.available_width() - 10.0, 24.0],
                    egui::TextEdit::singleline(&mut app.settings.workspace_root),
                );
            });
            ui.label(
                RichText::new("Parent directory used when suggesting case and export locations.")
                    .color(p.text_dim)
                    .size(11.0),
            );
            ui.add_space(8.0);

            ui.label(RichText::new("AI PROVIDER").color(p.text_dim).strong().size(11.0));
            ui.horizontal(|ui| {
                ui.label("Endpoint (optional)");
                ui.add_sized(
                    [ui.available_width() - 10.0, 24.0],
                    egui::TextEdit::singleline(&mut app.settings.ai_endpoint)
                        .hint_text("empty = fully local / offline"),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Protocol");
                let current = app.settings.ai_flavor.clone();
                egui::ComboBox::from_id_salt("ai_flavor_selector")
                    .selected_text(match current.as_str() {
                        "openai" => "OpenAI-compatible",
                        "alibaba" => "Alibaba-compatible",
                        "custom" => "Custom API",
                        _ => "Auto-detect from URL",
                    })
                    .width(180.0)
                    .show_ui(ui, |ui| {
                        for (value, label) in [
                            ("auto", "Auto-detect from URL"),
                            ("openai", "OpenAI-compatible"),
                            ("alibaba", "Alibaba-compatible"),
                            ("custom", "Custom API"),
                        ] {
                            if ui.selectable_label(current.as_str() == value, label).clicked() {
                                app.settings.ai_flavor = value.to_string();
                            }
                        }
                    });
            });
            ui.label(
                RichText::new(
                    "Leave empty to run the AI investigator fully local/offline. \
                     An endpoint configures an external provider; it is never called implicitly. \
                     Choose Custom API for local servers whose URL does not match auto-detection.",
                )
                .color(p.text_dim)
                .size(11.0),
            );
            ui.add_space(12.0);

            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    match app.settings.save() {
                        Ok(()) => {
                            app.toast("Settings saved.", false);
                            app.show_settings = false;
                        }
                        Err(e) => app.toast(format!("Settings could not be saved: {e}"), true),
                    }
                }
                if ui.button("Cancel").clicked() {
                    // Revert in-memory edits by reloading the persisted copy.
                    app.settings = crate::appsettings::AppSettings::load();
                    app.show_settings = false;
                }
            });
        });
    if !open {
        app.show_settings = false;
    }
}
