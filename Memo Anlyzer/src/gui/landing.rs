//! Case-management landing screen: CREATE NEW CASE / OPEN EXISTING CASE.
//!
//! Mirrors professional forensic tools: the application starts here,
//! before any evidence can be examined. No demo mode — real cases only.

use eframe::egui::{self, Align, Color32, Layout, RichText, Ui};

use crate::casemgmt;
use crate::casemgmt::db::CaseDatabase;

use super::state::{AppState, LandingTab, Screen, Session};
use super::theme::{self, palette, Palette};

pub fn draw(app: &mut AppState, ctx: &egui::Context) {
    let p = palette(app.theme);
    // Keep the recent-case list in sync with persisted settings.
    if app.landing.tab == LandingTab::Recent && app.landing.recent.is_empty() {
        app.landing.refresh_recent(&app.settings);
    }
    // Reference chrome: navy gradient titlebar above the landing body.
    theme::draw_titlebar(ctx, &p, None);
    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(p.panel_deep).inner_margin(0))
        .show(ctx, |ui| {
            egui::ScrollArea::both().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(36.0);
                    header(ui, &p);
                    ui.add_space(20.0);
                    card(app, ui, &p);
                    ui.add_space(24.0);
                    ui.label(
                        RichText::new("Every examination is bound to a persistent case database. Evidence is read-only; no data is ever fabricated.")
                            .color(p.text_dim)
                            .size(12.0),
                    );
                });
            });
        });
}

fn header(ui: &mut Ui, p: &Palette) {
    ui.label(RichText::new("NEUROFORENSICS AI").size(26.0).strong().color(p.text));
    ui.add_space(2.0);
    ui.label(
        RichText::new("Forensic Case-Management & Evidence Analysis Workstation")
            .size(13.0)
            .color(p.text_dim),
    );
}

fn card(app: &mut AppState, ui: &mut Ui, p: &Palette) {
    let width = ui.available_width().min(720.0).max(560.0);
    egui::Frame::default()
        .fill(p.panel)
        .corner_radius(10.0)
        .stroke(egui::Stroke::new(1.0_f32, p.border))
        .inner_margin(22.0)
        .show(ui, |ui| {
            ui.set_min_width(width);
            // Tab switcher
            ui.horizontal(|ui| {
                tab_button(ui, p, app.landing.tab == LandingTab::Create, "CREATE NEW CASE", || {
                    app.landing.tab = LandingTab::Create;
                    app.landing.error = None;
                });
                ui.add_space(6.0);
                tab_button(ui, p, app.landing.tab == LandingTab::Open, "OPEN EXISTING CASE", || {
                    app.landing.tab = LandingTab::Open;
                    app.landing.error = None;
                    app.landing.refresh_discovered();
                });
                ui.add_space(6.0);
                tab_button(ui, p, app.landing.tab == LandingTab::Recent, "RECENT CASES", || {
                    app.landing.tab = LandingTab::Recent;
                    app.landing.error = None;
                    app.landing.refresh_recent(&app.settings);
                });
            });
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(10.0);

            match app.landing.tab {
                LandingTab::Create => create_form(app, ui, p),
                LandingTab::Open => open_panel(app, ui, p),
                LandingTab::Recent => recent_panel(app, ui, p),
            }

            if let Some(err) = app.landing.error.clone() {
                ui.add_space(10.0);
                ui.label(RichText::new(format!("⚠ {err}")).color(p.danger));
            }

            // Workstation-level actions (spec §3: SETTINGS / EXIT).
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("SETTINGS").clicked() {
                    app.show_settings = true;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("EXIT").clicked() {
                        std::process::exit(0);
                    }
                });
            });
        });
}

fn tab_button(ui: &mut Ui, p: &Palette, active: bool, label: &str, on: impl FnOnce()) {
    let fill = if active { p.accent } else { p.chrome };
    let text = if active { Color32::WHITE } else { p.text };
    let response = ui.add(
        egui::Button::new(RichText::new(label).color(text).size(13.0).strong())
            .fill(fill)
            .corner_radius(6.0)
            .min_size(egui::vec2(200.0, 34.0)),
    );
    if response.clicked() {
        on();
    }
}

fn field_row(ui: &mut Ui, label: &str, value: &mut String, required: bool) {
    ui.horizontal(|ui| {
        let caption = if required {
            format!("{label} *")
        } else {
            label.to_string()
        };
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.label(RichText::new(caption).size(12.5).weak());
        });
        ui.add_sized([220.0, 24.0], egui::TextEdit::singleline(value));
    });
}

fn create_form(app: &mut AppState, ui: &mut Ui, p: &Palette) {
    ui.label(RichText::new("Register a new examination. A case folder with a persistent SQLite database is created.").color(p.text_dim).size(12.0));
    ui.add_space(12.0);

    egui::Grid::new("create_case_grid")
        .min_col_width(150.0)
        .spacing([12.0, 10.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Case number *").weak());
            ui.add_sized([420.0, 24.0], egui::TextEdit::singleline(&mut app.landing.form.case_number).hint_text("e.g. CASE-2026-1071"));
            ui.end_row();

            ui.label(RichText::new("Case name *").weak());
            ui.add_sized([420.0, 24.0], egui::TextEdit::singleline(&mut app.landing.form.case_name).hint_text("Descriptive case title"));
            ui.end_row();

            ui.label(RichText::new("Examiner *").weak());
            ui.add_sized([420.0, 24.0], egui::TextEdit::singleline(&mut app.landing.form.examiner).hint_text("Lead examiner"));
            ui.end_row();

            ui.label(RichText::new("Organization").weak());
            ui.add_sized([420.0, 24.0], egui::TextEdit::singleline(&mut app.landing.form.organization).hint_text("Agency / company"));
            ui.end_row();

            ui.label(RichText::new("Description").weak());
            ui.add_sized([420.0, 44.0], egui::TextEdit::multiline(&mut app.landing.form.description).hint_text("Scope of the examination"));
            ui.end_row();

            ui.label(RichText::new("Case directory *").weak());
            ui.horizontal(|ui| {
                ui.add_sized([330.0, 24.0], egui::TextEdit::singleline(&mut app.landing.dir_text));
                if ui.button("Browse…").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        app.landing.dir_text = dir.display().to_string();
                    }
                }
            });
            ui.end_row();
        });

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        let create = ui.add(
            egui::Button::new(RichText::new("CREATE CASE").color(Color32::WHITE).strong())
                .fill(p.accent)
                .min_size(egui::vec2(160.0, 34.0)),
        );
        if create.clicked() {
            app.landing.form.directory = std::path::PathBuf::from(app.landing.dir_text.trim());
            match casemgmt::create_case(&app.landing.form) {
                Ok(folder) => {
                    match CaseDatabase::open(&folder.db_path) {
                        Ok(db) => {
                            remember(app, &folder);
                            app.session = Some(Session::new(folder.clone(), db));
                            app.screen = Screen::Workstation;
                            app.toast(format!("Case created at {}", folder.dir.display()), false);
                        }
                        Err(e) => app.landing.error = Some(e),
                    }
                }
                Err(e) => app.landing.error = Some(e),
            }
        }
        ui.label(RichText::new("Fields marked * are required.").color(p.text_dim).size(11.5));
    });
}

fn open_panel(app: &mut AppState, ui: &mut Ui, p: &Palette) {
    ui.label(
        RichText::new("Open a NeuroForensics case folder and restore its database: indexed evidence, artifacts, findings and examination state.")
            .color(p.text_dim)
            .size(12.0),
    );
    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.label(RichText::new("Look in:").weak());
        ui.add_sized([420.0, 24.0], egui::TextEdit::singleline(&mut app.landing.browse_root_text));
        if ui.button("Browse…").clicked() {
            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                app.landing.browse_root = dir.clone();
                app.landing.browse_root_text = dir.display().to_string();
                app.landing.refresh_discovered();
            }
        }
        if ui.button("Scan").clicked() {
            app.landing.browse_root = std::path::PathBuf::from(app.landing.browse_root_text.trim());
            app.landing.refresh_discovered();
        }
    });
    ui.add_space(8.0);

    egui::Frame::default()
        .fill(p.panel_deep)
        .corner_radius(6.0)
        .inner_margin(6.0)
        .show(ui, |ui| {
            ui.set_min_height(150.0);
            if app.landing.discovered.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(56.0);
                    ui.label(
                        RichText::new("No case folders found here. Scan the directory that holds your cases, or browse directly to a case folder / case.db file.")
                            .color(p.text_dim),
                    );
                });
            } else {
                egui::ScrollArea::vertical().max_height(220.0).show_rows(
                    ui,
                    26.0,
                    app.landing.discovered.len(),
                    |ui, range| {
                        for i in range {
                            let folder = app.landing.discovered[i].clone();
                            let name = folder
                                .dir
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| folder.dir.display().to_string());
                            let response = ui.horizontal(|ui| {
                                ui.label(RichText::new("🗀").color(p.accent));
                                ui.label(RichText::new(&name).strong());
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(folder.dir.display().to_string()).weak().size(11.0));
                                });
                            });
                            // horizontal() allocates hover-only; re-interact with a
                            // click sense or the row never fires.
                            if response
                                .response
                                .interact(egui::Sense::click())
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .clicked()
                            {
                                open_folder(app, folder);
                            }
                        }
                    },
                );
            }
        });

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        if ui.button("Browse to case folder / case.db…").clicked() {
            if let Some(file) = rfd::FileDialog::new()
                .add_filter("NeuroForensics case", &["db"])
                .pick_file()
            {
                match casemgmt::locate_case(&file) {
                    Ok(folder) => open_folder(app, folder),
                    Err(e) => app.landing.error = Some(e),
                }
            }
        }
    });
}

fn recent_panel(app: &mut AppState, ui: &mut Ui, p: &Palette) {
    ui.label(
        RichText::new("Cases opened on this workstation, newest first. Entries whose database no longer exists are dropped automatically.")
            .color(p.text_dim)
            .size(12.0),
    );
    ui.add_space(10.0);

    if app.landing.recent.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(46.0);
            ui.label(RichText::new("No recent cases yet — create or open a case first.").color(p.text_dim));
        });
        return;
    }

    egui::Frame::default()
        .fill(p.panel_deep)
        .corner_radius(6.0)
        .inner_margin(6.0)
        .show(ui, |ui| {
            ui.set_min_height(150.0);
            egui::ScrollArea::vertical().max_height(240.0).show_rows(
                ui,
                40.0,
                app.landing.recent.len(),
                |ui, range| {
                    for i in range {
                        let summary = app.landing.recent[i].clone();
                        let response = egui::Frame::default().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("🗀").color(p.accent));
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{} — {}",
                                            summary.case_number, summary.case_name
                                        ))
                                        .strong()
                                        .size(12.0),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "Examiner {} · created {} · last opened {} · {} evidence image(s) · {}",
                                            if summary.examiner.is_empty() { "?" } else { &summary.examiner },
                                            if summary.created_at.is_empty() { "?" } else { &summary.created_at },
                                            if summary.last_opened.is_empty() { "never" } else { &summary.last_opened },
                                            summary.evidence_count,
                                            summary.folder.dir.display()
                                        ))
                                        .color(p.text_dim)
                                        .size(10.5),
                                    );
                                });
                            });
                        });
                        // Frame::show allocates hover-only; re-interact with a
                        // click sense or the row never fires.
                        if response
                            .response
                            .interact(egui::Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            open_folder(app, summary.folder);
                        }
                    }
                },
            );
        });
}

fn open_folder(app: &mut AppState, folder: casemgmt::CaseFolder) {
    match CaseDatabase::open(&folder.db_path) {
        Ok(mut db) => {
            db.mark_opened();
            // §41: opening a case is itself a custody-relevant event.
            let _ = db.log_custody("CASE OPENED", &format!("{}", folder.db_path.display()));
            remember(app, &folder);
            let mut session = Session::new(folder.clone(), db);
            session.restore_findings();
            // §21/§22: search index + timeline survive restarts.
            session.restore_persistent_index();
            // §35/§36: finding status + investigator notes survive restarts.
            session.refresh_finding_workflow();
            app.session = Some(session);
            app.screen = Screen::Workstation;
            app.toast(format!("Case restored from {}", folder.db_path.display()), false);
            // Reload the registered evidence image (read-only) so the
            // workstation shows the examiner's data, not an empty shell.
            super::workstation::try_restore_evidence(app);
        }
        Err(e) => app.landing.error = Some(e),
    }
}

/// Record the case in the persisted recent-case list (spec §3).
fn remember(app: &mut AppState, folder: &casemgmt::CaseFolder) {
    app.settings.remember_case(&folder.db_path.display().to_string());
    let _ = app.settings.save();
}
