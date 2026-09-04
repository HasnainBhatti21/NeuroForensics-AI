//! Professional dark forensic dashboard built on egui/eframe.
//!
//! Visual language: SOC / digital-forensics / incident-response tooling.
//! Dark surfaces, cyan/blue/purple accents, clean cards, no excessive
//! animation.

pub mod about;
pub mod acquisition;
pub mod case_creation;
pub mod case_info;
pub mod dashboard;
pub mod evidence;
pub mod integrity;
pub mod settings;

use std::time::Duration;

use eframe::egui;

use crate::app::state::{format_duration, AppState, Screen};

/// Theme palette.
pub mod theme {
    use eframe::egui::Color32;

    pub const BG: Color32 = Color32::from_rgb(10, 14, 20);
    pub const PANEL: Color32 = Color32::from_rgb(17, 23, 33);
    pub const CARD: Color32 = Color32::from_rgb(22, 30, 44);
    pub const CARD_ALT: Color32 = Color32::from_rgb(27, 36, 52);
    pub const BORDER: Color32 = Color32::from_rgb(45, 58, 80);
    pub const TEXT: Color32 = Color32::from_rgb(214, 224, 236);
    pub const TEXT_DIM: Color32 = Color32::from_rgb(130, 143, 160);
    pub const ACCENT: Color32 = Color32::from_rgb(34, 211, 238); // cyan
    pub const BLUE: Color32 = Color32::from_rgb(59, 130, 246);
    pub const PURPLE: Color32 = Color32::from_rgb(167, 139, 250);
    pub const GREEN: Color32 = Color32::from_rgb(52, 211, 153);
    pub const YELLOW: Color32 = Color32::from_rgb(250, 204, 21);
    pub const RED: Color32 = Color32::from_rgb(248, 113, 113);
    pub const NAV_ACTIVE: Color32 = Color32::from_rgb(13, 43, 61);
}

/// Apply the dark forensic theme once.
pub fn apply_theme(ctx: &egui::Context) {
    ctx.style_mut(|style| {
        style.visuals = egui::Visuals::dark();
        style.visuals.override_text_color = Some(theme::TEXT);
        style.visuals.window_fill = theme::BG;
        style.visuals.panel_fill = theme::BG;
        style.visuals.widgets.noninteractive.bg_fill = theme::PANEL;
        style.visuals.widgets.inactive.bg_fill = theme::CARD;
        style.visuals.widgets.hovered.bg_fill = theme::CARD_ALT;
        style.visuals.widgets.active.bg_fill = theme::ACCENT;
        style.visuals.selection.bg_fill = Color32::from_rgb(14, 60, 86);
        style.visuals.widgets.noninteractive.fg_stroke.color = theme::TEXT_DIM;
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 7.0);
        style.visuals.window_corner_radius = egui::CornerRadius::same(6);
        style.visuals.menu_corner_radius = egui::CornerRadius::same(6);
    });
}

use egui::Color32;

/// Card frame used across all screens.
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(theme::CARD)
        .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::same(14))
}

/// Section heading ("FORENSIC" uppercase style).
pub fn section_heading(ui: &mut egui::Ui, title: &str) {
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(title.to_uppercase())
            .color(theme::PURPLE)
            .strong()
            .size(12.0),
    );
    ui.separator();
}

/// Key/value status row.
pub fn status_row(ui: &mut egui::Ui, key: &str, value: &str, value_color: Color32) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(key).color(theme::TEXT_DIM).size(13.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).color(value_color).strong().size(13.0));
        });
    });
}

/// Status color helper.
pub fn state_color(state: crate::collectors::ModuleState) -> Color32 {
    use crate::collectors::ModuleState::*;
    match state {
        Pending => theme::TEXT_DIM,
        Running => theme::ACCENT,
        Completed => theme::GREEN,
        Skipped => theme::YELLOW,
        Failed => theme::RED,
        Cancelled => theme::YELLOW,
    }
}

/// Procedural window icon (rounded dark square with a cyan shield core).
pub fn app_icon() -> egui::IconData {
    let size = 64u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let center = size as f32 / 2.0;
    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            let dx = x as f32 - center + 0.5;
            let dy = y as f32 - center + 0.5;
            let dist = (dx * dx + dy * dy).sqrt();
            // Rounded square mask.
            let half = size as f32 / 2.0 - 1.0;
            let rx = dx.abs().max(half - 12.0);
            let ry = dy.abs().max(half - 12.0);
            let corner = (rx * rx + ry * ry).sqrt();
            let inside = corner <= half;
            if !inside {
                continue;
            }
            let (r, g, b) = if dist < 12.0 {
                (34, 211, 238) // cyan core
            } else if dist < 22.0 {
                (16, 52, 74) // ring
            } else {
                (14, 20, 30) // dark body
            };
            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 255;
        }
    }
    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}

/// Root application.
pub struct MemoApp {
    pub state: AppState,
}

impl MemoApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        let mut app = Self {
            state: AppState::new(),
        };
        if !app.state.status.admin {
            app.state.banner = Some(
                "Some forensic acquisition sources require elevated Windows privileges.".into(),
            );
        }
        app
    }

    fn nav_button(ui: &mut egui::Ui, screen: Screen, current: &mut Screen, label: &str, icon: &str) {
        let active = *current == screen;
        let response = ui
            .add_sized(
                egui::vec2(ui.available_width(), 34.0),
                egui::Button::new(
                    egui::RichText::new(format!("{}  {}", icon, label))
                        .color(if active { theme::ACCENT } else { theme::TEXT })
                        .size(13.5),
                )
                .fill(if active { theme::NAV_ACTIVE } else { Color32::TRANSPARENT })
                .stroke(if active {
                    egui::Stroke::new(1.0_f32, Color32::from_rgb(21, 74, 102))
                } else {
                    egui::Stroke::NONE
                })
                .corner_radius(egui::CornerRadius::same(6)),
            );
        if response.clicked() {
            *current = screen;
        }
    }
}

impl eframe::App for MemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Live elapsed/throughput bookkeeping while acquiring.
        {
            let mut p = self.state.progress.lock().unwrap();
            if p.running {
                if let Some(started) = &p.started_at {
                    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(started) {
                        let elapsed = chrono::Local::now()
                            .signed_duration_since(t.with_timezone(&chrono::Local));
                        p.elapsed_seconds = elapsed.num_seconds().max(0) as u64;
                        p.throughput_bytes_per_sec = if p.elapsed_seconds > 0 {
                            p.bytes_acquired / p.elapsed_seconds
                        } else {
                            0
                        };
                    }
                }
            }
        }

        // ---------------- Sidebar ----------------
        egui::SidePanel::left("nav_panel")
            .exact_width(216.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::PANEL)
                    .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
                    .inner_margin(egui::Margin::same(10)),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("NEUROFORENSICS AI")
                            .color(theme::PURPLE)
                            .strong()
                            .size(12.0),
                    );
                    ui.label(
                        egui::RichText::new("MEMO COLLECTOR")
                            .color(theme::ACCENT)
                            .strong()
                            .size(18.0),
                    );
                    ui.label(
                        egui::RichText::new(crate::APP_TAGLINE)
                            .color(theme::TEXT_DIM)
                            .size(10.5),
                    );
                    ui.add_space(10.0);
                });
                ui.separator();
                ui.add_space(6.0);
                Self::nav_button(ui, Screen::Dashboard, &mut self.state.screen, "DASHBOARD", "▣");
                Self::nav_button(ui, Screen::NewCase, &mut self.state.screen, "NEW CASE", "＋");
                Self::nav_button(ui, Screen::Acquisition, &mut self.state.screen, "ACQUISITION", "⟳");
                Self::nav_button(ui, Screen::Evidence, &mut self.state.screen, "EVIDENCE", "🗎");
                Self::nav_button(ui, Screen::Integrity, &mut self.state.screen, "INTEGRITY", "✓");
                Self::nav_button(ui, Screen::CaseInfo, &mut self.state.screen, "CASE INFO", "ℹ");
                Self::nav_button(ui, Screen::Settings, &mut self.state.screen, "SETTINGS", "⚙");
                Self::nav_button(ui, Screen::About, &mut self.state.screen, "ABOUT", "◈");
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.separator();
                    let admin = self.state.status.admin;
                    ui.label(
                        egui::RichText::new(if admin {
                            "● ELEVATED SESSION"
                        } else {
                            "● STANDARD SESSION"
                        })
                        .color(if admin { theme::GREEN } else { theme::YELLOW })
                        .size(11.0),
                    );
                    ui.label(
                        egui::RichText::new(format!("v{}", crate::APP_VERSION))
                            .color(theme::TEXT_DIM)
                            .size(11.0),
                    );
                    ui.add_space(4.0);
                });
            });

        // ---------------- Banner ----------------
        if let Some(banner) = self.state.banner.clone() {
            egui::TopBottomPanel::top("banner").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("⚠ ").color(theme::YELLOW));
                    ui.label(egui::RichText::new(&banner).color(theme::YELLOW).size(12.5));
                    if self.state.screen == Screen::Dashboard {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("RESTART AS ADMINISTRATOR").clicked() {
                                if crate::win::privs::restart_as_admin().is_ok() {
                                    std::process::exit(0);
                                }
                            }
                            ui.label(egui::RichText::new(" ").size(4.0));
                            if ui.small_button("✕").clicked() {
                                self.state.banner = None;
                            }
                        });
                    }
                });
            });
        }

        // ---------------- Main content ----------------
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::same(18)))
            .show(ctx, |ui| match self.state.screen {
                Screen::Dashboard => dashboard::show(ui, &mut self.state, ctx),
                Screen::NewCase => case_creation::show(ui, &mut self.state, ctx),
                Screen::Acquisition => acquisition::show(ui, &mut self.state, ctx),
                Screen::Evidence => evidence::show(ui, &mut self.state),
                Screen::Integrity => integrity::show(ui, &mut self.state),
                Screen::CaseInfo => case_info::show(ui, &mut self.state),
                Screen::Settings => settings::show(ui, &mut self.state),
                Screen::About => about::show(ui),
            });

        // Keep repainting while an acquisition is live.
        if self.state.acquisition_running() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
    }
}

/// Elapsed label reused by screens.
pub fn elapsed_label(seconds: u64) -> String {
    format_duration(seconds)
}
