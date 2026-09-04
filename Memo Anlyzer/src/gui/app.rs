//! Application root: screen routing (landing ⇄ workstation), theming
//! and the toast layer. All forensic behavior lives in the modules
//! behind `workstation` — this file only frames it.

use eframe::egui;

use super::state::{AppState, Screen};
use super::{ai_chat, landing, settings, theme, workstation};

pub struct NeuroForensicsApp {
    state: AppState,
}

impl NeuroForensicsApp {
    pub fn new() -> Self {
        NeuroForensicsApp { state: AppState::new() }
    }
}

impl Default for NeuroForensicsApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for NeuroForensicsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        theme::apply(ctx, self.state.theme);

        match self.state.screen {
            Screen::Landing => landing::draw(&mut self.state, ctx),
            Screen::Workstation => workstation::draw(&mut self.state, ctx),
        }

        settings::draw(&mut self.state, ctx);
        ai_chat::draw_toasts(&mut self.state, ctx);
    }
}
