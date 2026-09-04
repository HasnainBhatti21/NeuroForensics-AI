//! MEMO Collector - portable Windows forensic evidence acquisition GUI.
//!
//! Single portable executable: no installer, no runtime dependencies.

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title(format!("{} - {}", memo_collector::APP_NAME, memo_collector::APP_PLATFORM))
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([980.0, 640.0])
            .with_icon(memo_collector::gui::app_icon()),
        ..Default::default()
    };

    eframe::run_native(
        &format!("{} - {}", memo_collector::APP_NAME, memo_collector::APP_PLATFORM),
        options,
        Box::new(|cc| Ok(Box::new(memo_collector::gui::MemoApp::new(cc)))),
    )
}
