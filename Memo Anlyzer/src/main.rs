//! NEUROFORENSICS AI — AI-Powered CPU & GPU Forensic Analyzer.
//!
//! Analysis component of the MEMO Collector forensic framework.
//! It opens `.AIF` case files produced by MEMO Collector and analyzes
//! ONLY the evidence actually present in the case. It never fabricates
//! evidence, never collects from the investigator's live system, and
//! treats the original AIF as strictly read-only.

// Many struct fields mirror the AIF/collector contract and are parsed
// from evidence (serde) even when the UI does not display them yet.
#![allow(dead_code)]

mod ai;
mod aifzip;
mod analysis;
mod appsettings;
mod casemgmt;
mod correlation;
mod gui;
mod ingest;
mod ml;
mod reporting;

// §39 fixture-driven regression (tests/fixtures/) — compiled for tests only.
#[cfg(test)]
mod fixture_tests;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NeuroForensics AI — Case Examiner")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1080.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "NEUROFORENSICS AI",
        options,
        Box::new(|_cc| Ok(Box::new(gui::app::NeuroForensicsApp::new()))),
    )
}
