//! MEMO Collector - forensic evidence acquisition engine library.
//!
//! This crate implements the acquisition engine of the NEUROFORENSICS AI
//! platform. It only ACQUIRES and PRESERVES evidence; it performs no
//! analysis, detection or interpretation.

pub mod app;
pub mod collectors;
pub mod evidence;
pub mod gui;
pub mod hashing;
pub mod reporting;
pub mod win;

pub const APP_NAME: &str = "MEMO Collector";
pub const APP_PLATFORM: &str = "NEUROFORENSICS AI";
pub const APP_TAGLINE: &str = "Volatile Evidence. Stronger Forensics.";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_BUILD: &str = "1.0.0-mvp";
pub const AIF_EXTENSION: &str = "AIF";
pub const AIF_FORMAT_NAME: &str =
    "AIF - Acquisition & Investigation Forensic Evidence Container";
