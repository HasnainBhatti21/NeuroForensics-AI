//! NEUROFORENSICS AI workstation GUI — professional forensic layout:
//! landing (case management) ⇄ workstation (tree, explorer, viewer,
//! timeline, network, findings, AI panel). Dark and light themes.

pub mod ai_chat;
pub mod app;
pub mod correlation_view;
pub mod evidence;
pub mod explorer;
pub mod findings;
pub mod landing;
pub mod network_view;
pub mod parsed;
pub mod settings;
pub mod state;
pub mod theme;
pub mod timeline;
pub mod tree;
pub mod workstation;

/// Human-readable byte sizes for tables and status bars.
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::fmt_bytes;

    #[test]
    fn byte_formatting_is_readable() {
        assert_eq!(fmt_bytes(412), "412 B");
        assert_eq!(fmt_bytes(412_953), "403.3 KiB");
        assert_eq!(fmt_bytes(3_221_225_472), "3.0 GiB");
    }
}
