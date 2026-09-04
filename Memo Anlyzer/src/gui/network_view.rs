//! Network view: every recorded socket mapped to its process, with
//! watch-list port and remote-access-tool flagging. Data comes solely
//! from `network/connections.json` inside the opened AIF.
//!
//! Rendered as the reference "Process ↔ Network Connection Map": a
//! two-column node diagram (process boxes ↔ remote endpoint boxes)
//! joined by risk-colored connectors — solid and thick for flagged
//! rows, dashed for ordinary traffic.

use eframe::egui::{self, Align2, Color32, Layout, RichText, Stroke, StrokeKind, Ui};

use crate::ingest::streams::ConnectionEntry;

use super::state::AppState;
use super::theme::{paint_icon, palette, Icon, Palette};

const WATCH_PORTS: &[u16] = &[1337, 31337, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 3333, 14444];
const REMOTE_TOOLS: &[&str] = &[
    "anydesk", "teamviewer", "rustdesk", "ultraviewer", "splashtop", "logmein", "vncviewer",
    "tvnserver", "mstsc",
];

/// Node-map geometry (mirrors the reference card).
const ROW_H: f32 = 46.0;
const BOX_H: f32 = 36.0;
const BOX_L_W: f32 = 252.0;
const BOX_R_W: f32 = 220.0;

/// Risk color + flagged state for one connection (reference legend:
/// High risk = remote-access tool, Medium risk = watch-list port,
/// Clean = ordinary traffic).
fn risk(p: &Palette, c: &ConnectionEntry) -> (Color32, bool) {
    let proc_lower = c.process.to_ascii_lowercase();
    let is_remote_tool = REMOTE_TOOLS.iter().any(|t| proc_lower.contains(t));
    let watch_port = WATCH_PORTS.contains(&c.remote_port) || WATCH_PORTS.contains(&c.local_port);
    if is_remote_tool {
        (p.danger, true)
    } else if watch_port {
        (p.warn, true)
    } else {
        (p.good, false)
    }
}

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);
    let net = app.session.as_ref().and_then(|s| s.exam.as_ref()).and_then(|e| e.streams.network.clone());

    ui.horizontal(|ui| {
        let (irect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
        paint_icon(ui.painter(), irect, Icon::Grid, p.accent, 1.8);
        ui.label(RichText::new("Process ↔ Network Connection Map").strong().size(14.0));
        if let Some(net) = &net {
            let established = net
                .connections
                .iter()
                .filter(|c| c.state.eq_ignore_ascii_case("established"))
                .count();
            let flagged = net.connections.iter().filter(|c| risk(&p, c).1).count();
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                stat_card(ui, &p, &net.connections.len().to_string(), "CONNECTIONS", p.text);
                ui.add_space(8.0);
                stat_card(ui, &p, &established.to_string(), "ESTABLISHED", p.accent);
                ui.add_space(8.0);
                stat_card(
                    ui,
                    &p,
                    &flagged.to_string(),
                    "FLAGGED",
                    if flagged > 0 { p.danger } else { p.good },
                );
            });
        }
    });
    if let Some(net) = &net {
        let unique_remotes: std::collections::HashSet<&str> =
            net.connections.iter().map(|c| c.remote_address.as_str()).filter(|a| !a.is_empty()).collect();
        let source = net
            .connections_artifact
            .as_deref()
            .map(|a| format!("source: {a} · network/connections.json"))
            .unwrap_or_else(|| "source: network/connections.json".to_string());
        ui.label(
            RichText::new(format!(
                "{} unique remote address(es) · {source} — derived from Network Connections + Process artifacts",
                unique_remotes.len()
            ))
            .monospace()
            .color(p.text_dim)
            .size(10.5),
        );
    }
    ui.add_space(4.0);
    ui.separator();

    let Some(net) = net else {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            let msg = match &app.session {
                Some(s) if s.exam.is_none() => "No evidence image is open — network data cannot be displayed.",
                _ => "Not present in evidence — the collector did not record network connections for this case.",
            };
            ui.label(RichText::new(msg).color(p.text_dim));
        });
        return;
    };

    if net.connections.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("The collector recorded zero connections.").color(p.text_dim));
        });
        return;
    }

    // Legend (reference .net-legend): round swatches + mono labels.
    let (lrect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 16.0),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(lrect) {
        let painter = ui.painter();
        let legend_font = egui::FontId::new(10.5, egui::FontFamily::Monospace);
        let mut x = lrect.min.x;
        for (color, label) in [(p.danger, "High risk"), (p.warn, "Medium risk"), (p.good, "Clean")] {
            let galley = painter.layout_no_wrap(label.to_string(), legend_font.clone(), p.text_dim);
            let label_w = galley.size().x;
            painter.circle_filled(egui::pos2(x + 4.5, lrect.center().y), 4.5, color);
            painter.galley(
                egui::pos2(x + 13.0, lrect.center().y - galley.size().y / 2.0),
                galley,
                p.text_dim,
            );
            x += 13.0 + label_w + 26.0;
        }
    }
    ui.add_space(6.0);

    // Node-map card: two columns joined by risk-colored connectors.
    let reserve = if net.dns_adapters.is_empty() {
        12.0
    } else {
        92.0 + net.dns_adapters.len() as f32 * 18.0
    };
    let map_height = (ui.available_height() - reserve).max(220.0);
    egui::Frame::default()
        .fill(p.panel)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            // Column headers (reference tiny mono caps).
            let (hrect, _) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 18.0),
                egui::Sense::hover(),
            );
            if ui.is_rect_visible(hrect) {
                let painter = ui.painter();
                let font = egui::FontId::new(9.0, egui::FontFamily::Monospace);
                painter.text(
                    egui::pos2(hrect.min.x + 14.0, hrect.center().y),
                    Align2::LEFT_CENTER,
                    "PROCESS",
                    font.clone(),
                    p.text_muted,
                );
                painter.text(
                    egui::pos2(hrect.max.x - BOX_R_W + 6.0, hrect.center().y),
                    Align2::LEFT_CENTER,
                    "REMOTE ENDPOINT",
                    font,
                    p.text_muted,
                );
            }
            ui.add_space(4.0);

            let count = net.connections.len();
            egui::ScrollArea::vertical()
                .id_salt("network_map")
                .auto_shrink([false, true])
                .max_height(map_height)
                .show_rows(ui, ROW_H, count, |ui, range| {
                    for i in range {
                        draw_map_row(ui, &p, &net.connections[i]);
                    }
                });
        });

    // DNS adapters (if recorded).
    if !net.dns_adapters.is_empty() {
        ui.add_space(10.0);
        egui::Frame::default()
            .fill(p.block)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(6.0)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.label(RichText::new("DNS CONFIGURATION").strong().size(11.5).color(p.text_dim));
                ui.add_space(4.0);
                for adapter in &net.dns_adapters {
                    let servers = if adapter.dns_servers.is_empty() {
                        "none recorded".to_string()
                    } else {
                        adapter.dns_servers.join(", ")
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(&adapter.adapter).monospace().strong().size(11.5));
                        ui.label(RichText::new("— servers:").color(p.text_dim).size(11.0));
                        ui.label(RichText::new(&servers).monospace().size(11.0));
                    });
                }
            });
    }
}

/// Compact number card (right-hand header stats).
fn stat_card(ui: &mut Ui, p: &Palette, number: &str, label: &str, color: Color32) {
    egui::Frame::default()
        .fill(p.block)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(number).monospace().strong().color(color).size(14.0));
                ui.label(RichText::new(label).color(p.text_muted).size(9.0));
            });
        });
}

/// One node-map row: process box (left) ↔ remote endpoint box (right).
fn draw_map_row(ui: &mut Ui, p: &Palette, c: &ConnectionEntry) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_H),
        egui::Sense::hover(),
    );
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    let (color, flagged) = risk(p, c);
    let cy = rect.center().y;
    let lbox = egui::Rect::from_min_size(
        egui::pos2(rect.min.x + 4.0, cy - BOX_H / 2.0),
        egui::vec2(BOX_L_W, BOX_H),
    );
    let rbox = egui::Rect::from_min_size(
        egui::pos2(rect.max.x - BOX_R_W - 4.0, cy - BOX_H / 2.0),
        egui::vec2(BOX_R_W, BOX_H),
    );

    // Process box: card fill with a risk-colored stroke. Flagged rows
    // additionally get a small corner flag so they scan at a glance.
    painter.rect_filled(lbox, 8.0, p.panel);
    painter.rect_stroke(lbox, 8.0, Stroke::new(1.2_f32, color), StrokeKind::Inside);
    if flagged {
        painter.add(egui::Shape::convex_polygon(
            vec![
                egui::pos2(lbox.min.x + 1.0, lbox.min.y + 1.0),
                egui::pos2(lbox.min.x + 12.0, lbox.min.y + 1.0),
                egui::pos2(lbox.min.x + 1.0, lbox.min.y + 12.0),
            ],
            color,
            Stroke::NONE,
        ));
    }
    // Remote endpoint box: risk color at ~12% opacity + colored stroke.
    let tint = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 31);
    painter.rect_filled(rbox, 8.0, tint);
    painter.rect_stroke(rbox, 8.0, Stroke::new(1.2_f32, color), StrokeKind::Inside);

    // Connector: solid + thick for flagged rows, dashed for ordinary.
    let from = egui::pos2(lbox.max.x + 6.0, cy);
    let to = egui::pos2(rbox.min.x - 6.0, cy);
    if flagged {
        painter.line_segment([from, to], Stroke::new(2.5_f32, color));
    } else {
        paint_dashed(painter, from, to, color, 1.5);
    }

    // Process side: name + pid/proto/local-address line.
    painter.text(
        egui::pos2(lbox.min.x + 10.0, cy - 8.5),
        Align2::LEFT_CENTER,
        ellipsize(&c.process, 33),
        egui::FontId::new(11.0, egui::FontFamily::Monospace),
        p.text,
    );
    let local = if c.local_address.is_empty() {
        format!("pid {} · {}", c.pid, c.protocol)
    } else {
        format!("pid {} · {} · {}:{}", c.pid, c.protocol, c.local_address, c.local_port)
    };
    painter.text(
        egui::pos2(lbox.min.x + 10.0, cy + 9.0),
        Align2::LEFT_CENTER,
        ellipsize(&local, 42),
        egui::FontId::new(9.0, egui::FontFamily::Monospace),
        p.text_dim,
    );

    // Endpoint side: remote address:port + state.
    let remote = if c.remote_address.is_empty() {
        format!("port {}", c.remote_port)
    } else {
        format!("{}:{}", ellipsize(&c.remote_address, 21), c.remote_port)
    };
    painter.text(
        egui::pos2(rbox.min.x + 10.0, cy - 8.5),
        Align2::LEFT_CENTER,
        remote,
        egui::FontId::new(11.0, egui::FontFamily::Monospace),
        color,
    );
    let state = if c.state.is_empty() { "-".to_string() } else { c.state.clone() };
    painter.text(
        egui::pos2(rbox.min.x + 10.0, cy + 9.0),
        Align2::LEFT_CENTER,
        ellipsize(&state, 30),
        egui::FontId::new(9.0, egui::FontFamily::Monospace),
        p.text_dim,
    );
}

/// Dashed connector (reference dasharray 4,3) for ordinary traffic.
fn paint_dashed(painter: &egui::Painter, from: egui::Pos2, to: egui::Pos2, color: Color32, width: f32) {
    let mut x = from.x;
    while x < to.x {
        let end = (x + 4.0).min(to.x);
        painter.line_segment(
            [egui::pos2(x, from.y), egui::pos2(end, to.y)],
            Stroke::new(width, color),
        );
        x += 4.0 + 3.0;
    }
}

fn ellipsize(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut cut: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}
