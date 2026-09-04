//! Left-hand "Data Sources" evidence tree: header strip, filter box,
//! AIF root node, category groups with counts, artifact leaves with
//! risk flag dots — styled after the reference Autopsy tree panel.

use eframe::egui::{self, Align2, Color32, Stroke, StrokeKind, Ui};

use crate::ingest::index::{CATEGORY_ORDER, category_label};

use super::explorer::{build_rows, risk_map};
use super::state::AppState;
use super::theme::{self, anim, palette, severity_color, Icon, Palette, HOVER_TIME, SELECT_TIME};

/// Reference leaf row: pad-left ~38, doc icon, name, right flag dot.
/// Hover tint and selection fill ease in (same-frame hover reading).
fn leaf_row(
    ui: &mut Ui,
    p: &Palette,
    name: &str,
    dim: bool,
    selected: bool,
    dot: Color32,
) -> egui::Response {
    let ctx = ui.ctx().clone();
    let response = ui.allocate_response(egui::vec2(ui.available_width(), 24.0), egui::Sense::click());
    let rect = response.rect;
    if ui.is_rect_visible(rect) {
        let hov = anim(&ctx, response.id.with("hov"), response.hovered(), HOVER_TIME);
        let sel = anim(&ctx, response.id.with("sel"), selected, SELECT_TIME);
        let fill = theme::mix(theme::mix(Color32::TRANSPARENT, p.hover_soft, hov), p.selection, sel);
        let painter = ui.painter();
        if fill != Color32::TRANSPARENT {
            painter.rect_filled(rect, 4.0, fill);
        }
        if sel > 0.0 {
            painter.rect(
                rect,
                4.0,
                Color32::TRANSPARENT,
                Stroke::new(1.0_f32, theme::faded(p.accent, sel)),
                StrokeKind::Inside,
            );
        }
        let cy = rect.center().y;
        // Doc icon at the reference indent.
        let icon_rect = egui::Rect::from_center_size(egui::pos2(rect.min.x + 44.0, cy), egui::vec2(13.0, 13.0));
        let icon_color = if selected { p.accent_deep } else { p.text_muted };
        theme::paint_icon(painter, icon_rect, Icon::Doc, icon_color, 1.5);
        // Name (clipped to the row).
        let text_color = if selected {
            p.accent_deep
        } else if dim {
            p.text_dim
        } else {
            p.text
        };
        let galley = painter.layout_no_wrap(
            name.to_string(),
            egui::FontId::new(11.5, egui::FontFamily::Proportional),
            text_color,
        );
        let max_w = rect.max.x - 26.0 - (rect.min.x + 56.0);
        let pos = egui::pos2(rect.min.x + 56.0, cy - galley.size().y / 2.0);
        if galley.size().x > max_w {
            // Overflow-safe: re-layout with a hard wrap boundary.
            let clipped = painter.layout(
                name.to_string(),
                egui::FontId::new(11.5, egui::FontFamily::Proportional),
                text_color,
                max_w,
            );
            painter.galley(pos, clipped, text_color);
        } else {
            painter.galley(pos, galley, text_color);
        }
        // Right-hand risk dot.
        painter.circle_filled(egui::pos2(rect.max.x - 12.0, cy), 3.5, dot);
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Reference `.cat-head`: rotating chevron + yellow folder icon +
/// count/flag on the right.
fn cat_head(
    ui: &mut Ui,
    p: &Palette,
    label: &str,
    flagged: usize,
    count: usize,
    openness: f32,
) -> egui::Response {
    let ctx = ui.ctx().clone();
    let response = ui.allocate_response(egui::vec2(ui.available_width(), 26.0), egui::Sense::click());
    let rect = response.rect;
    if ui.is_rect_visible(rect) {
        let hov = anim(&ctx, response.id.with("hov"), response.hovered(), HOVER_TIME);
        let painter = ui.painter();
        if hov > 0.0 {
            painter.rect_filled(rect, 4.0, theme::faded(p.hover_soft, hov));
        }
        let cy = rect.center().y;
        // Chevron eases from right-pointing (closed) to down (open).
        theme::paint_chevron(
            painter,
            egui::pos2(rect.min.x + 12.0, cy),
            5.0,
            openness * std::f32::consts::FRAC_PI_2,
            p.text_dim,
        );
        let icon_rect = egui::Rect::from_center_size(egui::pos2(rect.min.x + 28.0, cy), egui::vec2(14.0, 14.0));
        theme::paint_icon(painter, icon_rect, Icon::Folder, p.folder, 1.7);
        painter.text(
            egui::pos2(rect.min.x + 42.0, cy),
            Align2::LEFT_CENTER,
            label,
            egui::FontId::new(12.0, egui::FontFamily::Proportional),
            p.text,
        );
        // Count (+ flag) right-aligned.
        let right = if flagged > 0 {
            format!("⚑ {flagged} · {count}")
        } else {
            count.to_string()
        };
        let color = if flagged > 0 { p.danger } else { p.text_muted };
        painter.text(
            egui::pos2(rect.max.x - 10.0, cy),
            Align2::RIGHT_CENTER,
            right,
            egui::FontId::new(10.5, egui::FontFamily::Monospace),
            color,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);
    let Some(session) = &mut app.session else { return };

    // Reference head strip — pinned above the scrolling tree body.
    let (head_rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 26.0),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(head_rect) {
        let painter = ui.painter();
        painter.rect_filled(head_rect, 0.0, p.panel_deep);
        painter.text(
            egui::pos2(head_rect.min.x + 8.0, head_rect.center().y),
            Align2::LEFT_CENTER,
            "DATA SOURCES",
            egui::FontId::new(10.0, egui::FontFamily::Proportional),
            p.text_dim,
        );
        painter.hline(
            head_rect.x_range(),
            head_rect.max.y - 0.5,
            Stroke::new(1.0_f32, p.border),
        );
    }
    // Filter input (reference: #FBFBFC field with #C2C8D0 border).
    egui::Frame::default()
        .fill(p.input_bg)
        .stroke(Stroke::new(1.0_f32, p.border_strong))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut session.tree_filter)
                    .hint_text("Filter evidence…")
                    .frame(false)
                    .desired_width(f32::INFINITY),
            );
        });
    ui.add_space(4.0);

    let rows = build_rows(session);
    let risks = risk_map(session);
    let filter = session.tree_filter.to_ascii_lowercase();

    // Only the tree list scrolls.
    egui::ScrollArea::vertical().id_salt("evidence_tree").show(ui, |ui| {
        // Root node: evidence image (or the case when none is open).
        let (root_label, root_sub) = match &session.exam {
            Some(exam) => (
                exam.image_name.clone(),
                format!(
                    "AIF v{} · {} · {} artifacts",
                    exam.case_doc.format_version,
                    crate::gui::fmt_bytes(exam.size_bytes),
                    exam.artifacts.len()
                ),
            ),
            None => (
                session.meta.case_number.clone(),
                "No evidence image opened".to_string(),
            ),
        };
        let root_resp = ui.allocate_response(egui::vec2(ui.available_width(), 34.0), egui::Sense::hover());
        if ui.is_rect_visible(root_resp.rect) {
            let ctx = ui.ctx().clone();
            let hov = anim(&ctx, root_resp.id.with("hov"), root_resp.hovered(), HOVER_TIME);
            let painter = ui.painter();
            if hov > 0.0 {
                painter.rect_filled(root_resp.rect, 4.0, theme::faded(p.hover_soft, hov));
            }
            let icon_rect = egui::Rect::from_center_size(
                egui::pos2(root_resp.rect.min.x + 16.0, root_resp.rect.center().y),
                egui::vec2(16.0, 16.0),
            );
            theme::paint_icon(painter, icon_rect, Icon::Shield, p.accent, 1.8);
            painter.text(
                egui::pos2(root_resp.rect.min.x + 32.0, root_resp.rect.center().y - 6.0),
                Align2::LEFT_CENTER,
                root_label,
                egui::FontId::new(12.5, egui::FontFamily::Proportional),
                p.text,
            );
            painter.text(
                egui::pos2(root_resp.rect.min.x + 32.0, root_resp.rect.center().y + 8.0),
                Align2::LEFT_CENTER,
                root_sub,
                egui::FontId::new(10.5, egui::FontFamily::Proportional),
                p.text_dim,
            );
        }
        ui.add_space(4.0);

        if rows.is_empty() {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("No evidence indexed yet.").color(p.text_dim));
            ui.label(
                egui::RichText::new("Use Ingest ▸ Add Evidence Image to attach a real .AIF container.")
                    .color(p.text_dim)
                    .size(11.0),
            );
            return;
        }

        // Category groups: animated chevron + clip-reveal of the leaves.
        for key in CATEGORY_ORDER.iter().chain(std::iter::once(&"other")) {
            let members: Vec<usize> = rows
                .iter()
                .enumerate()
                .filter(|(_, r)| &r.category == key)
                .filter(|(_, r)| {
                    filter.is_empty()
                        || r.display_name.to_ascii_lowercase().contains(&filter)
                        || r.relative_path.to_ascii_lowercase().contains(&filter)
                        || r.artifact_id.to_ascii_lowercase().contains(&filter)
                })
                .map(|(i, _)| i)
                .collect();
            if members.is_empty() {
                continue;
            }

            let flagged = members
                .iter()
                .filter(|i| risks.contains_key(&rows[**i].artifact_id))
                .count();

            let cat_id = ui.id().with("tree_cat").with(key);
            let mut state =
                egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), cat_id, true);
            let openness = state.openness(ui.ctx());
            let header = cat_head(ui, &p, category_label(key), flagged, members.len(), openness);
            if header.clicked() {
                state.toggle(ui);
            }
            if state.is_open() || state.openness(ui.ctx()) > 0.001 {
                state.show_body_unindented(ui, |ui| {
                    for idx in members {
                        let row = &rows[idx];
                        let selected =
                            session.selected_artifact.as_deref() == Some(row.artifact_id.as_str());
                        let dot = match risks.get(&row.artifact_id) {
                            Some(sev) => severity_color(&p, *sev),
                            None => p.good,
                        };
                        let name = if row.opened {
                            row.display_name.clone()
                        } else {
                            format!("{} (indexed)", row.display_name)
                        };
                        let item = leaf_row(ui, &p, &name, !row.opened && !selected, selected, dot);
                        if item.clicked() {
                            session.selected_artifact = Some(row.artifact_id.clone());
                            session.view = crate::gui::state::MainView::Explorer;
                        }
                    }
                });
            } else {
                state.store(ui.ctx());
            }
        }
    });
}
