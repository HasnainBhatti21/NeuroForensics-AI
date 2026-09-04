//! Forensic workstation theming (dark / light), applied globally.
//!
//! Palette tokens are the exact design-system values from the approved
//! reference (spec §38B) — high risk is always red, medium amber,
//! clean/low green; only the shade changes per theme.

use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke, StrokeKind, TextStyle, Visuals};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThemeMode {
    Dark,
    Light,
}

impl ThemeMode {
    pub fn label(self) -> &'static str {
        match self {
            ThemeMode::Dark => "Dark",
            ThemeMode::Light => "Light",
        }
    }
    pub fn toggle(&mut self) {
        *self = match self {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        };
    }
}

/// Shared palette so every screen stays consistent.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub panel: Color32,
    pub panel_deep: Color32,
    pub chrome: Color32,
    pub chrome_deep: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub accent: Color32,
    pub accent_dim: Color32,
    /// Secondary accent reserved for AI surfaces (dark: #8A6CF2).
    pub accent_ai: Color32,
    pub good: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub selection: Color32,
    pub grid_stripe: Color32,
    pub border: Color32,
    /// Tertiary / muted text (§38B: light #8993A1, dark #57667C).
    pub text_muted: Color32,
    /// Strong border for inputs (§38B: light #C2C8D0; the spec defines
    /// no separate dark value, so dark keeps the standard border).
    pub border_strong: Color32,
    /// Deep accent for active toolbar/tab text (reference: light #164680).
    pub accent_deep: Color32,
    /// Soft hover tint for tree rows / chips / cards (reference #EEF3FA).
    pub hover_soft: Color32,
    /// Dark navy chrome strip — status bar + toasts (reference #1C2B3A).
    pub titlebar: Color32,
    /// Muted text on the dark navy strip (reference #A9B7C4).
    pub status_text: Color32,
    /// Toolbar button hover fill (reference #E6ECF3).
    pub tb_hover: Color32,
    /// Active toolbar button border (reference #B7D3F2).
    pub active_border: Color32,
    /// Menubar item hover fill (reference #E4E9EF).
    pub menubar_hover: Color32,
    /// Result-table sticky header fill (reference #F5F6F8).
    pub thead: Color32,
    /// Hairline row separator (reference #EEF0F3).
    pub row_border: Color32,
    /// Text input background (reference #FBFBFC).
    pub input_bg: Color32,
    /// Inset block/card background (reference #FAFBFC).
    pub block: Color32,
    /// Tree folder icon yellow (reference #E8B04B).
    pub folder: Color32,
    /// Titlebar gradient top / bottom (reference #233245 → #1A2734).
    pub titlebar_top: Color32,
    pub titlebar_bot: Color32,
    /// Titlebar text + case accent (reference #DFE6EE / #7FB2E8).
    pub title_text: Color32,
    pub title_accent: Color32,
    /// Decorative window dots (reference #3A4B5C / #B23A3A).
    pub win_dot: Color32,
    pub win_close: Color32,
}

pub fn palette(mode: ThemeMode) -> Palette {
    match mode {
        ThemeMode::Dark => Palette {
            panel: Color32::from_rgb(0x11, 0x18, 0x26),        // panel            #111826
            panel_deep: Color32::from_rgb(0x0B, 0x0F, 0x16),   // app void         #0B0F16
            chrome: Color32::from_rgb(0x16, 0x1F, 0x2E),       // raised rows/cards#161F2E
            chrome_deep: Color32::from_rgb(0x0E, 0x14, 0x20),  // toolbar/status strip
            text: Color32::from_rgb(0xE9, 0xEE, 0xF4),         // primary text     #E9EEF4
            text_dim: Color32::from_rgb(0x8B, 0x98, 0xAB),     // secondary text   #8B98AB
            accent: Color32::from_rgb(0x49, 0xB8, 0xE8),       // accent / info    #49B8E8
            accent_dim: Color32::from_rgb(0x18, 0x2B, 0x3D),   // accent @ ~12% on panel
            accent_ai: Color32::from_rgb(0x8A, 0x6C, 0xF2),    // accent / AI      #8A6CF2
            good: Color32::from_rgb(0x3D, 0xDC, 0x9A),         // clean / low      #3DDC9A
            warn: Color32::from_rgb(0xF0, 0xA6, 0x3A),         // medium risk      #F0A63A
            danger: Color32::from_rgb(0xFF, 0x54, 0x68),       // high risk        #FF5468
            selection: Color32::from_rgb(0x1C, 0x38, 0x4D),    // accent @ ~20% on panel
            grid_stripe: Color32::from_rgb(0x16, 0x1F, 0x2E),  // raised row tint
            border: Color32::from_rgb(0x23, 0x2E, 0x40),       // border           #232E40
            text_muted: Color32::from_rgb(0x57, 0x66, 0x7C),   // tertiary text    #57667C
            border_strong: Color32::from_rgb(0x23, 0x2E, 0x40), // spec: dark border only
            accent_deep: Color32::from_rgb(0x8E, 0xD0, 0xF0),  // active text on dark
            hover_soft: Color32::from_rgba_unmultiplied(0x49, 0xB8, 0xE8, 22),
            titlebar: Color32::from_rgb(0x1C, 0x2B, 0x3A),     // navy strip       #1C2B3A
            status_text: Color32::from_rgb(0xA9, 0xB7, 0xC4),  // strip text       #A9B7C4
            tb_hover: Color32::from_rgba_unmultiplied(0x49, 0xB8, 0xE8, 26),
            active_border: Color32::from_rgb(0x35, 0x64, 0x8C),
            menubar_hover: Color32::from_rgb(0x23, 0x2E, 0x40),
            thead: Color32::from_rgb(0x16, 0x1F, 0x2E),
            row_border: Color32::from_rgba_unmultiplied(0x23, 0x2E, 0x40, 120),
            input_bg: Color32::from_rgb(0x0B, 0x0F, 0x16),
            block: Color32::from_rgb(0x0E, 0x14, 0x20),
            folder: Color32::from_rgb(0xE8, 0xB0, 0x4B),
            titlebar_top: Color32::from_rgb(0x23, 0x32, 0x45),
            titlebar_bot: Color32::from_rgb(0x1A, 0x27, 0x34),
            title_text: Color32::from_rgb(0xDF, 0xE6, 0xEE),
            title_accent: Color32::from_rgb(0x7F, 0xB2, 0xE8),
            win_dot: Color32::from_rgb(0x3A, 0x4B, 0x5C),
            win_close: Color32::from_rgb(0xB2, 0x3A, 0x3A),
        },
        ThemeMode::Light => Palette {
            panel: Color32::from_rgb(0xFF, 0xFF, 0xFF),        // panel/card       #FFFFFF
            panel_deep: Color32::from_rgb(0xEE, 0xF1, 0xF5),   // app bg / headers #EEF1F5
            chrome: Color32::from_rgb(0xF7, 0xF8, 0xFA),       // menu bar         #F7F8FA
            chrome_deep: Color32::from_rgb(0xF4, 0xF5, 0xF7),  // toolbar          #F4F5F7
            text: Color32::from_rgb(0x1B, 0x23, 0x2E),         // primary text     #1B232E
            text_dim: Color32::from_rgb(0x57, 0x62, 0x6F),     // secondary text   #57626F
            accent: Color32::from_rgb(0x1F, 0x5F, 0xA8),       // accent           #1F5FA8
            accent_dim: Color32::from_rgb(0xE8, 0xEC, 0xF4),   // accent @ ~12% on white
            accent_ai: Color32::from_rgb(0x8A, 0x6C, 0xF2),    // AI accent        #8A6CF2
            good: Color32::from_rgb(0x1F, 0x7A, 0x45),         // clean / low      #1F7A45
            warn: Color32::from_rgb(0xB3, 0x72, 0x0B),         // medium risk      #B3720B
            danger: Color32::from_rgb(0xC0, 0x39, 0x2B),       // high risk        #C0392B
            selection: Color32::from_rgb(0xD9, 0xE9, 0xFB),    // row selected     #D9E9FB
            grid_stripe: Color32::from_rgb(0xF2, 0xF6, 0xFB),  // row hover        #F2F6FB
            border: Color32::from_rgb(0xD7, 0xDB, 0xE1),       // standard border  #D7DBE1
            text_muted: Color32::from_rgb(0x89, 0x93, 0xA1),   // tertiary text    #8993A1
            border_strong: Color32::from_rgb(0xC2, 0xC8, 0xD0), // input border    #C2C8D0
            accent_deep: Color32::from_rgb(0x16, 0x46, 0x80),   // active chip text #164680
            hover_soft: Color32::from_rgb(0xEE, 0xF3, 0xFA),   // soft hover tint  #EEF3FA
            titlebar: Color32::from_rgb(0x1C, 0x2B, 0x3A),     // navy strip       #1C2B3A
            status_text: Color32::from_rgb(0xA9, 0xB7, 0xC4),  // strip text       #A9B7C4
            tb_hover: Color32::from_rgb(0xE6, 0xEC, 0xF3),     // tb hover         #E6ECF3
            active_border: Color32::from_rgb(0xB7, 0xD3, 0xF2), // active border   #B7D3F2
            menubar_hover: Color32::from_rgb(0xE4, 0xE9, 0xEF), // menu hover      #E4E9EF
            thead: Color32::from_rgb(0xF5, 0xF6, 0xF8),        // table header     #F5F6F8
            row_border: Color32::from_rgb(0xEE, 0xF0, 0xF3),   // row hairline     #EEF0F3
            input_bg: Color32::from_rgb(0xFB, 0xFB, 0xFC),     // input bg         #FBFBFC
            block: Color32::from_rgb(0xFA, 0xFB, 0xFC),        // inset block      #FAFBFC
            folder: Color32::from_rgb(0xE8, 0xB0, 0x4B),       // folder icon      #E8B04B
            titlebar_top: Color32::from_rgb(0x23, 0x32, 0x45), // titlebar grad    #233245
            titlebar_bot: Color32::from_rgb(0x1A, 0x27, 0x34), // titlebar grad    #1A2734
            title_text: Color32::from_rgb(0xDF, 0xE6, 0xEE),   // titlebar text    #DFE6EE
            title_accent: Color32::from_rgb(0x7F, 0xB2, 0xE8), // titlebar case    #7FB2E8
            win_dot: Color32::from_rgb(0x3A, 0x4B, 0x5C),      // win dots         #3A4B5C
            win_close: Color32::from_rgb(0xB2, 0x3A, 0x3A),    // win close dot    #B23A3A
        },
    }
}

/// Apply fonts, spacing and colors for a professional forensic look.
pub fn apply(ctx: &egui::Context, mode: ThemeMode) {
    install_fonts(ctx);
    let p = palette(mode);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.window_margin = egui::Margin::same(0);
    style.spacing.menu_margin = egui::Margin::same(4);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.indent = 18.0;
    // Built-in widget animations (menus, collapsing) stay short and calm.
    style.animation_time = 0.16;
    style.visuals = visuals(mode);
    style.visuals.widgets.noninteractive.bg_fill = p.panel;
    style.visuals.widgets.noninteractive.fg_stroke.color = p.text;
    style.visuals.panel_fill = p.panel;
    style.visuals.window_fill = p.panel;
    style.visuals.faint_bg_color = p.grid_stripe;
    style.visuals.extreme_bg_color = p.panel_deep;

    // Typography: keep egui defaults, tighten the monospace face used
    // for hashes / hex viewers.
    style.text_styles.insert(
        TextStyle::Monospace,
        egui::FontId::new(12.5, egui::FontFamily::Monospace),
    );
    ctx.set_style(style);
}

fn visuals(mode: ThemeMode) -> Visuals {
    let p = palette(mode);
    let mut v = match mode {
        ThemeMode::Dark => Visuals::dark(),
        ThemeMode::Light => Visuals::light(),
    };
    v.widgets.noninteractive.corner_radius = CornerRadius::same(4);
    v.widgets.inactive.corner_radius = CornerRadius::same(4);
    v.widgets.hovered.corner_radius = CornerRadius::same(4);
    v.widgets.active.corner_radius = CornerRadius::same(4);
    v.window_corner_radius = CornerRadius::same(8);
    v.window_stroke = Stroke::new(1.0_f32, p.border);
    v.widgets.inactive.bg_fill = p.chrome;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border);
    v.widgets.hovered.bg_fill = p.accent_dim;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.active_border);
    v.widgets.active.bg_fill = p.accent;
    v.selection.bg_fill = p.selection;
    // Buttons MUST paint their frame: with `button_frame = false` egui
    // skips the fill entirely, which made filled buttons (CREATE CASE,
    // ADD TO CASE & INGEST, primary modal buttons) render as invisible
    // white-on-white text in the light theme.
    v.button_frame = true;
    v
}

pub fn severity_color(p: &Palette, severity: crate::analysis::rules::Severity) -> Color32 {
    use crate::analysis::rules::Severity::*;
    // §38B semantic roles never remap: high = red, medium = amber,
    // clean/low = green.
    match severity {
        Low => p.good,
        Medium => p.warn,
        High | Critical => p.danger,
    }
}

/// §38B badge tone — the semantic role, never remapped per theme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskTone {
    High,
    Medium,
    Clean,
}

impl RiskTone {
    pub fn from_severity(severity: crate::analysis::rules::Severity) -> RiskTone {
        use crate::analysis::rules::Severity::*;
        match severity {
            Low => RiskTone::Clean,
            Medium => RiskTone::Medium,
            High | Critical => RiskTone::High,
        }
    }
}

/// §38B risk badge triple (text, tinted background, matching border).
/// Light theme uses the exact spec tokens; the spec defines dark-theme
/// risk colors as text values only, so dark bg/border are translucent
/// tints of those exact text colors on the panel.
pub fn risk_badge(p: &Palette, mode: ThemeMode, tone: RiskTone) -> (Color32, Color32, Color32) {
    match mode {
        ThemeMode::Light => match tone {
            RiskTone::High => (
                Color32::from_rgb(0xC0, 0x39, 0x2B),
                Color32::from_rgb(0xFB, 0xE9, 0xE7),
                Color32::from_rgb(0xF0, 0xC4, 0xBD),
            ),
            RiskTone::Medium => (
                Color32::from_rgb(0xB3, 0x72, 0x0B),
                Color32::from_rgb(0xFD, 0xF1, 0xDE),
                Color32::from_rgb(0xF0, 0xD6, 0x9F),
            ),
            RiskTone::Clean => (
                Color32::from_rgb(0x1F, 0x7A, 0x45),
                Color32::from_rgb(0xE7, 0xF5, 0xEC),
                Color32::from_rgb(0xBF, 0xE3, 0xCD),
            ),
        },
        ThemeMode::Dark => {
            let text = match tone {
                RiskTone::High => p.danger,
                RiskTone::Medium => p.warn,
                RiskTone::Clean => p.good,
            };
            let (r, g, b) = (text.r(), text.g(), text.b());
            (
                text,
                Color32::from_rgba_unmultiplied(r, g, b, 26),  // ~10% tint
                Color32::from_rgba_unmultiplied(r, g, b, 92),  // ~36% border
            )
        }
    }
}

/// Fill / border / text triple for the reference chip states: at rest
/// transparent, hovered a soft tint, active the soft-blue selection
/// triple (#D9E9FB / #B7D3F2 / deep-accent text in light mode).
pub fn chip_colors(p: &Palette, mode: ThemeMode, active: bool, hovered: bool) -> (Color32, Stroke, Color32) {
    if active {
        let border = match mode {
            ThemeMode::Light => Color32::from_rgb(0xB7, 0xD3, 0xF2), // reference active border
            ThemeMode::Dark => Color32::from_rgb(0x35, 0x64, 0x8C),
        };
        (p.selection, Stroke::new(1.0_f32, border), p.accent_deep)
    } else if hovered {
        (p.hover_soft, Stroke::new(1.0_f32, p.border), p.text)
    } else {
        (Color32::TRANSPARENT, Stroke::NONE, p.text_dim)
    }
}

// ---------------------------------------------------------------------
// §38B motion — short ease-out transitions only. This is an
// investigator's tool used for hours: nothing bouncy, nothing > ~200ms.
// ---------------------------------------------------------------------

pub const HOVER_TIME: f32 = 0.12;
pub const SELECT_TIME: f32 = 0.15;
pub const MODAL_TIME: f32 = 0.18;

/// Ease-out cubic: quick start, gentle landing.
pub fn cubic_out(t: f32) -> f32 {
    let f = 1.0 - t.clamp(0.0, 1.0);
    1.0 - f * f * f
}

/// Animated 0..=1 transition toward `target`, ease-out eased.
pub fn anim(ctx: &egui::Context, id: egui::Id, target: bool, secs: f32) -> f32 {
    ctx.animate_bool_with_time_and_easing(id, target, secs, cubic_out)
}

/// Gamma-space blend between two colors (state transitions).
pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    if t <= 0.0 {
        return a;
    }
    if t >= 1.0 {
        return b;
    }
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgba_unmultiplied(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()), l(a.a(), b.a()))
}

/// Alpha-only fade (tint strength without hue shift).
pub fn faded(c: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    if t >= 1.0 {
        return c;
    }
    if t <= 0.0 {
        return Color32::TRANSPARENT;
    }
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (c.a() as f32 * t) as u8)
}

// ---------------------------------------------------------------------
// Reference line icons — 24-unit vector art painted with the egui
// painter so the toolbar/tree carry the reference's stroke icons.
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// rect + horizontal line (case info card).
    Card,
    /// card with vertical divider (add evidence).
    CardSplit,
    /// shield + check (run analysis / ingest).
    Shield,
    Clock,
    Wave,
    Grid,
    Search,
    /// document with folded corner (report / tree leaf).
    Doc,
    Folder,
    CheckCircle,
    WarnTri,
}

pub fn paint_icon(painter: &egui::Painter, rect: egui::Rect, icon: Icon, color: Color32, stroke_w: f32) {
    let s = |x: f32, y: f32| {
        egui::pos2(
            rect.min.x + x / 24.0 * rect.width(),
            rect.min.y + y / 24.0 * rect.height(),
        )
    };
    let stroke = Stroke::new(stroke_w, color);
    let line = |pts: &[(f32, f32)]| {
        let pts: Vec<egui::Pos2> = pts.iter().map(|&(x, y)| s(x, y)).collect();
        painter.add(egui::Shape::line(pts, stroke));
    };
    let circle = |c: (f32, f32), r: f32| {
        painter.circle_stroke(s(c.0, c.1), r / 24.0 * rect.width(), stroke);
    };
    match icon {
        Icon::Card => {
            line(&[(3.5, 4.5), (20.5, 4.5), (20.5, 19.5), (3.5, 19.5), (3.5, 4.5)]);
            line(&[(3.5, 9.0), (20.5, 9.0)]);
        }
        Icon::CardSplit => {
            line(&[(3.5, 4.5), (20.5, 4.5), (20.5, 19.5), (3.5, 19.5), (3.5, 4.5)]);
            line(&[(3.5, 9.0), (20.5, 9.0)]);
            line(&[(8.0, 9.0), (8.0, 19.5)]);
        }
        Icon::Shield => {
            line(&[
                (12.0, 3.0), (5.0, 6.0), (5.0, 12.0), (7.0, 17.0), (12.0, 21.0),
                (17.0, 17.0), (19.0, 12.0), (19.0, 6.0), (12.0, 3.0),
            ]);
            line(&[(9.5, 12.0), (11.3, 13.8), (14.5, 10.2)]);
        }
        Icon::Clock => {
            circle((12.0, 12.0), 9.0);
            line(&[(12.0, 7.0), (12.0, 12.0), (15.5, 14.0)]);
        }
        Icon::Wave => {
            line(&[(4.0, 12.0), (8.0, 12.0), (10.0, 5.0), (14.0, 19.0), (16.0, 12.0), (20.0, 12.0)]);
        }
        Icon::Grid => {
            for (x, y) in [(3.0, 3.0), (14.0, 3.0), (3.0, 14.0), (14.0, 14.0)] {
                line(&[(x, y), (x + 7.0, y), (x + 7.0, y + 7.0), (x, y + 7.0), (x, y)]);
            }
        }
        Icon::Search => {
            circle((11.0, 11.0), 7.0);
            line(&[(21.0, 21.0), (16.0, 16.0)]);
        }
        Icon::Doc => {
            line(&[
                (13.0, 3.0), (7.0, 3.0), (5.0, 5.0), (5.0, 19.0), (7.0, 21.0),
                (17.0, 21.0), (19.0, 19.0), (19.0, 8.0), (13.0, 3.0),
            ]);
            line(&[(13.0, 3.0), (13.0, 8.0), (19.0, 8.0)]);
            line(&[(9.0, 13.0), (15.0, 13.0)]);
            line(&[(9.0, 17.0), (15.0, 17.0)]);
        }
        Icon::Folder => {
            line(&[
                (3.0, 7.0), (5.0, 5.0), (9.0, 5.0), (11.0, 7.0), (21.0, 7.0),
                (21.0, 19.0), (3.0, 19.0), (3.0, 7.0),
            ]);
        }
        Icon::CheckCircle => {
            circle((12.0, 12.0), 9.0);
            line(&[(9.0, 12.0), (11.0, 14.0), (15.0, 10.0)]);
        }
        Icon::WarnTri => {
            line(&[(12.0, 3.5), (2.5, 20.5), (21.5, 20.5), (12.0, 3.5)]);
            line(&[(12.0, 9.0), (12.0, 14.0)]);
            painter.circle_filled(s(12.0, 17.0), stroke_w * 0.7, color);
        }
    }
}

/// Right-pointing chevron rotated by `angle` radians (tree categories).
pub fn paint_chevron(painter: &egui::Painter, center: egui::Pos2, size: f32, angle: f32, color: Color32) {
    let (sin, cos) = angle.sin_cos();
    let rot = |x: f32, y: f32| {
        egui::pos2(center.x + (x * cos - y * sin) * size, center.y + (x * sin + y * cos) * size)
    };
    let pts = vec![rot(-0.2, -0.42), rot(0.3, 0.0), rot(-0.2, 0.42)];
    painter.add(egui::Shape::line(pts, Stroke::new(1.6_f32, color)));
}

/// Reference `.tb-btn`: vertical icon-over-label button with eased
/// hover / active states (transparent → #E6ECF3 → #D9E9FB).
pub fn toolbar_button(
    ui: &mut egui::Ui,
    p: &Palette,
    active: bool,
    icon: Icon,
    label: &str,
) -> egui::Response {
    let ctx = ui.ctx().clone();
    let font = egui::FontId::new(10.0, egui::FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, Color32::PLACEHOLDER);
    let w = (galley.size().x + 24.0).max(48.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(w, 44.0), egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let hov = anim(&ctx, response.id.with("hov"), response.hovered(), HOVER_TIME);
        let act = anim(&ctx, response.id.with("act"), active, HOVER_TIME);
        let fill = mix(mix(Color32::TRANSPARENT, p.tb_hover, hov), p.selection, act);
        let border = mix(mix(Color32::TRANSPARENT, p.border, hov), p.active_border, act);
        ui.painter().rect(rect, 5.0, fill, Stroke::new(1.0_f32, border), StrokeKind::Inside);
        let fg = mix(mix(p.text_dim, p.text, hov), p.accent_deep, act);
        let icon_rect = egui::Rect::from_center_size(
            egui::pos2(rect.center().x, rect.min.y + 5.0 + 9.5),
            egui::vec2(19.0, 19.0),
        );
        paint_icon(ui.painter(), icon_rect, icon, fg, 1.7);
        ui.painter().galley(
            egui::pos2(rect.center().x - galley.size().x / 2.0, rect.max.y - 5.0 - galley.size().y),
            galley,
            fg,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Reference `.tb-sep` vertical hairline.
pub fn tb_sep(ui: &mut egui::Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(1.0, 30.0), egui::Sense::hover());
    ui.painter().vline(rect.center().x, rect.y_range(), Stroke::new(1.0_f32, p.border));
    ui.add_space(10.0);
}

/// Reference `.titlebar`: navy gradient strip with logo, title and
/// decorative window dots. Shared by landing and workstation.
pub fn draw_titlebar(ctx: &egui::Context, p: &Palette, case_title: Option<String>) {
    egui::TopBottomPanel::top("titlebar")
        .frame(egui::Frame::default().fill(Color32::TRANSPARENT).inner_margin(0))
        .show(ctx, |ui| {
            let rect = ui.max_rect();
            // Titlebar gradient: horizontal 1px scanlines (egui 0.33 has
            // no gradient fill primitive; interpolation reads identically).
            let n = (rect.height() as i32).max(1);
            let painter = ui.painter();
            for i in 0..n {
                let t = i as f32 / (n as f32 - 1.0).max(1.0);
                let y = rect.min.y + i as f32;
                painter.hline(
                    rect.min.x..=rect.max.x,
                    y + 0.5,
                    Stroke::new(1.2_f32, mix(p.titlebar_top, p.titlebar_bot, t)),
                );
            }
            ui.allocate_ui_with_layout(
                egui::vec2(rect.width(), 34.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.add_space(12.0);
                    let icon_rect = egui::Rect::from_center_size(
                        egui::pos2(ui.cursor().min.x + 8.0, rect.center().y),
                        egui::vec2(16.0, 16.0),
                    );
                    paint_icon(ui.painter(), icon_rect, Icon::Shield, p.title_accent, 2.0);
                    ui.add_space(24.0);
                    ui.label(
                        RichText::new("NeuroForensics AI — Case Examiner")
                            .strong()
                            .size(12.0)
                            .color(p.title_text),
                    );
                    if let Some(case) = case_title {
                        ui.label(
                            RichText::new(format!(" [ {case} ]")).size(12.0).color(p.title_accent),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(12.0);
                        for color in [p.win_close, p.win_dot, p.win_dot] {
                            let (r, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                            ui.painter().circle_filled(r.center(), 6.0, color);
                            ui.add_space(8.0);
                        }
                    });
                },
            );
        });
}

/// Toolbar / view-switch chip styled after the reference design:
/// centered label, transparent at rest, soft hover, active soft-blue.
/// Same-frame hover (allocated before painting, not post-hoc).
pub fn chip(ui: &mut egui::Ui, p: &Palette, mode: ThemeMode, active: bool, label: &str) -> egui::Response {
    let font = egui::FontId::new(12.0, egui::FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, Color32::PLACEHOLDER);
    let size = egui::vec2(
        galley.size().x + 24.0,
        (galley.size().y + 10.0).max(26.0),
    );
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let (fill, stroke, text) = chip_colors(p, mode, active, response.hovered());
        ui.painter().rect(rect, 5.0, fill, stroke, StrokeKind::Inside);
        let pos = rect.center() - 0.5 * galley.size();
        ui.painter().galley(pos, galley, text);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// View-switch chip with a leading stroke icon — the dashboard's
/// navigation icons. Same hover/active semantics as [`chip`].
pub fn view_chip(
    ui: &mut egui::Ui,
    p: &Palette,
    mode: ThemeMode,
    active: bool,
    icon: Icon,
    label: &str,
) -> egui::Response {
    let font = egui::FontId::new(12.0, egui::FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, Color32::PLACEHOLDER);
    let size = egui::vec2(
        galley.size().x + 44.0,
        (galley.size().y + 10.0).max(28.0),
    );
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let (fill, stroke, text) = chip_colors(p, mode, active, response.hovered());
        ui.painter().rect(rect, 5.0, fill, stroke, StrokeKind::Inside);
        let icon_color = if active { p.accent_deep } else { text };
        let icon_rect = egui::Rect::from_center_size(
            egui::pos2(rect.min.x + 17.0, rect.center().y),
            egui::vec2(15.0, 15.0),
        );
        paint_icon(ui.painter(), icon_rect, icon, icon_color, 1.7);
        ui.painter().galley(
            egui::pos2(rect.min.x + 32.0, rect.center().y - galley.size().y / 2.0),
            galley,
            text,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Paint a small reference-style risk badge (tinted bg + matching
/// border, bold monospace text) anchored at its left-center; returns
/// the total width so manual layouts can advance.
pub fn paint_risk_badge(
    ui: &egui::Ui,
    left_center: egui::Pos2,
    mode: ThemeMode,
    p: &Palette,
    tone: RiskTone,
    text: &str,
) -> f32 {
    let (fg, bg, border) = risk_badge(p, mode, tone);
    let font = egui::FontId::new(9.5, egui::FontFamily::Monospace);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, fg);
    let pad_x = 7.0;
    let pad_y = 2.5;
    let size = egui::vec2(galley.size().x + pad_x * 2.0, galley.size().y + pad_y * 2.0);
    let rect = egui::Rect::from_min_size(
        egui::pos2(left_center.x, left_center.y - size.y / 2.0),
        size,
    );
    ui.painter().rect(rect, 3.0, bg, Stroke::new(1.0_f32, border), StrokeKind::Inside);
    ui.painter().galley(rect.center() - 0.5 * galley.size(), galley, fg);
    size.x
}

/// Primary modal footer button (reference: accent fill, white text).
pub fn primary_button(ui: &mut egui::Ui, p: &Palette, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(Color32::WHITE).strong().size(12.5))
            .fill(p.accent)
            .stroke(Stroke::new(1.0_f32, p.accent_deep))
            .corner_radius(6.0),
    )
}

/// Plain modal footer button (reference: light grey fill, strong border).
pub fn modal_button(ui: &mut egui::Ui, p: &Palette, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(p.text).strong().size(12.5))
            .fill(p.chrome_deep)
            .stroke(Stroke::new(1.0_f32, p.border_strong))
            .corner_radius(6.0),
    )
}

/// §38B typography: OFL/MIT redistributable monospace faces the spec
/// allows (JetBrains Mono or Cascadia Mono), resolved from the system
/// at runtime. Returns candidate paths in preference order.
pub fn monospace_font_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let local = std::env::var("LOCALAPPDATA").ok();
    for name in ["CascadiaMono.ttf", "JetBrainsMono-Regular.ttf", "CascadiaCode.ttf"] {
        out.push(std::path::PathBuf::from(format!("C:\\Windows\\Fonts\\{name}")));
        if let Some(local) = &local {
            out.push(std::path::PathBuf::from(local).join("Microsoft\\Windows\\Fonts").join(name));
        }
    }
    out
}

/// Load the first available §38B monospace font into egui (idempotent
/// — guarded per context) plus a symbol fallback so glyphs like ✓ ✕ ●
/// ▸ ▾ ⚑ render instead of tofu boxes. Falls back silently to egui's
/// default faces when none of the allowed fonts is installed.
pub fn install_fonts(ctx: &egui::Context) {
    let guard = egui::Id::new("nf_fonts_installed");
    if ctx.data(|d| d.get_temp::<bool>(guard).unwrap_or(false)) {
        return;
    }
    ctx.data_mut(|d| d.insert_temp(guard, true));
    let mut fonts = egui::FontDefinitions::default();
    let mut changed = false;
    for path in monospace_font_candidates() {
        if let Ok(bytes) = std::fs::read(&path) {
            fonts
                .font_data
                .insert("nf_monospace".to_owned(), egui::FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "nf_monospace".to_owned());
            changed = true;
            break;
        }
    }
    // Symbol fallback for both families: the default proportional face
    // has no coverage for the UI glyphs this app uses, which rendered
    // as misaligned tofu squares (tree dots, modal ✕, chip icons…).
    let symbol_path = std::path::PathBuf::from("C:\\Windows\\Fonts\\seguisym.ttf");
    if let Ok(bytes) = std::fs::read(&symbol_path) {
        fonts
            .font_data
            .insert("nf_symbols".to_owned(), egui::FontData::from_owned(bytes).into());
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts.families.entry(family).or_default().insert(1, "nf_symbols".to_owned());
        }
        changed = true;
    }
    if changed {
        ctx.set_fonts(fonts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §38B is exact: light-theme badge triples must match the spec
    /// tokens byte for byte.
    #[test]
    fn light_risk_badge_triples_match_spec_tokens() {
        let p = palette(ThemeMode::Light);
        let (t, bg, b) = risk_badge(&p, ThemeMode::Light, RiskTone::High);
        assert_eq!((t, bg, b), (
            Color32::from_rgb(0xC0, 0x39, 0x2B),
            Color32::from_rgb(0xFB, 0xE9, 0xE7),
            Color32::from_rgb(0xF0, 0xC4, 0xBD),
        ));
        let (t, bg, b) = risk_badge(&p, ThemeMode::Light, RiskTone::Medium);
        assert_eq!((t, bg, b), (
            Color32::from_rgb(0xB3, 0x72, 0x0B),
            Color32::from_rgb(0xFD, 0xF1, 0xDE),
            Color32::from_rgb(0xF0, 0xD6, 0x9F),
        ));
        let (t, bg, b) = risk_badge(&p, ThemeMode::Light, RiskTone::Clean);
        assert_eq!((t, bg, b), (
            Color32::from_rgb(0x1F, 0x7A, 0x45),
            Color32::from_rgb(0xE7, 0xF5, 0xEC),
            Color32::from_rgb(0xBF, 0xE3, 0xCD),
        ));
    }

    /// Semantic roles never remap between themes.
    #[test]
    fn severity_roles_are_stable_across_themes() {
        use crate::analysis::rules::Severity;
        for mode in [ThemeMode::Dark, ThemeMode::Light] {
            let p = palette(mode);
            assert_eq!(severity_color(&p, Severity::Low), p.good);
            assert_eq!(severity_color(&p, Severity::Medium), p.warn);
            assert_eq!(severity_color(&p, Severity::High), p.danger);
            assert_eq!(severity_color(&p, Severity::Critical), p.danger);
        }
    }

    /// GUI-alignment tokens pinned to gui-reference.html: the light
    /// palette must carry the exact reference values.
    #[test]
    fn light_palette_matches_reference_tokens() {
        let p = palette(ThemeMode::Light);
        assert_eq!(p.accent_deep, Color32::from_rgb(0x16, 0x46, 0x80)); // #164680
        assert_eq!(p.hover_soft, Color32::from_rgb(0xEE, 0xF3, 0xFA));  // #EEF3FA
        assert_eq!(p.titlebar, Color32::from_rgb(0x1C, 0x2B, 0x3A));    // #1C2B3A
        assert_eq!(p.status_text, Color32::from_rgb(0xA9, 0xB7, 0xC4)); // #A9B7C4
        assert_eq!(p.selection, Color32::from_rgb(0xD9, 0xE9, 0xFB));   // #D9E9FB
        assert_eq!(p.grid_stripe, Color32::from_rgb(0xF2, 0xF6, 0xFB)); // #F2F6FB
    }
}
