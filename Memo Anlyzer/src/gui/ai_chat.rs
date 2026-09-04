//! AI investigator assistant panel: grounded Q&A over the open case.
//! Every answer cites verifiable ART- ids; absent evidence is said so.
//!
//! Visual identity: the panel is themed around the secondary AI
//! accent (§38B reserves it for AI surfaces) — navy header card with
//! a ringed avatar, avatar-led answer cards, quick-prompt chips and a
//! styled composer row.

use eframe::egui::{self, Color32, Layout, RichText, Stroke, Ui};

use crate::analysis::AnalysisReport;

use super::state::{AppState, ChatMessage};
use super::theme::{faded, mix, palette, Palette};

/// Right-side panel: the AI investigator chat.
pub fn draw_panel(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);
    let ai = p.accent_ai;

    // §31: state plainly how this panel runs — never imply offline if
    // it isn't. The chat itself always answers locally from the index;
    // the AI analysis layer may be external if configured.
    let external_configured = !app.settings.ai_endpoint.trim().is_empty();
    let mode_short = if external_configured {
        "LOCAL CHAT · EXTERNAL AI LAYER"
    } else {
        "LOCAL / OFFLINE"
    };

    let mut pending_question: Option<String> = None;
    let mut clear_chat = false;

    // ---- header card: navy band, ringed avatar, status + actions ----
    egui::Frame::default()
        .fill(p.titlebar)
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Avatar with a soft accent ring.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(32.0, 32.0), egui::Sense::hover());
                ui.painter().circle_stroke(rect.center(), 16.0, Stroke::new(1.5_f32, faded(ai, 0.55)));
                ui.painter().circle_filled(rect.center(), 12.5, ai);
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "✦",
                    egui::FontId::new(13.0, egui::FontFamily::Proportional),
                    Color32::WHITE,
                );
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.5;
                    ui.label(
                        RichText::new("AI INVESTIGATOR").color(Color32::WHITE).strong().size(12.5),
                    );
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let (dot, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                        ui.painter()
                            .circle_filled(dot.center(), 3.0, Color32::from_rgb(0x3D, 0xDC, 0x9A));
                        ui.label(
                            RichText::new(format!("{mode_short} · grounded answers only"))
                                .color(p.status_text)
                                .size(9.5),
                        );
                    });
                });
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    let has_history = app
                        .session
                        .as_ref()
                        .map(|s| !s.chat.is_empty())
                        .unwrap_or(false);
                    if has_history
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("New chat").color(p.status_text).size(10.5),
                                )
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::new(1.0_f32, faded(ai, 0.45)))
                                .corner_radius(10.0),
                            )
                            .on_hover_text("Clear this conversation")
                            .clicked()
                    {
                        clear_chat = true;
                    }
                });
            });
        });
    ui.add_space(8.0);

    // ---- conversation -------------------------------------------------
    egui::ScrollArea::vertical()
        .id_salt("ai_chat")
        .stick_to_bottom(true)
        .show(ui, |ui| {
            let Some(session) = &app.session else {
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Open a case to start asking questions.")
                        .color(p.text_muted)
                        .size(11.5),
                );
                return;
            };
            if session.chat.is_empty() {
                draw_empty_state(ui, &p, ai, &mut pending_question);
            }
            for msg in &session.chat {
                // Question bubble — right-aligned, AI-tinted.
                ui.with_layout(Layout::right_to_left(egui::Align::TOP), |ui| {
                    egui::Frame::default()
                        .fill(faded(ai, 0.16))
                        .stroke(Stroke::new(1.0_f32, faded(ai, 0.38)))
                        .corner_radius(9.0)
                        .inner_margin(egui::Margin::symmetric(10, 7))
                        .show(ui, |ui| {
                            ui.set_max_width(262.0);
                            ui.label(RichText::new(&msg.question).size(12.0));
                        });
                });
                ui.add_space(2.0);
                // Answer card — avatar + mini header + grounded body.
                let max_w = (ui.available_width() - 42.0).max(170.0);
                ui.horizontal_top(|ui| {
                    let (av, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
                    ui.painter().circle_filled(av.center(), 11.0, ai);
                    ui.painter().text(
                        av.center(),
                        egui::Align2::CENTER_CENTER,
                        "✦",
                        egui::FontId::new(11.0, egui::FontFamily::Proportional),
                        Color32::WHITE,
                    );
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        // §31: every answer carries its own runtime stamp —
                        // consistent with the panel header, never implied.
                        ui.label(
                            RichText::new(format!("AI Investigator · {}", msg.answer.mode))
                                .monospace()
                                .color(p.text_muted)
                                .size(8.5),
                        );
                        egui::Frame::default()
                            .fill(p.block)
                            .stroke(Stroke::new(1.0_f32, p.border))
                            .corner_radius(9.0)
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.set_max_width(max_w);
                                ui.label(RichText::new(&msg.answer.text).size(11.5));
                                if !msg.answer.references.is_empty() {
                                    ui.add_space(6.0);
                                    ui.label(
                                        RichText::new("GROUNDED ON")
                                            .color(p.text_muted)
                                            .strong()
                                            .size(8.5),
                                    );
                                    ui.horizontal_wrapped(|ui| {
                                        for r in &msg.answer.references {
                                            ui.label(
                                                RichText::new(format!(" {r} "))
                                                    .monospace()
                                                    .color(p.accent_deep)
                                                    .size(9.5),
                                            );
                                        }
                                    });
                                }
                                // Gate audit trail: shown, never hidden.
                                if !msg.answer.dropped_claims.is_empty() {
                                    ui.add_space(6.0);
                                    egui::Frame::default()
                                        .fill(faded(p.warn, 0.10))
                                        .stroke(Stroke::new(1.0_f32, faded(p.warn, 0.4)))
                                        .corner_radius(6.0)
                                        .inner_margin(egui::Margin::symmetric(8, 6))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new("GROUNDING GATE — dropped ungrounded claims:")
                                                    .color(p.warn)
                                                    .strong()
                                                    .size(9.5),
                                            );
                                            for dropped in &msg.answer.dropped_claims {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "✕ {} — {}",
                                                        dropped.claim, dropped.reason
                                                    ))
                                                    .color(p.warn)
                                                    .size(9.5),
                                                );
                                            }
                                        });
                                }
                            });
                    });
                });
                ui.add_space(10.0);
            }
        });

    // ---- composer (needs &mut session after the borrows above) --------
    let mut submit = false;
    ui.add_space(2.0);
    egui::Frame::default()
        .fill(p.input_bg)
        .stroke(Stroke::new(1.0_f32, p.border_strong))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(session) = &mut app.session {
                    let width = (ui.available_width() - 44.0).max(120.0);
                    let response = ui.add_sized(
                        [width, 24.0],
                        egui::TextEdit::singleline(&mut session.chat_input)
                            .hint_text("Ask the AI investigator…")
                            .frame(false),
                    );
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit = true;
                    }
                    if ui
                        .add(
                            egui::Button::new(RichText::new("➤").color(Color32::WHITE).strong())
                                .fill(ai)
                                .stroke(Stroke::new(1.0_f32, faded(ai, 0.6)))
                                .corner_radius(7.0)
                                .min_size(egui::vec2(32.0, 26.0)),
                        )
                        .on_hover_text("Send")
                        .clicked()
                    {
                        submit = true;
                    }
                } else {
                    ui.label(
                        RichText::new("Open a case to start asking questions.")
                            .color(p.text_muted)
                            .size(11.0),
                    );
                }
            });
        });

    if clear_chat {
        if let Some(session) = &mut app.session {
            session.chat.clear();
        }
    }
    if let Some(q) = pending_question {
        if let Some(session) = &mut app.session {
            session.chat_input = q;
        }
        ask(app);
    } else if submit {
        ask(app);
    }
}

/// Empty-conversation state: large avatar, greeting and quick-prompt
/// chips that feed straight into `ask()`.
fn draw_empty_state(
    ui: &mut Ui,
    p: &Palette,
    ai: Color32,
    pending_question: &mut Option<String>,
) {
    ui.add_space(18.0);
    ui.vertical_centered(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(46.0, 46.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 23.0, faded(ai, 0.16));
        ui.painter().circle_stroke(rect.center(), 23.0, Stroke::new(1.5_f32, faded(ai, 0.5)));
        ui.painter().circle_filled(rect.center(), 15.0, ai);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "✦",
            egui::FontId::new(15.0, egui::FontFamily::Proportional),
            Color32::WHITE,
        );
        ui.add_space(10.0);
        ui.label(RichText::new("How can I help the investigation?").strong().size(13.0));
        ui.add_space(2.0);
        ui.label(
            RichText::new(
                "Ask about findings, processes, network, persistence,\n\
                 events, memory, integrity or ML anomalies — or start with:",
            )
            .color(p.text_dim)
            .size(11.0),
        );
        ui.add_space(10.0);
        for q in [
            "What's the most suspicious thing here?",
            "Any flagged network connections?",
            "Summarize the findings",
            "Evidence integrity status?",
            "Any ML anomalies?",
        ] {
            let resp = ui.add(
                egui::Button::new(RichText::new(format!("✦  {q}")).color(p.accent_deep).size(11.0))
                    .fill(mix(p.panel, ai, 0.08))
                    .stroke(Stroke::new(1.0_f32, faded(ai, 0.38)))
                    .corner_radius(12.0),
            );
            if resp.clicked() {
                *pending_question = Some(q.to_string());
            }
            ui.add_space(2.0);
        }
    });
}

fn ask(app: &mut AppState) {
    let question = app
        .session
        .as_mut()
        .map(|s| std::mem::take(&mut s.chat_input).trim().to_string())
        .unwrap_or_default();
    if question.is_empty() {
        return;
    }
    let external_configured = !app.settings.ai_endpoint.trim().is_empty();
    let Some(session) = &app.session else { return };
    let Some(exam) = &session.exam else {
        if let Some(session) = &mut app.session {
            session.chat.push(ChatMessage {
                question,
                answer: crate::analysis::assistant::AssistantAnswer {
                    text: "No evidence image is open. Add and ingest a .AIF evidence image first — I only answer from real, indexed evidence.".into(),
                    references: Vec::new(),
                    mode: crate::analysis::assistant::mode_label(external_configured),
                    dropped_claims: Vec::new(),
                },
            });
        }
        return;
    };

    let fallback = AnalysisReport {
        case_id: exam.case_id().to_string(),
        generated_at: String::new(),
        findings: Vec::new(),
        ml: crate::analysis::ml::MlReport {
            model_id: crate::ml::models::MODEL_ID.to_string(),
            status: crate::analysis::ml::MlStatus::NotAvailable,
            samples_used: 0,
            anomalies: Vec::new(),
            evidence_class: "ML ANOMALY".to_string(),
        },
        integrity_problems: exam.failed_verifications(),
        coverage: Vec::new(),
    };
    let report_ref = session.report.as_ref().unwrap_or(&fallback);
    let answer = crate::analysis::assistant::answer(exam, report_ref, &question, external_configured);

    if let Some(session) = &mut app.session {
        session.chat.push(ChatMessage { question, answer });
    }
}

/// Draw a toast stack (shared helper used by the app frame). Reference
/// toasts: bottom-right navy stack, status icon left, shadowed cards.
pub fn draw_toasts(app: &mut AppState, ctx: &eframe::egui::Context) {
    let p = palette(app.theme);
    app.prune_toasts();
    let toasts = app.toasts.clone();
    if toasts.is_empty() {
        return;
    }
    // Reference motion: slide in from the right (~.3s ease-out), then
    // fade out as the toast's lifetime runs down.
    for (idx, toast) in toasts.iter().rev().take(3).enumerate() {
        let elapsed = toast.created.elapsed().as_secs_f32();
        let t_in = super::theme::cubic_out((elapsed / 0.3).min(1.0));
        let fade_out = ((6.0 - elapsed) / 0.5).clamp(0.0, 1.0);
        let opacity = t_in * fade_out;
        let slide_x = (1.0 - t_in) * 300.0;
        let mut layer: Option<egui::LayerId> = None;
        egui::Area::new(egui::Id::new("toast_card").with(idx).with(toast.message.as_str()))
            .anchor(
                egui::Align2::RIGHT_BOTTOM,
                egui::vec2(-14.0, -40.0 - (idx as f32) * 54.0),
            )
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_opacity(opacity);
                egui::Frame::default()
                    .fill(p.titlebar)
                    .corner_radius(8.0)
                    .shadow(egui::epaint::Shadow {
                        offset: [0, 6],
                        blur: 18,
                        spread: 0,
                        color: Color32::from_black_alpha(80),
                    })
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_min_width(260.0);
                        ui.set_max_width(380.0);
                        ui.horizontal(|ui| {
                            let (icon, icon_color) = if toast.danger {
                                ("⚠", p.warn)
                            } else {
                                ("✓", Color32::from_rgb(0x3D, 0xDC, 0x9A))
                            };
                            ui.label(RichText::new(icon).color(icon_color).strong().size(13.0));
                            ui.label(
                                RichText::new(&toast.message)
                                    .color(Color32::from_rgb(0xE7, 0xED, 0xF3))
                                    .size(12.0),
                            );
                        });
                    });
                layer = Some(ui.layer_id());
            });
        if slide_x > 0.05 {
            if let Some(layer) = layer {
                ctx.transform_layer_shapes(
                    layer,
                    egui::emath::TSTransform {
                        translation: egui::vec2(slide_x, 0.0),
                        scaling: 1.0,
                    },
                );
            }
        }
    }
    ctx.request_repaint_after(std::time::Duration::from_millis(60));
}
