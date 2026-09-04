//! Findings panel: every analytical indicator with severity, reasoning
//! (indicators) and clickable ART-id links to the grounding evidence.

use eframe::egui::{self, RichText, Ui};

use super::state::{AppState, MainView};
use super::theme::{palette, severity_color};

pub fn draw(app: &mut AppState, ui: &mut Ui) {
    let p = palette(app.theme);
    let report_present = app.session.as_ref().and_then(|s| s.report.as_ref()).is_some();

    ui.horizontal(|ui| {
        ui.label(RichText::new("FINDINGS").strong().size(13.0));
        if let Some(session) = &app.session {
            if let Some(report) = &session.report {
                ui.label(
                    RichText::new(format!(
                        "{} indicator(s) · {} HIGH · {} MEDIUM · verdict: {}",
                        report.findings.len(),
                        report.high_risk_count(),
                        report.medium_risk_count(),
                        report.verdict_label()
                    ))
                    .color(p.text_dim)
                    .size(11.5),
                );
            } else if session.exam.is_none() {
                ui.label(RichText::new("no analysis run yet").color(p.text_dim).size(11.5));
            }
        }
    });
    ui.separator();

    let Some(session) = &mut app.session else { return };

    if !report_present {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            if session.exam.is_none() {
                ui.label(RichText::new("No findings — no evidence image has been ingested yet.").color(p.text_dim));
                ui.label(
                    RichText::new("The application stays empty until real evidence is loaded.")
                        .color(p.text_dim)
                        .size(11.5),
                );
            } else {
                ui.label(RichText::new("Run the analysis (toolbar ▸ Run Analysis) to evaluate the ingested evidence.").color(p.text_dim));
            }
        });
        return;
    }

    let report = session.report.clone().expect("checked above");
    if report.findings.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("CLEAN — the rule engine and ML scoring found no indicators in the ingested evidence.").color(p.good));
            ui.label(
                RichText::new(format!("Analyzed at {}", report.generated_at)).color(p.text_dim).size(11.0),
            );
        });
        draw_ai_section(app, ui);
        return;
    }

    egui::ScrollArea::vertical().id_salt("findings_list").show(ui, |ui| {
        for (idx, finding) in report.findings.iter().enumerate() {
            let color = severity_color(&p, finding.severity);
            egui::Frame::default()
                .fill(p.panel_deep)
                .stroke(egui::Stroke::new(1.0_f32, p.border))
                .corner_radius(6.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&finding.rule_id).monospace().color(color).strong());
                        ui.label(RichText::new(finding.severity.label()).color(color).size(11.0).strong());
                        ui.label(RichText::new(&finding.evidence_class).weak().size(11.0));
                        // §24/§29/§33: method + confidence always visible.
                        ui.label(
                            RichText::new(format!("{} · {}", finding.method.label(), finding.confidence_label()))
                                .color(p.accent)
                                .size(11.0),
                        );
                        if let Some(pid) = finding.pid {
                            ui.label(RichText::new(format!("pid {pid}")).weak().size(11.0));
                        }
                    });
                    ui.label(RichText::new(&finding.title).strong().size(12.5));
                    ui.label(RichText::new(&finding.summary).size(12.0));
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!("Why flagged: {}", finding.indicators.join("; ")))
                            .color(p.text_dim)
                            .size(11.5),
                    );
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Evidence:").weak().size(11.0));
                        for id in &finding.supporting_artifacts {
                            if ui.link(RichText::new(id).monospace().size(11.0)).clicked() {
                                if let Some(session) = &mut app.session {
                                    session.selected_artifact = Some(id.clone());
                                    session.view = MainView::Explorer;
                                }
                            }
                        }
                    });
                    draw_finding_workflow(app, ui, &p, finding, idx);
                });
            ui.add_space(6.0);
        }

        // §27 detection coverage: what the engine could NOT evaluate.
        if !report.coverage.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new("DETECTION COVERAGE").strong().color(p.accent).size(12.0));
            ui.add_space(2.0);
            for note in &report.coverage {
                let mark = match note.status {
                    crate::analysis::rules::CoverageStatus::Evaluated => ("EVALUATED", p.good),
                    crate::analysis::rules::CoverageStatus::NotEvaluated => ("NOT EVALUATED", p.warn),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("[{}]", mark.0)).monospace().color(mark.1).size(11.0));
                    ui.label(RichText::new(&note.category).strong().size(11.5));
                    ui.label(RichText::new(&note.detail).color(p.text_dim).size(11.5));
                });
            }
        }

        draw_ai_section(app, ui);
    });
}

/// §35/§36 investigator workflow for one finding: status selection
/// (NEW/REVIEWED/CONFIRMED/DISMISSED) and a note field. Every change
/// persists to the case database immediately; nothing auto-confirms.
fn draw_finding_workflow(
    app: &mut AppState,
    ui: &mut Ui,
    p: &super::theme::Palette,
    finding: &crate::analysis::rules::Finding,
    seq: usize,
) {
    use crate::casemgmt::db::FindingStatus;
    // Same key the persistence layer uses (finding_rows ordering).
    let key = crate::analysis::rule_row_key(finding, seq);
    let current = app
        .session
        .as_ref()
        .and_then(|s| s.finding_workflow.get(&key).copied())
        .unwrap_or(FindingStatus::New);

    ui.horizontal(|ui| {
        ui.label(RichText::new("Status:").weak().size(11.0));
        egui::ComboBox::from_id_salt(format!("finding_status_{key}"))
            .selected_text(RichText::new(current.label()).color(workflow_color(p, current)).size(11.0))
            .width(100.0)
            .show_ui(ui, |ui| {
                for option in FindingStatus::ALL {
                    if ui
                        .selectable_label(current == option, option.label())
                        .clicked()
                        && current != option
                    {
                        if let Some(session) = &mut app.session {
                            if let Some(image_id) = session.current_image_id {
                                let _ = session.db.set_finding_status(image_id, &key, option);
                            }
                            session.finding_workflow.insert(key.clone(), option);
                        }
                    }
                }
            });
        if current == FindingStatus::New {
            ui.label(
                RichText::new("unreviewed — the tool never auto-confirms (§35)")
                    .color(p.text_dim)
                    .size(10.5)
                    .italics(),
            );
        }
    });

    ui.horizontal(|ui| {
        let Some(session) = &mut app.session else { return };
        let commit = {
            let draft = session.finding_note_draft.entry(key.clone()).or_default();
            let response = ui.add(
                egui::TextEdit::singleline(draft)
                    .hint_text("investigator note (§36) — Enter or click away to save")
                    .desired_width(300.0)
                    .font(egui::TextStyle::Small),
            );
            response.lost_focus()
        };
        if commit {
            let text = session.finding_note_draft.get(&key).cloned().unwrap_or_default();
            if let Some(image_id) = session.current_image_id {
                let _ = session.db.set_finding_note(image_id, &key, &text);
            }
        }
    });
}

fn workflow_color(p: &super::theme::Palette, status: crate::casemgmt::db::FindingStatus) -> eframe::egui::Color32 {
    use crate::casemgmt::db::FindingStatus;
    match status {
        FindingStatus::New => p.text_dim,
        FindingStatus::Reviewed => p.accent,
        FindingStatus::Confirmed => p.warn,
        FindingStatus::Dismissed => p.good,
    }
}

/// §29/§32 AI analysis layer: provider identity, mode (local/offline
/// vs external), structured grounded findings, and claims the
/// grounding gate rejected — shown, never hidden.
fn draw_ai_section(app: &mut super::state::AppState, ui: &mut Ui) {
    let p = super::theme::palette(app.theme);
    let ai = app.session.as_ref().and_then(|s| s.ai_analysis.clone());
    ui.add_space(10.0);
    ui.label(RichText::new("AI ANALYSIS LAYER (§29/§32)").strong().color(p.accent).size(12.0));
    ui.add_space(2.0);
    let Some(ai) = ai else {
        ui.label(
            RichText::new("Not run in this session — Run Analysis computes it alongside the rule engine.")
                .color(p.text_dim)
                .size(11.5),
        );
        return;
    };

    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(&ai.provider.name).strong().size(11.5));
        ui.label(
            RichText::new(format!("[{}]", ai.provider.mode.label()))
                .monospace()
                .color(p.accent)
                .size(11.0),
        );
    });
    ui.label(RichText::new(&ai.provider.description).color(p.text_dim).size(11.0));

    if let Some(err) = &ai.error {
        ui.add_space(2.0);
        ui.label(RichText::new(err).color(p.warn).size(11.5));
    }

    for finding in &ai.findings {
        let color = severity_color(&p, finding.severity);
        ui.add_space(3.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(finding.severity.label()).color(color).size(11.0).strong());
            ui.label(
                RichText::new(format!("{} · {}", finding.method.label(), finding.confidence_label()))
                    .color(p.accent)
                    .size(11.0),
            );
            ui.label(RichText::new(&finding.title).strong().size(11.5));
        });
        ui.label(RichText::new(&finding.reasoning).color(p.text_dim).size(11.0));
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Evidence:").weak().size(11.0));
            for id in &finding.evidence_artifacts {
                if ui.link(RichText::new(id).monospace().size(11.0)).clicked() {
                    if let Some(session) = &mut app.session {
                        session.selected_artifact = Some(id.clone());
                        session.view = MainView::Explorer;
                    }
                }
            }
        });
        ui.label(
            RichText::new(format!("Limitations: {}", finding.limitations))
                .color(p.text_dim)
                .size(10.5)
                .italics(),
        );
    }

    if !ai.rejected.is_empty() {
        ui.add_space(6.0);
        ui.label(
            RichText::new(format!("REJECTED BY GROUNDING GATE ({})", ai.rejected.len()))
                .color(p.warn)
                .strong()
                .size(11.5),
        );
        for r in &ai.rejected {
            ui.label(
                RichText::new(format!("• {} — {}", r.title, r.reason))
                    .color(p.warn)
                    .size(11.0),
            );
        }
    }
}
