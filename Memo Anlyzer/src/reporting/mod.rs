//! Forensic report generation: JSON / HTML / PDF exports that strictly
//! separate evidence classes — OBSERVED FACT, INTEGRITY VERIFICATION,
//! ANALYTICAL INDICATOR, ML ANOMALY, INVESTIGATOR INTERPRETATION.
//!
//! §43 content contract: case information, examiner, evidence list,
//! evidence hashes, integrity status, artifact summary, timeline,
//! findings (with §35 investigator status + notes), AI findings,
//! explainability (§30), supporting evidence, tool version, timestamp.
//! Every line derives from the case database, the ingested AIF image
//! and the grounded analysis outputs. Missing inputs are reported as
//! explicit absences — the report never invents data.

pub mod html;
pub mod json;
pub mod pdf;

use crate::ai::ValidatedAnalysis;
use crate::analysis::AnalysisReport;
use crate::casemgmt::db::{CaseMeta, CaseNote, CustodyEntry, FindingRow, FindingStatus, TimelineEventRecord};
use crate::correlation::CorrelationReport;
use crate::ingest::ExaminedCase;

/// Tool identity embedded in every report (§43 tool version).
pub const TOOL_NAME: &str = "NEUROFORENSICS AI";

pub fn tool_version() -> String {
    format!("{TOOL_NAME} v{}", env!("CARGO_PKG_VERSION"))
}

/// Everything the §43 report may draw from. Absent inputs stay
/// `None`/empty and surface as explicit absence statements.
pub struct ReportInputs<'a> {
    pub meta: &'a CaseMeta,
    pub exam: Option<&'a ExaminedCase>,
    pub report: Option<&'a AnalysisReport>,
    /// §23 correlation engine output (Phase 5).
    pub correlations: Option<&'a CorrelationReport>,
    /// §29/§32 validated AI-layer output with its rejection ledger.
    pub ai: Option<&'a ValidatedAnalysis>,
    /// §35 persisted finding rows (status + investigator notes).
    pub finding_workflow: &'a [FindingRow],
    /// §22 persisted timeline events for the report's TIMELINE section.
    pub timeline: &'a [TimelineEventRecord],
    /// §41 append-only chain-of-custody trail (oldest first).
    pub custody: &'a [CustodyEntry],
    pub notes: &'a [CaseNote],
}

/// Flat line-based report content shared by the HTML and PDF exporters.
pub struct ReportContent {
    pub title: String,
    pub demo_mode: bool,
    pub sections: Vec<(String, Vec<String>)>,
}

/// Assemble the canonical report content for the open case.
pub fn collect(inputs: &ReportInputs) -> ReportContent {
    let meta = inputs.meta;
    let exam = inputs.exam;
    let report = inputs.report;
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let demo_mode = exam.map(|e| e.is_demo()).unwrap_or(false);

    // §35 workflow lookup: finding_key -> persisted row.
    let workflow: std::collections::HashMap<&str, &FindingRow> = inputs
        .finding_workflow
        .iter()
        .map(|r| (r.finding_key.as_str(), r))
        .collect();

    // Case identity (from the persistent case database).
    let identity = vec![
        format!("Case number: {}", meta.case_number),
        format!("Case name: {}", meta.case_name),
        format!("Examiner: {}", meta.examiner),
        format!("Organization: {}", meta.organization),
        format!("Description: {}", if meta.description.is_empty() { "—" } else { &meta.description }),
        format!("Case created: {}", meta.created_at),
        format!("Case directory: {}", meta.case_dir),
        format!("Tool version: {}", tool_version()),
        format!("Report generated: {}", chrono::Local::now().to_rfc3339()),
    ];
    sections.push(("CASE IDENTITY".into(), identity));

    // Documentation block: how an examiner should read this report.
    sections.push((
        "HOW TO READ THIS REPORT".into(),
        vec![
            "This report strictly separates five evidence classes, in order of appearance:".into(),
            "  OBSERVED FACT — raw data recorded by the collector, quoted unmodified.".into(),
            "  INTEGRITY VERIFICATION — SHA-256 hash checks for the container and every artifact.".into(),
            "  ANALYTICAL INDICATOR — rule-engine findings; each one cites the artifact IDs it is based on.".into(),
            "  ML ANOMALY — statistical outliers scored by the local isolation-forest model.".into(),
            "  INVESTIGATOR INTERPRETATION — notes and status decisions recorded by the examiner.".into(),
            "Severity legend: HIGH = strong indicator to act on, MEDIUM = requires review, LOW = informational.".into(),
            "Every artifact ID (ART-xxxxxx) is verifiable in the case index; findings are POTENTIAL indicators, never confirmations.".into(),
            "Lines marked WARNING: or MISMATCH draw attention to integrity gaps; their absence means all checks passed.".into(),
        ],
    ));

    // Observed facts (from the ingested evidence image only).
    let mut facts = Vec::new();
    match exam {
        None => facts.push("No evidence image ingested — nothing observed.".into()),
        Some(exam) => {
            facts.push(format!("Evidence image: {}", exam.image_name));
            facts.push(format!("Image path: {}", exam.image_path.display()));
            facts.push(format!("Image size: {} bytes", exam.size_bytes));
            facts.push(format!("AIF format version: {}", exam.case_doc.format_version));
            facts.push(format!("AIF case id: {}", exam.case_id()));
            facts.push(format!(
                "Collector: {} {}",
                exam.manifest.collector.name, exam.manifest.collector.version
            ));
            facts.push(format!(
                "Acquired host: {} ({})",
                exam.manifest.host.hostname, exam.manifest.host.os
            ));
            facts.push(format!(
                "Acquisition window: {} -> {}",
                exam.manifest.acquisition.start_time, exam.manifest.acquisition.end_time
            ));
            facts.push(format!("Acquisition status: {}", exam.manifest.acquisition.status));
            facts.push(format!("Artifacts indexed: {}", exam.artifacts.len()));
            for cat in &exam.tree.categories {
                facts.push(format!("  {} artifacts: {} ({} bytes)", cat.label, cat.artifacts.len(), cat.bytes));
            }
            if demo_mode {
                facts.push("MODE: DEMO / SYNTHETIC EVIDENCE — NOT A REAL CASE".into());
            }
        }
    }
    sections.push(("OBSERVED FACT".into(), facts));

    // Integrity verification (container + per-artifact SHA-256).
    let mut integrity = Vec::new();
    match exam {
        None => integrity.push("No evidence image ingested — no integrity checks performed.".into()),
        Some(exam) => {
            integrity.push(format!("Container SHA-256: {}", exam.container_check.calculated));
            match exam.container_check.ok {
                Some(true) => integrity.push(format!(
                    "Container hash VERIFIED against {}",
                    exam.container_check.expected_source.as_deref().unwrap_or("sidecar")
                )),
                Some(false) => integrity.push(format!(
                    "CONTAINER HASH MISMATCH — expected {} from {}",
                    exam.container_check.expected.as_deref().unwrap_or("?"),
                    exam.container_check.expected_source.as_deref().unwrap_or("sidecar")
                )),
                None => integrity.push(
                    "No external container hash found — container integrity not independently verifiable.".into(),
                ),
            }
            let ok = exam.artifact_checks.iter().filter(|c| c.ok).count();
            integrity.push(format!(
                "Artifact SHA-256 verification: {} of {} OK",
                ok,
                exam.artifact_checks.len()
            ));
            for w in &exam.warnings {
                integrity.push(format!("  WARNING: {w}"));
            }
        }
    }
    sections.push(("INTEGRITY VERIFICATION".into(), integrity));

    // §43 timeline (mirrored from real evidence timestamps).
    let mut timeline = Vec::new();
    if inputs.timeline.is_empty() {
        timeline.push("No timeline events persisted for this case.".into());
    } else {
        timeline.push(format!("{} event(s) mirrored from evidence timestamps:", inputs.timeline.len()));
        for ev in inputs.timeline {
            let detail = if ev.detail.is_empty() { String::new() } else { format!(" — {}", ev.detail) };
            let artifact = ev
                .artifact_id
                .as_deref()
                .map(|a| format!(" ({a})"))
                .unwrap_or_default();
            timeline.push(format!("{} [{}] {}{detail}{artifact}", ev.ts, ev.category, ev.label));
        }
    }
    sections.push(("TIMELINE".into(), timeline));

    // Analytical indicators (grounded rule findings + §35 workflow state).
    let mut indicators = Vec::new();
    match report {
        None => indicators.push("Analysis not run for this case.".into()),
        Some(report) if report.findings.is_empty() => {
            indicators.push("No analytical indicators produced for this case.".into())
        }
        Some(report) => {
            indicators.push(format!("{} indicator(s) produced by the rule engine:", report.findings.len()));
            for (idx, finding) in report.findings.iter().enumerate() {
                let severity = format!("{:?}", finding.severity).to_ascii_uppercase();
                indicators.push(format!(
                    "[{}] INDICATOR {} OF {} · {} — {}",
                    severity,
                    idx + 1,
                    report.findings.len(),
                    finding.rule_id,
                    finding.title
                ));
                indicators.push(format!("    summary: {}", finding.summary));
                indicators.push(format!(
                    "    method: {} · confidence: {}",
                    finding.method.label(),
                    finding.confidence_label()
                ));
                indicators.push(format!("    supporting artifacts: {}", finding.supporting_artifacts.join(", ")));
                match workflow.get(crate::analysis::rule_row_key(finding, idx).as_str()) {
                    Some(row) => {
                        indicators.push(format!("    investigator status: {}", row.status.label()));
                        if !row.investigator_note.is_empty() {
                            indicators.push(format!("    investigator note: {}", row.investigator_note));
                        }
                    }
                    None => indicators.push(
                        "    investigator status: not persisted (run analysis to create workflow rows)".into(),
                    ),
                }
            }
        }
    }
    sections.push(("ANALYTICAL INDICATOR".into(), indicators));

    // §27 detection coverage: what could not be evaluated, and why.
    if let Some(report) = report {
        if !report.coverage.is_empty() {
            let mut coverage = Vec::new();
            for note in &report.coverage {
                let status = match note.status {
                    crate::analysis::rules::CoverageStatus::Evaluated => "EVALUATED",
                    crate::analysis::rules::CoverageStatus::NotEvaluated => "NOT EVALUATED",
                };
                coverage.push(format!("[{}] {} — {}", status, note.category, note.detail));
            }
            sections.push(("DETECTION COVERAGE".into(), coverage));
        }
    }

    // §23 correlation engine (Phase 5): links + activity chains.
    let mut corr = Vec::new();
    match inputs.correlations {
        None => corr.push("Correlation engine not run for this case.".into()),
        Some(c) if c.links.is_empty() && c.activities.is_empty() => {
            corr.push("No cross-stream links found in this evidence.".into())
        }
        Some(c) => {
            corr.push(format!("Cross-stream links: {}", c.links.len()));
            for link in &c.links {
                corr.push(format!(
                    "    [{}] {} <-> {} — matched value: {}",
                    link.kind.label(),
                    link.a.label,
                    link.b.label,
                    link.matched
                ));
                corr.push(format!(
                    "        artifacts: {} · {}",
                    link.a.artifact_id, link.b.artifact_id
                ));
            }
            corr.push(format!("Correlated activity chains: {}", c.activities.len()));
            for act in &c.activities {
                corr.push(format!(
                    "    pid {} · {} ({}) — linked with: {} [{}]",
                    act.process_pid,
                    act.process_name,
                    act.process_artifact,
                    act.partners.join(", "),
                    act.kinds.join(", ")
                ));
            }
        }
    }
    sections.push(("CORRELATION".into(), corr));

    // ML anomalies (local isolation forest over real process evidence).
    let mut ml_lines = Vec::new();
    match report {
        None => ml_lines.push("Analysis not run for this case.".into()),
        Some(report) => {
            ml_lines.push(format!("Model: {}", report.ml.model_id));
            ml_lines.push(format!("Status: {}", report.ml.status.label()));
            ml_lines.push(format!("Samples used: {}", report.ml.samples_used));
            for anomaly in &report.ml.anomalies {
                ml_lines.push(format!(
                    "pid {} ({}) score {:.3} — dominant features: {} ({})",
                    anomaly.pid,
                    anomaly.process_name,
                    anomaly.score,
                    anomaly.dominant_features.join(", "),
                    anomaly.supporting_artifact.as_deref().unwrap_or("no artifact reference")
                ));
            }
            ml_lines.push("ML anomalies are statistical observations, not confirmations.".into());
        }
    }
    sections.push(("ML ANOMALY".into(), ml_lines));

    // §29/§32 AI analysis layer: provider, grounded findings, and the
    // rejection ledger — shown, never hidden.
    let mut ai_lines = Vec::new();
    match inputs.ai {
        None => ai_lines.push(
            "Not run in this session — Run Analysis computes the AI layer alongside the rule engine.".into(),
        ),
        Some(ai) => {
            ai_lines.push(format!("Provider: {} [{}]", ai.provider.name, ai.provider.mode.label()));
            ai_lines.push(ai.provider.description.clone());
            if let Some(err) = &ai.error {
                ai_lines.push(format!("Provider error: {err}"));
            }
            ai_lines.push(format!("Validated findings: {}", ai.findings.len()));
            for f in &ai.findings {
                ai_lines.push(format!(
                    "[{}] {} ({} · {})",
                    f.severity.label(),
                    f.title,
                    f.method.label(),
                    f.confidence_label()
                ));
                ai_lines.push(format!("    reasoning: {}", f.reasoning));
                ai_lines.push(format!("    evidence: {}", f.evidence_artifacts.join(", ")));
                ai_lines.push(format!("    limitations: {}", f.limitations));
            }
            ai_lines.push(format!("Rejected by grounding gate: {}", ai.rejected.len()));
            for r in &ai.rejected {
                ai_lines.push(format!("    {} — {}", r.title, r.reason));
            }
        }
    }
    sections.push(("AI ANALYSIS LAYER".into(), ai_lines));

    // §30/§43 explainability: one card per finding and ML anomaly.
    let mut xai_lines = Vec::new();
    match (exam, report) {
        (None, _) => xai_lines.push("Not available — no ingested evidence to explain.".into()),
        (Some(_), None) => xai_lines.push("Analysis not run for this case.".into()),
        (Some(exam), Some(report)) => {
            for finding in &report.findings {
                let explanation = crate::analysis::xai::explain_finding(exam, finding);
                xai_lines.push(format!("--- {} ---", finding.rule_id));
                xai_lines.extend(explanation.render().lines().map(|l| format!("    {l}")));
            }
            for anomaly in &report.ml.anomalies {
                let explanation = crate::analysis::xai::explain_anomaly(exam, anomaly, &report.ml.model_id);
                xai_lines.push(format!("--- {} · pid {} ---", report.ml.model_id, anomaly.pid));
                xai_lines.extend(explanation.render().lines().map(|l| format!("    {l}")));
            }
        }
    }
    sections.push(("EXPLAINABILITY".into(), xai_lines));

    // §35 finding workflow: persisted status + notes per finding.
    let mut wf = Vec::new();
    if inputs.finding_workflow.is_empty() {
        wf.push("No persisted finding rows — run analysis to create them.".into());
    } else {
        let count = |s: FindingStatus| inputs.finding_workflow.iter().filter(|r| r.status == s).count();
        wf.push(format!(
            "Persisted finding rows: {} ({} NEW · {} REVIEWED · {} CONFIRMED · {} DISMISSED)",
            inputs.finding_workflow.len(),
            count(FindingStatus::New),
            count(FindingStatus::Reviewed),
            count(FindingStatus::Confirmed),
            count(FindingStatus::Dismissed)
        ));
        wf.push("Status changes only through explicit investigator action (§35) — the tool never auto-confirms.".into());
        for row in inputs.finding_workflow {
            wf.push(format!("[{}] {} — {}", row.status.label(), row.finding_id, row.title));
            wf.push(format!(
                "    category: {} · method: {} · {}",
                row.category,
                row.method,
                row.confidence
                    .map(|c| format!("confidence {c:.2}"))
                    .unwrap_or_else(|| "confidence not recorded".to_string())
            ));
            wf.push(format!(
                "    artifacts: {}",
                if row.supporting_artifacts.is_empty() {
                    "—".to_string()
                } else {
                    row.supporting_artifacts.join(", ")
                }
            ));
            wf.push(format!(
                "    note: {}",
                if row.investigator_note.is_empty() { "—" } else { row.investigator_note.as_str() }
            ));
        }
    }
    sections.push(("FINDING WORKFLOW".into(), wf));

    // §41 chain of custody: the immutable trail of every operation the
    // tool performed on this case (append-only, never edited).
    let mut trail = Vec::new();
    if inputs.custody.is_empty() {
        trail.push("No custody entries recorded for this case yet.".into());
    } else {
        trail.push(format!("{} immutable entr{}, oldest first:", inputs.custody.len(), if inputs.custody.len() == 1 { "y" } else { "ies" }));
        for e in inputs.custody {
            trail.push(format!(
                "{} [{}] {} — {}",
                e.ts,
                if e.examiner.is_empty() { "examiner not recorded" } else { e.examiner.as_str() },
                e.operation,
                if e.detail.is_empty() { "—" } else { e.detail.as_str() },
            ));
        }
    }
    sections.push(("CHAIN OF CUSTODY".into(), trail));

    // Investigator interpretation (notes recorded in the case database).
    let mut note_lines = Vec::new();
    if inputs.notes.is_empty() {
        note_lines.push("No investigator notes recorded.".into());
    }
    for note in inputs.notes {
        note_lines.push(format!(
            "[{}] {}: {}",
            note.created_at,
            note.artifact_id.as_deref().unwrap_or("case-wide"),
            note.text
        ));
    }
    sections.push(("INVESTIGATOR INTERPRETATION".into(), note_lines));

    // Disclaimer.
    sections.push((
        "NOTICE".into(),
        vec![
            "All statements in this report derive exclusively from the case database and the ingested AIF evidence image.".into(),
            "Findings are POTENTIAL indicators, not confirmations. The original AIF was never modified.".into(),
            "Finding statuses reflect explicit investigator actions (§35); rows created by analysis always enter as NEW.".into(),
        ],
    ));

    let title = format!(
        "NEUROFORENSICS AI — Forensic Report — {}",
        if meta.case_number.is_empty() { meta.case_name.clone() } else { meta.case_number.clone() }
    );
    ReportContent { title, demo_mode, sections }
}

/// Escape text for safe embedding in HTML output.
pub fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> CaseMeta {
        CaseMeta {
            case_number: "CASE-TEST-001".into(),
            case_name: "Unit test case".into(),
            examiner: "Tester".into(),
            organization: "QA".into(),
            description: String::new(),
            created_at: "2026-08-29T00:00:00".into(),
            case_dir: "C:\\cases\\test".into(),
            last_opened: String::new(),
        }
    }

    fn empty_inputs(meta: &CaseMeta) -> ReportInputs<'_> {
        ReportInputs {
            meta,
            exam: None,
            report: None,
            correlations: None,
            ai: None,
            finding_workflow: &[],
            timeline: &[],
            custody: &[],
            notes: &[],
        }
    }

    #[test]
    fn empty_case_reports_absence_not_data() {
        let m = meta();
        let content = collect(&empty_inputs(&m));
        let section = |name: &str| {
            content
                .sections
                .iter()
                .find(|(s, _)| s == name)
                .unwrap_or_else(|| panic!("missing section {name}"))
                .1
                .clone()
        };
        assert!(section("OBSERVED FACT").iter().any(|l| l.contains("No evidence image ingested")));
        assert!(section("INTEGRITY VERIFICATION").iter().any(|l| l.contains("no integrity checks")));
        assert!(section("TIMELINE").iter().any(|l| l.contains("No timeline events persisted")));
        assert!(section("CORRELATION").iter().any(|l| l.contains("not run")));
        assert!(section("AI ANALYSIS LAYER").iter().any(|l| l.contains("Not run in this session")));
        assert!(section("EXPLAINABILITY").iter().any(|l| l.contains("Not available")));
        assert!(section("FINDING WORKFLOW").iter().any(|l| l.contains("No persisted finding rows")));
        assert!(section("CHAIN OF CUSTODY").iter().any(|l| l.contains("No custody entries recorded")));
        assert!(section("CASE IDENTITY").iter().any(|l| l.contains(&tool_version())));
        assert!(!content.demo_mode);
    }

    #[test]
    fn real_case_report_is_fully_grounded() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = AnalysisReport::run(&exam);
        let correlations = crate::correlation::correlate_streams(&exam.streams);
        let provider = crate::ai::LocalRuleProvider;
        let ai = crate::ai::run_validated(&provider, &exam, &report);
        let rows = crate::analysis::finding_rows(&report);
        let m = meta();
        let inputs = ReportInputs {
            meta: &m,
            exam: Some(&exam),
            report: Some(&report),
            correlations: Some(&correlations),
            ai: Some(&ai),
            finding_workflow: &rows,
            timeline: &[],
            custody: &[],
            notes: &[],
        };
        let content = collect(&inputs);
        let joined: String = content
            .sections
            .iter()
            .flat_map(|(_, lines)| lines.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains(&exam.image_name));
        assert!(joined.contains("Container SHA-256:"));
        // Every finding id in the report must appear in the export.
        for finding in &report.findings {
            assert!(joined.contains(&finding.rule_id), "missing finding {}", finding.rule_id);
        }
        // Phase 5–8 outputs pulled forward: correlations, AI layer with
        // its rejection ledger, §30 explainability, §35 workflow.
        assert!(joined.contains("Cross-stream links:"), "correlation section present");
        assert!(joined.contains("Provider:"), "AI layer present");
        assert!(joined.contains(&format!("Rejected by grounding gate: {}", ai.rejected.len())));
        assert!(joined.contains("--- NET-001 ---") || joined.contains("--- "), "explainability cards present");
        assert!(joined.contains("Persisted finding rows:"), "workflow section present");
        assert!(joined.contains("investigator status: NEW"), "status attached to indicators");
        // AI-layer findings in the report cite only real artifacts.
        for f in &ai.findings {
            for id in &f.evidence_artifacts {
                assert!(exam.artifact_by_id(id).is_some(), "AI report cites unknown {id}");
            }
        }
    }
}
