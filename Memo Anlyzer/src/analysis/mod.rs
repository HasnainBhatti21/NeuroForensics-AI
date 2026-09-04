//! Grounded analysis layer: deterministic rules + local ML + assistant,
//! all operating exclusively on artifacts decoded from the opened AIF
//! evidence image. No synthetic evidence is ever produced.

pub mod assistant;
pub mod ml;
pub mod rules;
pub mod xai;

use serde::{Deserialize, Serialize};

use crate::ingest::ExaminedCase;

/// Full analysis outcome for one evidence image run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub case_id: String,
    pub generated_at: String,
    pub findings: Vec<rules::Finding>,
    pub ml: ml::MlReport,
    /// Integrity failures detected during ingest (hash mismatch / missing).
    pub integrity_problems: usize,
    /// Â§27 honest coverage: categories the engine could not evaluate
    /// and why. Separate from findings so counts stay evidence-driven.
    #[serde(default)]
    pub coverage: Vec<rules::CoverageNote>,
}

impl AnalysisReport {
    /// Run rules + ML over the ingested case.
    pub fn run(exam: &ExaminedCase) -> AnalysisReport {
        AnalysisReport {
            case_id: exam.case_id().to_string(),
            generated_at: chrono::Local::now().to_rfc3339(),
            findings: rules::run_all(&exam.streams),
            ml: ml::run(&exam.streams),
            integrity_problems: exam.failed_verifications(),
            coverage: rules::coverage(&exam.streams),
        }
    }

    pub fn high_risk_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity >= rules::Severity::High)
            .count()
    }

    pub fn medium_risk_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == rules::Severity::Medium)
            .count()
    }

    /// Risk label for the toolbar: CLEAN until an indicator exists.
    pub fn verdict_label(&self) -> &'static str {
        if self.integrity_problems > 0 {
            "INTEGRITY WARNING"
        } else if self.high_risk_count() > 0 {
            "HIGH RISK INDICATORS"
        } else if self.medium_risk_count() > 0 {
            "MEDIUM RISK INDICATORS"
        } else if !self.findings.is_empty() {
            "LOW RISK INDICATORS"
        } else {
            "CLEAN â€” NO INDICATORS"
        }
    }

    /// Serialize for persistence in the case database.
    pub fn to_payload(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    pub fn from_payload(payload: &str) -> Result<AnalysisReport, String> {
        serde_json::from_str(payload).map_err(|e| e.to_string())
    }
}

/// Â§35 identity of one rule finding across re-runs: the rule plus its
/// grounding basis, so re-analyzing preserves investigator workflow.
pub fn finding_key(finding: &rules::Finding) -> String {
    let mut sorted = finding.supporting_artifacts.clone();
    sorted.sort();
    format!("{}|{}", finding.rule_id, sorted.join(","))
}

/// Â§35 persisted row key for the rule finding at position `seq` in
/// `report.findings` â€” matches the ordering used by [`finding_rows`],
/// so GUI and report lookups resolve the exact persisted row.
pub fn rule_row_key(finding: &rules::Finding, seq: usize) -> String {
    format!("{}|seq-{seq}", finding_key(finding))
}

/// Â§35 evidence category derived from the rule family prefix.
fn category_for_rule(rule_id: &str) -> &'static str {
    match rule_id.split('-').next().unwrap_or("") {
        "CRYPTO" => "CRYPTOGRAPHY / EXFILTRATION",
        "MAL" => "MALWARE INDICATORS",
        "NET" => "NETWORK",
        "PERSIST" => "PERSISTENCE",
        "EVT" => "WINDOWS EVENTS",
        "GPU" => "GPU ACTIVITY",
        _ => "BEHAVIOR",
    }
}

/// Â§35: map one analysis run to persistable finding rows (rule
/// findings + ML anomalies). Rows always enter with status NEW â€” the
/// database layer preserves any prior investigator status/note for a
/// surviving `finding_key`, and nothing ever auto-confirms.
pub fn finding_rows(report: &AnalysisReport) -> Vec<crate::casemgmt::db::FindingRow> {
    use crate::casemgmt::db::{FindingRow, FindingStatus};
    let mut rows = Vec::new();
    // seq suffix keeps keys unique when one rule fires multiple times
    // on identical grounding (e.g. several sockets of one listener);
    // ordering is deterministic for identical evidence.
    let mut seq = 0usize;
    for f in &report.findings {
        rows.push(FindingRow {
            finding_id: f.rule_id.clone(),
            finding_key: format!("{}|seq-{seq}", finding_key(f)),
            severity: f.severity.label().to_string(),
            category: category_for_rule(&f.rule_id).to_string(),
            confidence: f.confidence,
            method: f.method.label().to_string(),
            title: f.title.clone(),
            description: f.summary.clone(),
            reasoning: f.indicators.join("; "),
            supporting_artifacts: f.supporting_artifacts.clone(),
            run_at: report.generated_at.clone(),
            status: FindingStatus::New,
            investigator_note: String::new(),
        });
        seq += 1;
    }
    for a in &report.ml.anomalies {
        let artifacts: Vec<String> = a.supporting_artifact.clone().into_iter().collect();
        rows.push(FindingRow {
            finding_id: report.ml.model_id.clone(),
            finding_key: format!("{}|pid-{}|{}|seq-{seq}", report.ml.model_id, a.pid, artifacts.join(",")),
            severity: "LOW".to_string(),
            category: "PROCESS BEHAVIOR".to_string(),
            // Anomaly score is not detection confidence (Â§33).
            confidence: None,
            method: "ML".to_string(),
            title: format!("POTENTIAL INDICATOR â€” anomalous process {} (pid {})", a.process_name, a.pid),
            description: format!(
                "Statistical outlier (score {:.3}) within this case's process sample.",
                a.score
            ),
            reasoning: format!("Dominant features: {}", a.dominant_features.join(", ")),
            supporting_artifacts: artifacts,
            run_at: report.generated_at.clone(),
            status: FindingStatus::New,
            investigator_note: String::new(),
        });
        seq += 1;
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_case_is_clean() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = AnalysisReport::run(&exam);
        // Every finding must resolve to real artifact IDs in the index.
        for finding in &report.findings {
            for id in &finding.supporting_artifacts {
                assert!(
                    exam.artifact_by_id(id).is_some(),
                    "finding {} cites unknown artifact {id}",
                    finding.rule_id
                );
            }
        }
        let payload = report.to_payload().expect("serialize");
        let restored = AnalysisReport::from_payload(&payload).expect("deserialize");
        assert_eq!(restored.findings.len(), report.findings.len());
        // Phase 6 contract on real evidence: every finding carries a
        // confidence + method label; injection coverage speaks explicitly.
        for finding in &report.findings {
            let conf = finding.confidence.expect("current findings record confidence");
            assert!(conf > 0.0 && conf <= 1.0);
            assert!(!finding.method.label().is_empty());
        }
        let inj = report
            .coverage
            .iter()
            .find(|n| n.category.starts_with("PROCESS INJECTION"))
            .expect("injection coverage note present");
        assert!(inj.detail.to_ascii_lowercase().contains("not evaluated"));
    }

    #[test]
    fn finding_rows_cover_every_finding_and_stay_grounded() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = AnalysisReport::run(&exam);
        let rows = finding_rows(&report);
        assert_eq!(rows.len(), report.findings.len() + report.ml.anomalies.len());
        let mut keys: Vec<&str> = Vec::new();
        for row in &rows {
            // Â§35: rows enter NEW â€” never auto-confirmed.
            assert_eq!(row.status, crate::casemgmt::db::FindingStatus::New);
            assert!(!row.category.is_empty());
            for id in &row.supporting_artifacts {
                assert!(exam.artifact_by_id(id).is_some(), "row cites unknown artifact {id}");
            }
            keys.push(&row.finding_key);
        }
        // Identity is unique (re-run upsert can match exactly).
        let unique: std::collections::HashSet<&str> = keys.iter().copied().collect();
        assert_eq!(unique.len(), keys.len());
    }
}

