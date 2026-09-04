//! Explainable AI (§30): every indicator explains itself.
//!
//! What was detected, why it was flagged, which artifacts support it,
//! what features contributed, confidence, and limitations — and every
//! explanation links back to real artifact IDs. Explanations are built
//! only from fields the engines actually recorded; nothing is added.

use crate::analysis::ml::MlAnomaly;
use crate::analysis::rules::Finding;
use crate::ingest::ExaminedCase;

/// Standard limitation statement for deterministic rule indicators.
pub const RULE_LIMITATION: &str = "Deterministic indicator — behavior consistent with the rule, \
                                   not proof of operator intent.";
/// Standard limitation statement for statistical ML anomalies.
pub const ML_LIMITATION: &str = "Statistical outlier within this case's process sample only — \
                                 not a detection by itself.";

/// §30 explanation card for one indicator.
#[derive(Clone, Debug, Default)]
pub struct Explanation {
    /// What was detected.
    pub what: String,
    /// Why it was flagged — the contributing signals.
    pub why_flagged: Vec<String>,
    /// Supporting artifact IDs (already grounded by the engines).
    pub evidence: Vec<String>,
    /// Evidence-source categories resolved from the case index.
    pub sources: Vec<String>,
    /// Confidence display — never invents a score.
    pub confidence_label: String,
    /// Detection-method label (§33).
    pub method_label: String,
    pub limitations: String,
}

impl Explanation {
    /// Plain-text §30 block (used by the chat panel and reports).
    pub fn render(&self) -> String {
        let mut lines = vec![self.what.clone()];
        for reason in &self.why_flagged {
            lines.push(format!("[✓] {reason}"));
        }
        lines.push(format!(
            "Supporting Evidence: {}",
            if self.evidence.is_empty() { "none".to_string() } else { self.evidence.join(", ") }
        ));
        if !self.sources.is_empty() {
            lines.push(format!("Evidence Sources: {}", self.sources.join(", ")));
        }
        lines.push(format!("Method: {} · {}", self.method_label, self.confidence_label));
        lines.push(format!("Limitations: {}", self.limitations));
        lines.join("\n")
    }
}

/// Resolve artifact IDs to their index categories (deduplicated,
/// index order). IDs not present in the index are skipped — an
/// explanation never cites a source it cannot verify.
pub fn evidence_sources(exam: &ExaminedCase, artifact_ids: &[String]) -> Vec<String> {
    let mut sources = Vec::new();
    for id in artifact_ids {
        if let Some(a) = exam.artifact_by_id(id) {
            if !sources.contains(&a.category.to_string()) {
                sources.push(a.category.to_string());
            }
        }
    }
    sources
}

/// §30 card for a deterministic rule finding.
pub fn explain_finding(exam: &ExaminedCase, finding: &Finding) -> Explanation {
    Explanation {
        what: format!("[{}] {}", finding.rule_id, finding.title),
        why_flagged: finding.indicators.clone(),
        evidence: finding.supporting_artifacts.clone(),
        sources: evidence_sources(exam, &finding.supporting_artifacts),
        confidence_label: finding.confidence_label(),
        method_label: finding.method.label().to_string(),
        limitations: RULE_LIMITATION.into(),
    }
}

/// §30 card for an isolation-forest anomaly. The anomaly score is a
/// feature, not a confidence — it is reported as-is and the card says
/// "confidence not recorded".
pub fn explain_anomaly(exam: &ExaminedCase, anomaly: &MlAnomaly, model_id: &str) -> Explanation {
    Explanation {
        what: format!(
            "[ML] POTENTIAL PROCESS ANOMALY — pid {} '{}'",
            anomaly.pid, anomaly.process_name
        ),
        why_flagged: vec![format!(
            "{model_id} anomaly score {:.3}; dominant features: {}",
            anomaly.score,
            anomaly.dominant_features.join(", ")
        )],
        evidence: anomaly.supporting_artifact.iter().cloned().collect(),
        sources: evidence_sources(exam, &anomaly.supporting_artifact.iter().cloned().collect::<Vec<_>>()),
        confidence_label: "confidence not recorded".into(),
        method_label: "ML".into(),
        limitations: ML_LIMITATION.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_case_explanations_link_back_to_indexed_artifacts() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = crate::analysis::AnalysisReport::run(&exam);
        assert!(!report.findings.is_empty(), "reference case has findings");
        for finding in &report.findings {
            let x = explain_finding(&exam, finding);
            assert!(!x.what.is_empty());
            assert!(!x.why_flagged.is_empty(), "{} explains why flagged", finding.rule_id);
            assert!(!x.evidence.is_empty(), "{} cites evidence", finding.rule_id);
            assert!(!x.sources.is_empty(), "{} resolves sources from index", finding.rule_id);
            assert!(!x.limitations.is_empty());
            let rendered = x.render();
            assert!(rendered.contains("Supporting Evidence:"));
            assert!(rendered.contains("Limitations:"));
            for id in &x.evidence {
                assert!(exam.artifact_by_id(id).is_some(), "explanation cites unknown {id}");
            }
        }
        for anomaly in &report.ml.anomalies {
            let x = explain_anomaly(&exam, anomaly, &report.ml.model_id);
            assert!(x.confidence_label.contains("not recorded"));
            assert_eq!(x.method_label, "ML");
        }
    }
}
