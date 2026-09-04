//! AI investigator assistant — answers strictly from the OPEN case (§31).
//!
//! Local / offline and deterministic: summaries of indexed evidence,
//! findings and ML status. Every claim references verifiable collector
//! artifact IDs (`ART-xxxxxx`). Answers are assembled from claim
//! units and pass the SAME grounding gate the AI analysis layer uses:
//! a claim citing artifact IDs that do not resolve in the case index
//! is dropped and recorded — a free-form question is just another
//! attack surface for an ungrounded claim. Absent evidence answers
//! "Not present in evidence"; nothing is ever fabricated.

use serde::Serialize;

use crate::ingest::ExaminedCase;

use super::rules::Finding;
use super::{xai, AnalysisReport};

#[derive(Clone, Debug, Serialize)]
pub struct AssistantAnswer {
    pub text: String,
    /// Artifact IDs the answer is grounded on (verified against the index).
    pub references: Vec<String>,
    /// Accurate runtime label (§31): the chat engine is always local;
    /// when an external analysis endpoint is configured, that is said
    /// as well — never imply offline if it isn't.
    pub mode: String,
    /// Claims the grounding gate dropped (audit trail, shown in UI).
    pub dropped_claims: Vec<DroppedClaim>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DroppedClaim {
    pub claim: String,
    pub reason: String,
}

/// One factual unit of an answer. `refs` empty = statement about
/// absence/limits that needs no artifact backing.
#[derive(Clone, Debug)]
pub struct Claim {
    pub text: String,
    pub refs: Vec<String>,
}

impl Claim {
    fn plain(text: String) -> Claim {
        Claim { text, refs: Vec::new() }
    }
    fn grounded(text: String, refs: Vec<String>) -> Claim {
        Claim { text, refs }
    }
}

/// Chat-side mirror of `ai::validate_raw`: claims whose cited IDs do
/// not resolve are dropped with a reason; unknown IDs are stripped
/// from surviving claims. Testable against any resolver.
pub fn ground_claims(
    claims: Vec<Claim>,
    exists: impl Fn(&str) -> bool,
) -> (Vec<String>, Vec<String>, Vec<DroppedClaim>) {
    let mut lines = Vec::new();
    let mut refs_all = Vec::new();
    let mut dropped = Vec::new();

    for claim in claims {
        if claim.refs.is_empty() {
            lines.push(claim.text);
            continue;
        }
        let (known, unknown): (Vec<String>, Vec<String>) =
            claim.refs.into_iter().partition(|id| exists(id));
        if known.is_empty() {
            dropped.push(DroppedClaim {
                claim: claim.text,
                reason: format!(
                    "cited {}, none of which exist in this case — dropped per the no-fabrication rule",
                    unknown.join(", ")
                ),
            });
            continue;
        }
        for id in &known {
            if !refs_all.contains(id) {
                refs_all.push(id.clone());
            }
        }
        lines.push(claim.text);
    }

    refs_all.sort();
    (lines, refs_all, dropped)
}

/// Accurate §31 mode label for the panel and each answer stamp.
pub fn mode_label(external_ai_configured: bool) -> String {
    if external_ai_configured {
        "LOCAL ANSWERS · EXTERNAL AI ANALYSIS LAYER CONFIGURED".into()
    } else {
        "LOCAL / OFFLINE".into()
    }
}

pub fn answer(
    exam: &ExaminedCase,
    report: &AnalysisReport,
    question: &str,
    external_ai_configured: bool,
) -> AssistantAnswer {
    let q = question.to_ascii_lowercase();
    let mentions = |words: &[&str]| words.iter().any(|w| q.contains(w));

    // §31 intent order: most specific first.
    let claims = if let Some(ids) = extract_artifact_ids(question) {
        explain_artifact_claims(exam, report, &ids)
    } else if mentions(&["unsigned", "signature", "signed process"]) {
        unsigned_processes_claims(exam)
    } else if mentions(&["most suspicious", "top finding", "biggest risk", "worst"]) {
        most_suspicious_claims(exam, report)
    } else if (mentions(&["flagged", "flag"]) || mentions(&["suspicious"]))
        && mentions(&["network", "connection", "socket"])
    {
        flagged_network_claims(exam, report)
    } else if mentions(&["finding", "indicator", "suspicious", "alert", "detect", "risk"]) {
        findings_overview_claims(report)
    } else if mentions(&["ml", "anomaly", "isolation", "model", "score"]) {
        ml_claims(report)
    } else if mentions(&["network", "connection", "dns", "port", "c2", "remote"]) {
        network_overview_claims(exam)
    } else if mentions(&["persistence", "run key", "startup", "service", "registry"]) {
        persistence_overview_claims(exam)
    } else if mentions(&["event", "security log", "application log", "system log"]) {
        events_overview_claims(exam)
    } else if mentions(&["process", "pid", "cpu"]) {
        process_overview_claims(exam)
    } else if mentions(&["memory", "ram"]) {
        memory_claims(exam)
    } else if mentions(&["integrity", "hash", "sha", "verif"]) {
        integrity_claims(exam)
    } else {
        generic_lookup_claims(exam, report, &q)
    };

    // The grounding gate: every factual claim with artifact backing is
    // checked against the real index before the examiner sees it.
    let (mut lines, refs, dropped) = ground_claims(claims, |id| exam.artifact_by_id(id).is_some());

    if exam.is_demo() {
        lines.push("NOTE: this evidence image was flagged as DEMO/synthetic by the collector.".into());
    }
    lines.push("All statements above are derived exclusively from artifacts indexed in the opened AIF evidence image; nothing was inferred beyond the recorded data.".into());

    AssistantAnswer {
        text: lines.join("\n"),
        references: refs,
        mode: mode_label(external_ai_configured),
        dropped_claims: dropped,
    }
}

/// Extract `ART-xxxxxx` tokens from a free-form question.
fn extract_artifact_ids(question: &str) -> Option<Vec<String>> {
    let re = regex::Regex::new(r"(?i)\bART-[0-9]+\b").ok()?;
    let mut ids: Vec<String> = re
        .find_iter(question)
        .map(|m| m.as_str().to_ascii_uppercase())
        .collect();
    if ids.is_empty() {
        return None;
    }
    ids.sort();
    ids.dedup();
    Some(ids)
}

// ---------------------------------------------------------------------
// §31 intents
// ---------------------------------------------------------------------

/// "Explain why <artifact> was flagged" — §30 card per citing finding,
/// honest absence when nothing references the artifact, explicit
/// rejection of IDs that aren't indexed at all.
fn explain_artifact_claims(exam: &ExaminedCase, report: &AnalysisReport, ids: &[String]) -> Vec<Claim> {
    let mut claims = Vec::new();
    for id in ids {
        let Some(artifact) = exam.artifact_by_id(id) else {
            claims.push(Claim::plain(format!(
                "{id} is not in this case's artifact index — I only reference artifacts the collector actually indexed."
            )));
            continue;
        };
        let citing: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.supporting_artifacts.iter().any(|a| a == id))
            .collect();
        if citing.is_empty() {
            claims.push(Claim::grounded(
                format!(
                    "{id} [{}] {} — no analytical indicator references this artifact. This is an absence statement, not a clearance.",
                    artifact.category, artifact.relative_path
                ),
                vec![id.clone()],
            ));
            continue;
        }
        claims.push(Claim::grounded(
            format!("{id} is cited by {} indicator(s):", citing.len()),
            vec![id.clone()],
        ));
        for finding in citing {
            claims.push(Claim::grounded(
                xai::explain_finding(exam, finding).render(),
                finding.supporting_artifacts.clone(),
            ));
        }
    }
    claims
}

/// "List unsigned processes" — the AIF contract carries no signature
/// data, so the honest answer is absence, never a guess.
fn unsigned_processes_claims(exam: &ExaminedCase) -> Vec<Claim> {
    let mut claims = vec![Claim::plain(
        "Not present in evidence — this case's AIF records no code-signing information for \
         processes, so I cannot list unsigned processes without inventing data."
            .into(),
    )];
    if let Some(ps) = &exam.streams.processes {
        if let Some(a) = &ps.list_artifact {
            claims.push(Claim::grounded(
                format!(
                    "What IS recorded: {} process(es) in {} — ask about findings to see location-based and masquerading indicators instead.",
                    ps.processes.len(),
                    a
                ),
                vec![a.clone()],
            ));
        }
    }
    claims
}

/// "What's the most suspicious thing in this case" — rank by severity
/// then confidence, explain the top indicator with a §30 card.
fn most_suspicious_claims(exam: &ExaminedCase, report: &AnalysisReport) -> Vec<Claim> {
    if report.findings.is_empty() {
        return vec![Claim::plain(
            "No indicators exist for this case — the rule engine and ML scoring ran over all \
             decoded evidence streams and observed nothing to rank."
                .into(),
        )];
    }
    let mut ranked: Vec<&Finding> = report.findings.iter().collect();
    ranked.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.confidence.unwrap_or(0.0).partial_cmp(&a.confidence.unwrap_or(0.0)).unwrap())
    });
    let top = ranked[0];
    let mut claims = vec![Claim::plain(format!(
        "Most suspicious indicator (highest severity, then confidence) out of {} total:",
        report.findings.len()
    ))];
    claims.push(Claim::grounded(
        xai::explain_finding(exam, top).render(),
        top.supporting_artifacts.clone(),
    ));
    claims.push(Claim::plain(
        "All findings are POTENTIAL indicators, not confirmations.".into(),
    ));
    claims
}

/// "Show me all flagged network connections" — only what the rules
/// actually flagged; explicit honesty when nothing was flagged.
fn flagged_network_claims(exam: &ExaminedCase, report: &AnalysisReport) -> Vec<Claim> {
    let net_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.rule_id.starts_with("NET-"))
        .collect();
    if net_findings.is_empty() {
        return match &exam.streams.network {
            Some(net) => vec![Claim::grounded(
                format!(
                    "Nothing in this case matches that — {} network connection(s) were examined and none were flagged by the rules.",
                    net.connections.len()
                ),
                net.connections_artifact.iter().cloned().collect(),
            )],
            None => vec![Claim::plain(
                "Not present in evidence — no network artifacts were recorded by the collector.".into(),
            )],
        };
    }
    let mut claims = vec![Claim::plain(format!("{} flagged network indicator(s):", net_findings.len()))];
    for finding in net_findings {
        claims.push(Claim::grounded(
            xai::explain_finding(exam, finding).render(),
            finding.supporting_artifacts.clone(),
        ));
    }
    claims
}

// ---------------------------------------------------------------------
// Overview branches (unchanged behavior, now claim-based)
// ---------------------------------------------------------------------

fn findings_overview_claims(report: &AnalysisReport) -> Vec<Claim> {
    if report.findings.is_empty() {
        return vec![Claim::plain(
            "No findings exist for this case. The rule engine and ML scoring ran over all decoded evidence streams and observed no indicators.".into(),
        )];
    }
    let mut claims = vec![Claim::plain(format!(
        "{} finding(s) produced by deterministic rules + local ML:",
        report.findings.len()
    ))];
    for finding in report.findings.iter().take(8) {
        claims.push(Claim::grounded(finding_line(finding), finding.supporting_artifacts.clone()));
    }
    claims.push(Claim::plain("All findings are POTENTIAL indicators, not confirmations.".into()));
    claims
}

fn ml_claims(report: &AnalysisReport) -> Vec<Claim> {
    let ml = &report.ml;
    match ml.status {
        super::ml::MlStatus::Completed => {
            let mut claims = vec![Claim::plain(format!(
                "Model {} COMPLETED — {} process sample(s) scored; {} anomaly(ies) above threshold.",
                ml.model_id,
                ml.samples_used,
                ml.anomalies.len()
            ))];
            for anomaly in &ml.anomalies {
                claims.push(Claim::grounded(
                    format!(
                        "• pid {} ({}) score {:.3} — dominant features: {}",
                        anomaly.pid,
                        anomaly.process_name,
                        anomaly.score,
                        anomaly.dominant_features.join(", ")
                    ),
                    anomaly.supporting_artifact.iter().cloned().collect(),
                ));
            }
            claims.push(Claim::plain(
                "ML anomalies are statistical observations, not confirmations.".into(),
            ));
            claims
        }
        super::ml::MlStatus::InsufficientData => vec![Claim::plain(format!(
            "Model {} reports INSUFFICIENT DATA: only {} process sample(s) available (minimum 10 required). No anomalies are produced rather than inventing them.",
            ml.model_id, ml.samples_used
        ))],
        super::ml::MlStatus::NotAvailable => vec![Claim::plain(format!(
            "Model {} — not available for this case: no process evidence was recorded by the collector.",
            ml.model_id
        ))],
    }
}

fn network_overview_claims(exam: &ExaminedCase) -> Vec<Claim> {
    match &exam.streams.network {
        Some(net) => {
            let mut claims = vec![Claim::plain(format!(
                "{} network connection(s) and {} DNS adapter(s) recorded.",
                net.connections.len(),
                net.dns_adapters.len()
            ))];
            for conn in net.connections.iter().take(8) {
                claims.push(Claim::plain(format!(
                    "• {} {} → {}:{} ({}), pid {} '{}'",
                    conn.protocol, conn.local_address, conn.remote_address, conn.remote_port, conn.state, conn.pid, conn.process
                )));
            }
            if let Some(a) = &net.connections_artifact {
                claims.push(Claim::grounded(format!("Recorded in {a}."), vec![a.clone()]));
            }
            claims
        }
        None => vec![Claim::plain(
            "Not present in evidence — no network artifacts were recorded by the collector.".into(),
        )],
    }
}

fn persistence_overview_claims(exam: &ExaminedCase) -> Vec<Claim> {
    match &exam.streams.persistence {
        Some(persist) => {
            let mut claims = vec![Claim::plain(format!(
                "{} run key(s) and {} service(s) recorded.",
                persist.run_keys.len(),
                persist.services.len()
            ))];
            for key in persist.run_keys.iter().take(6) {
                claims.push(Claim::plain(format!(
                    "• {}\\{} — {} value(s)",
                    key.hive,
                    key.key_path,
                    key.values.len()
                )));
            }
            for a in persist.run_keys_artifact.iter().chain(persist.services_artifact.iter()) {
                claims.push(Claim::grounded(format!("Recorded in {a}."), vec![a.clone()]));
            }
            claims
        }
        None => vec![Claim::plain(
            "Not present in evidence — no persistence artifacts were recorded by the collector.".into(),
        )],
    }
}

fn events_overview_claims(exam: &ExaminedCase) -> Vec<Claim> {
    match &exam.streams.events {
        Some(events) => {
            let mut claims = vec![Claim::plain(format!(
                "{} Windows event(s) across {} channel(s):",
                events.total_events,
                events.channels.len()
            ))];
            for channel in &events.channels {
                let text = format!("• {} — {} event(s)", channel.label, channel.event_count);
                match &channel.artifact_id {
                    Some(a) => claims.push(Claim::grounded(text, vec![a.clone()])),
                    None => claims.push(Claim::plain(text)),
                }
            }
            claims
        }
        None => vec![Claim::plain(
            "Not present in evidence — no Windows event artifacts were recorded by the collector.".into(),
        )],
    }
}

fn process_overview_claims(exam: &ExaminedCase) -> Vec<Claim> {
    match &exam.streams.processes {
        Some(ps) if !ps.processes.is_empty() => {
            let mut claims = vec![Claim::plain(format!("{} process(es) recorded:", ps.processes.len()))];
            for p in ps.processes.iter().take(10) {
                claims.push(Claim::plain(format!(
                    "• pid {} {} — user {}",
                    p.pid,
                    p.name,
                    p.user.as_deref().unwrap_or("?")
                )));
            }
            if let Some(a) = &ps.list_artifact {
                claims.push(Claim::grounded(format!("Recorded in {a}."), vec![a.clone()]));
            }
            claims
        }
        _ => vec![Claim::plain(
            "Not present in evidence — no process artifacts were recorded by the collector.".into(),
        )],
    }
}

fn memory_claims(exam: &ExaminedCase) -> Vec<Claim> {
    if exam.streams.memory_present {
        vec![Claim::plain(
            "Memory / RAM evidence is present in this case (see the Memory node in the evidence tree).".into(),
        )]
    } else {
        vec![Claim::plain(
            "Not present in evidence — the collector did not acquire a memory image for this case.".into(),
        )]
    }
}

fn integrity_claims(exam: &ExaminedCase) -> Vec<Claim> {
    let verified = exam.artifacts.iter().filter(|a| a.hash_verified == Some(true)).count();
    let text = format!(
        "Integrity: container SHA-256 {} — {} of {} artifact(s) re-hash verified OK. Container hash: {}.",
        match exam.container_check.ok {
            Some(true) => "VERIFIED against external sidecar",
            Some(false) => "MISMATCH — container may have been altered",
            None => "NOT VERIFIABLE — no external sidecar found",
        },
        verified,
        exam.artifacts.len(),
        exam.aif.container_sha256
    );
    let refs: Vec<String> = exam.artifacts.iter().take(3).map(|a| a.artifact_id.clone()).collect();
    vec![Claim::grounded(text, refs)]
}

fn generic_lookup_claims(exam: &ExaminedCase, report: &AnalysisReport, q: &str) -> Vec<Claim> {
    let tokens: Vec<&str> = q.split_whitespace().filter(|w| w.len() >= 3).collect();
    let hits: Vec<&crate::ingest::index::IndexedArtifact> = exam
        .artifacts
        .iter()
        .filter(|a| {
            let path_lower = a.relative_path.to_ascii_lowercase();
            tokens.iter().any(|t| path_lower.contains(t))
        })
        .take(8)
        .collect();
    if hits.is_empty() {
        return vec![Claim::plain(format!(
            "Case {} contains {} indexed artifact(s) and {} finding(s). I could not match your question to specific evidence — try asking about findings, ML anomalies, processes, network, persistence, events, memory or integrity.",
            exam.case_id(),
            exam.artifacts.len(),
            report.findings.len()
        ))];
    }
    let mut claims = vec![Claim::plain(format!("{} matching artifact(s):", hits.len()))];
    for hit in hits {
        claims.push(Claim::grounded(
            format!(
                "• {} [{}] {} ({} bytes)",
                hit.artifact_id, hit.category, hit.relative_path, hit.size
            ),
            vec![hit.artifact_id.clone()],
        ));
    }
    claims
}

fn finding_line(finding: &Finding) -> String {
    let grounded = if finding.supporting_artifacts.is_empty() {
        "stream-level evidence".to_string()
    } else {
        finding.supporting_artifacts.join(", ")
    };
    format!(
        "• [{}] {} — {} ({}, {} · {}) — grounded on: {}",
        finding.rule_id,
        finding.severity.label(),
        finding.title,
        finding.evidence_class,
        finding.method.label(),
        finding.confidence_label(),
        grounded
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::ExaminedCase;

    #[cfg(test)]
    fn real_exam() -> Option<ExaminedCase> {
        crate::ingest::tests::real_exam_if_available()
    }

    #[test]
    fn absent_evidence_is_reported_honestly() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        // Memory was not acquired in the reference case.
        let about_memory = answer(&exam, &report, "what does the memory image contain?", false);
        assert!(about_memory.text.contains("Not present in evidence"));
        assert!(about_memory.references.iter().all(|r| exam.artifact_by_id(r).is_some()));
    }

    #[test]
    fn answers_are_grounded_on_real_artifact_ids() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        for question in ["what findings exist?", "describe the network activity", "process list please", "verify integrity"] {
            let ans = answer(&exam, &report, question, false);
            assert!(!ans.text.is_empty(), "empty answer for '{question}'");
            for reference in &ans.references {
                assert!(
                    exam.artifact_by_id(reference).is_some(),
                    "ungrounded reference {reference} for '{question}'"
                );
            }
        }
    }

    /// The gate itself: ungrounded claims are dropped and recorded,
    /// grounded claims survive, unknown IDs are stripped.
    #[test]
    fn chat_gate_drops_ungrounded_claims() {
        let known = ["ART-000001".to_string()];
        let claims = vec![
            Claim::grounded("bad claim".into(), vec!["ART-999999".into()]),
            Claim::grounded("good claim".into(), vec!["ART-000001".into()]),
            Claim::plain("absence statement".into()),
        ];
        let (lines, refs, dropped) = ground_claims(claims, |id| known.contains(&id.to_string()));
        assert_eq!(lines, vec!["good claim", "absence statement"]);
        assert_eq!(refs, vec!["ART-000001"]);
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].reason.contains("ART-999999"));
        assert!(dropped[0].reason.contains("no-fabrication"));
    }

    /// §31: "explain why <artifact>" — §30 card for flagged artifacts,
    /// honest absence for unflagged ones, explicit rejection of IDs
    /// outside the index.
    #[test]
    fn explain_artifact_intent_covers_all_three_paths() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);

        // Flagged artifact → §30 card with rule ID.
        let flagged = &report.findings[0];
        let id = &flagged.supporting_artifacts[0];
        let ans = answer(&exam, &report, &format!("explain why {id} was flagged"), false);
        assert!(ans.text.contains(&flagged.rule_id), "{}", ans.text);
        assert!(ans.text.contains("Supporting Evidence:"), "§30 card rendered");
        assert!(ans.references.contains(id));

        // Indexed but unflagged artifact → absence statement.
        let flagged_ids: Vec<&str> = report
            .findings
            .iter()
            .flat_map(|f| f.supporting_artifacts.iter().map(|s| s.as_str()))
            .collect();
        if let Some(quiet) = exam.artifacts.iter().find(|a| !flagged_ids.contains(&a.artifact_id.as_str())) {
            let ans = answer(&exam, &report, &format!("why was {} flagged?", quiet.artifact_id), false);
            assert!(ans.text.contains("no analytical indicator"), "{}", ans.text);
        }

        // Unknown artifact → explicit rejection, never a fabricated answer.
        let ans = answer(&exam, &report, "explain why ART-999999 was flagged", false);
        assert!(ans.text.contains("not in this case's artifact index"), "{}", ans.text);
        assert!(!ans.references.contains(&"ART-999999".to_string()));
    }

    /// §31: "most suspicious" ranks and explains the top indicator.
    #[test]
    fn most_suspicious_intent_ranks_top_finding() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        let ans = answer(&exam, &report, "what's the most suspicious thing in this case?", false);
        assert!(ans.text.contains("Most suspicious indicator"), "{}", ans.text);
        // The top finding is the first after the rules' severity sort.
        assert!(ans.text.contains(&report.findings[0].rule_id), "{}", ans.text);
        assert!(ans.dropped_claims.is_empty());
    }

    /// §31: flagged-network intent is honest in both branches.
    #[test]
    fn flagged_network_intent_is_honest() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        let ans = answer(&exam, &report, "show me all flagged network connections", false);
        let has_net_findings = report.findings.iter().any(|f| f.rule_id.starts_with("NET-"));
        if has_net_findings {
            assert!(ans.text.contains("flagged network indicator(s)"), "{}", ans.text);
        } else {
            assert!(
                ans.text.contains("none were flagged") || ans.text.contains("Not present in evidence"),
                "{}",
                ans.text
            );
        }
        for r in &ans.references {
            assert!(exam.artifact_by_id(r).is_some());
        }
    }

    /// §31: "list unsigned processes" — signature data is absent from
    /// the AIF contract, so the answer says so instead of guessing.
    #[test]
    fn unsigned_processes_is_honest_absence() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        let ans = answer(&exam, &report, "list unsigned processes", false);
        assert!(ans.text.contains("no code-signing information"), "{}", ans.text);
        assert!(ans.text.contains("without inventing data"), "{}", ans.text);
        assert!(ans.dropped_claims.is_empty());
    }

    /// Phase-7-style zero-drop contract: across the required §31
    /// question set on the real case, the gate drops NOTHING — the
    /// assistant never attempts an ungrounded claim.
    #[test]
    fn real_case_chat_drops_zero_claims() {
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        let questions = [
            "what's the most suspicious thing in this case?",
            "show me all flagged network connections",
            "list unsigned processes",
            "what findings exist?",
            "describe the network activity",
            "any ML anomalies?",
            "verify integrity",
        ];
        for q in questions {
            let ans = answer(&exam, &report, q, false);
            assert!(ans.dropped_claims.is_empty(), "'{q}' dropped {:?}", ans.dropped_claims);
            for r in &ans.references {
                assert!(exam.artifact_by_id(r).is_some(), "'{q}' ungrounded {r}");
            }
        }
    }

    /// §31 mode transparency: local by default; external configuration
    /// is stated plainly, never implied away.
    #[test]
    fn mode_label_tracks_configuration() {
        assert_eq!(mode_label(false), "LOCAL / OFFLINE");
        assert!(mode_label(true).contains("EXTERNAL"));
        let Some(exam) = real_exam() else { return };
        let report = super::super::AnalysisReport::run(&exam);
        let local = answer(&exam, &report, "what findings exist?", false);
        assert_eq!(local.mode, "LOCAL / OFFLINE");
        let external = answer(&exam, &report, "what findings exist?", true);
        assert!(external.mode.contains("LOCAL ANSWERS"));
        assert!(external.mode.contains("EXTERNAL"));
    }
}
