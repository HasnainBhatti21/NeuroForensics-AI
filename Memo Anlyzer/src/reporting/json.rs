//! JSON forensic report for machine-readable exchange. Every section
//! maps to one evidence class; no invented fields. §43 content
//! contract: correlations, AI layer + rejection ledger, §30
//! explainability, §35 finding workflow and tool version are included.

use serde_json::json;

use super::{tool_version, ReportInputs};

/// Serialize the full case analysis into a structured JSON report.
pub fn generate(inputs: &ReportInputs) -> Result<String, String> {
    let evidence = inputs.exam.map(|e| {
        json!({
            "image": e.image_name,
            "path": e.image_path.display().to_string(),
            "size_bytes": e.size_bytes,
            "aif_format_version": e.case_doc.format_version,
            "case_id": e.case_id(),
            "demo_mode": e.is_demo(),
            "collector": {
                "name": e.manifest.collector.name,
                "version": e.manifest.collector.version,
                "platform": e.manifest.collector.platform,
            },
            "host": {
                "hostname": e.manifest.host.hostname,
                "os": e.manifest.host.os,
                "os_version": e.manifest.host.os_version,
                "architecture": e.manifest.host.architecture,
            },
            "acquisition": {
                "start_time": e.manifest.acquisition.start_time,
                "end_time": e.manifest.acquisition.end_time,
                "operator": e.manifest.acquisition.operator,
                "status": e.manifest.acquisition.status,
            },
            "integrity": {
                "container_sha256": e.container_check.calculated,
                "container_verified": e.container_check.ok,
                "expected_sha256": e.container_check.expected,
                "artifacts_checked": e.artifact_checks.len(),
                "artifacts_ok": e.artifact_checks.iter().filter(|c| c.ok).count(),
            },
            "artifacts": e.artifacts.iter().map(|a| json!({
                "artifact_id": a.artifact_id,
                "path": a.relative_path,
                "category": a.category,
                "size": a.size,
                "sha256": a.sha256,
                "acquisition_time": a.acquisition_time,
                "collector": a.collector,
                "status": a.status.label(),
                "synthetic": a.synthetic,
                "present_in_container": a.present,
                "hash_verified": a.hash_verified,
            })).collect::<Vec<_>>(),
            "warnings": e.warnings,
        })
    });

    let report_json = inputs.report.map(|r| {
        json!({
            "generated_at": r.generated_at,
            "verdict": r.verdict_label(),
            "integrity_problems": r.integrity_problems,
            "coverage": r.coverage,
            "analytical_indicator": {
                "evidence_class": "ANALYTICAL INDICATOR",
                "findings": r.findings,
            },
            "ml_anomaly": r.ml,
        })
    });

    // §23 correlation engine output.
    let correlation = inputs.correlations.map(|c| {
        json!({
            "links": c.links.iter().map(|l| json!({
                "kind": l.kind.label(),
                "a_artifact": l.a.artifact_id,
                "a_label": l.a.label,
                "b_artifact": l.b.artifact_id,
                "b_label": l.b.label,
                "matched_value": l.matched,
            })).collect::<Vec<_>>(),
            "activities": c.activities.iter().map(|a| json!({
                "pid": a.process_pid,
                "process": a.process_name,
                "process_artifact": a.process_artifact,
                "partners": a.partners,
                "kinds": a.kinds,
            })).collect::<Vec<_>>(),
        })
    });

    // §29/§32 AI layer with its grounding-gate rejection ledger.
    let ai_layer = inputs.ai.map(|ai| {
        json!({
            "provider": ai.provider.name,
            "mode": ai.provider.mode.label(),
            "description": ai.provider.description,
            "error": ai.error,
            "findings": ai.findings.iter().map(|f| json!({
                "title": f.title,
                "severity": f.severity.label(),
                "confidence": f.confidence,
                "method": f.method.label(),
                "evidence_artifacts": f.evidence_artifacts,
                "reasoning": f.reasoning,
                "limitations": f.limitations,
            })).collect::<Vec<_>>(),
            "rejected": ai.rejected.iter().map(|r| json!({
                "title": r.title,
                "reason": r.reason,
            })).collect::<Vec<_>>(),
        })
    });

    // §30 explainability cards.
    let explainability: Option<Vec<serde_json::Value>> = match (inputs.exam, inputs.report) {
        (Some(exam), Some(report)) => {
            let mut cards = Vec::new();
            for finding in &report.findings {
                let e = crate::analysis::xai::explain_finding(exam, finding);
                cards.push(json!({
                    "id": finding.rule_id,
                    "what": e.what,
                    "why_flagged": e.why_flagged,
                    "evidence": e.evidence,
                    "sources": e.sources,
                    "confidence_label": e.confidence_label,
                    "method_label": e.method_label,
                    "limitations": e.limitations,
                }));
            }
            for anomaly in &report.ml.anomalies {
                let e = crate::analysis::xai::explain_anomaly(exam, anomaly, &report.ml.model_id);
                cards.push(json!({
                    "id": format!("{} · pid {}", report.ml.model_id, anomaly.pid),
                    "what": e.what,
                    "why_flagged": e.why_flagged,
                    "evidence": e.evidence,
                    "sources": e.sources,
                    "confidence_label": e.confidence_label,
                    "method_label": e.method_label,
                    "limitations": e.limitations,
                }));
            }
            Some(cards)
        }
        _ => None,
    };

    // §35 persisted finding workflow (status + investigator notes).
    let finding_workflow = inputs
        .finding_workflow
        .iter()
        .map(|row| {
            json!({
                "finding_id": row.finding_id,
                "finding_key": row.finding_key,
                "severity": row.severity,
                "category": row.category,
                "confidence": row.confidence,
                "method": row.method,
                "title": row.title,
                "description": row.description,
                "reasoning": row.reasoning,
                "supporting_artifacts": row.supporting_artifacts,
                "run_at": row.run_at,
                "status": row.status.label(),
                "investigator_note": row.investigator_note,
            })
        })
        .collect::<Vec<_>>();

    // §43 timeline.
    let timeline = inputs
        .timeline
        .iter()
        .map(|ev| {
            json!({
                "ts": ev.ts,
                "category": ev.category,
                "label": ev.label,
                "detail": ev.detail,
                "artifact_id": ev.artifact_id,
            })
        })
        .collect::<Vec<_>>();

    // §41 append-only chain-of-custody trail.
    let chain_of_custody = inputs
        .custody
        .iter()
        .map(|e| {
            json!({
                "ts": e.ts,
                "examiner": e.examiner,
                "operation": e.operation,
                "detail": e.detail,
            })
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "tool": tool_version(),
        "report_version": 4,
        "generated_at": chrono::Local::now().to_rfc3339(),
        "case": {
            "number": inputs.meta.case_number,
            "name": inputs.meta.case_name,
            "examiner": inputs.meta.examiner,
            "organization": inputs.meta.organization,
            "description": inputs.meta.description,
            "created_at": inputs.meta.created_at,
            "case_dir": inputs.meta.case_dir,
        },
        "evidence": evidence,
        "timeline": timeline,
        "analysis": report_json,
        "correlation": correlation,
        "ai_layer": ai_layer,
        "explainability": explainability,
        "finding_workflow": finding_workflow,
        "chain_of_custody": chain_of_custody,
        "investigator_interpretation": {
            "notes": inputs.notes.iter().map(|n| json!({
                "created_at": n.created_at,
                "artifact_id": n.artifact_id,
                "text": n.text,
            })).collect::<Vec<_>>(),
        },
        "statement": "All data in this report derives from the case database and the ingested AIF evidence image. Nothing was generated or simulated.",
    });

    serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casemgmt::db::CaseMeta;

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

    #[test]
    fn empty_case_is_valid_json_with_null_sections() {
        let m = meta();
        let inputs = ReportInputs {
            meta: &m,
            exam: None,
            report: None,
            correlations: None,
            ai: None,
            finding_workflow: &[],
            timeline: &[],
            custody: &[],
            notes: &[],
        };
        let text = generate(&inputs).expect("report generates");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert!(value["evidence"].is_null());
        assert!(value["analysis"].is_null());
        assert!(value["correlation"].is_null());
        assert!(value["ai_layer"].is_null());
        assert!(value["explainability"].is_null());
        assert_eq!(value["chain_of_custody"].as_array().unwrap().len(), 0);
        assert_eq!(value["case"]["number"], serde_json::json!("CASE-TEST-001"));
        assert_eq!(value["report_version"], serde_json::json!(4));
        assert!(value["tool"].as_str().unwrap().contains("NEUROFORENSICS AI"));
    }

    #[test]
    fn real_case_report_lists_every_artifact_and_phase_outputs() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = crate::analysis::AnalysisReport::run(&exam);
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
        let text = generate(&inputs).expect("report generates");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        let artifacts = value["evidence"]["artifacts"].as_array().expect("artifacts array");
        assert_eq!(artifacts.len(), exam.artifacts.len());
        assert!(value["analysis"]["verdict"].as_str().is_some());
        // Phase 5–8 outputs present and complete.
        assert_eq!(
            value["correlation"]["links"].as_array().unwrap().len(),
            correlations.links.len()
        );
        assert_eq!(value["ai_layer"]["findings"].as_array().unwrap().len(), ai.findings.len());
        assert_eq!(value["ai_layer"]["rejected"].as_array().unwrap().len(), ai.rejected.len());
        assert_eq!(
            value["explainability"].as_array().unwrap().len(),
            report.findings.len() + report.ml.anomalies.len()
        );
        assert_eq!(value["finding_workflow"].as_array().unwrap().len(), rows.len());
        for row in value["finding_workflow"].as_array().unwrap() {
            assert_eq!(row["status"], serde_json::json!("NEW"), "fresh rows are never auto-confirmed");
        }
    }
}
