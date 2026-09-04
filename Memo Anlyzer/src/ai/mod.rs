//! AI provider abstraction (§29/§32/§33).
//!
//! Every provider — local or external — emits the SAME structured
//! finding shape (§29) and passes the SAME validation gate before it
//! reaches the examiner:
//!
//! * findings citing artifact IDs that do not exist in the open case
//!   are rejected and recorded — the no-fabrication rule applies to
//!   the AI layer exactly as it does to the rule engine;
//! * confidence is clamped to [0, 1], and a missing value stays
//!   "not recorded" rather than being invented;
//! * titles are forced into "POTENTIAL/SUSPECTED" wording (§22/§24);
//! * every finding carries a limitations statement (§30).
//!
//! The deterministic rule engine never depends on this layer: AI is an
//! enhancement, never a requirement (§32).

use serde::{Deserialize, Serialize};

use crate::analysis::rules::{DetectionMethod, Severity};
use crate::analysis::{ml, AnalysisReport};
use crate::appsettings::AppSettings;
use crate::ingest::ExaminedCase;

/// Environment variable holding the external provider API key. Keys
/// are read at call time only — never persisted, never logged (§47).
pub const API_KEY_ENV: &str = "NEUROFORENSICS_AI_API_KEY";
/// Optional model override for external providers.
pub const MODEL_ENV: &str = "NEUROFORENSICS_AI_MODEL";

/// How the active provider runs (§31: the UI must state this plainly).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderMode {
    LocalOffline,
    External,
}

impl ProviderMode {
    pub fn label(self) -> &'static str {
        match self {
            ProviderMode::LocalOffline => "LOCAL / OFFLINE",
            ProviderMode::External => "EXTERNAL ENDPOINT",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub mode: ProviderMode,
    pub description: String,
}

/// §29 structured AI finding — the only shape any provider may emit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiFinding {
    pub title: String,
    pub severity: Severity,
    /// None = the provider recorded no score — never invented.
    pub confidence: Option<f64>,
    /// Validated: only IDs that resolve in the open case survive.
    pub evidence_artifacts: Vec<String>,
    pub reasoning: String,
    pub limitations: String,
    pub method: DetectionMethod,
}

impl AiFinding {
    pub fn confidence_label(&self) -> String {
        match self.confidence {
            Some(c) => format!("confidence {c:.2}"),
            None => "confidence not recorded".into(),
        }
    }
}

/// A provider claim dropped by the validation gate, with the reason.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectedFinding {
    pub title: String,
    pub reason: String,
}

/// Outcome of one validated provider run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatedAnalysis {
    pub provider: ProviderInfo,
    /// Findings that survived grounding — every cited artifact ID
    /// resolves in the open case index.
    pub findings: Vec<AiFinding>,
    /// Claims dropped by the gate (shown, never hidden).
    pub rejected: Vec<RejectedFinding>,
    /// Honest failure statement when the provider itself errored.
    pub error: Option<String>,
}

/// §32 provider interface. Implementations return RAW output; the
/// validation gate is applied by the engine, never trusted to them.
pub trait AiProvider {
    fn info(&self) -> ProviderInfo;
    fn analyze(&self, exam: &ExaminedCase, report: &AnalysisReport) -> Result<Vec<AiFinding>, String>;
}

/// Run a provider and apply the grounding gate. Provider failure is
/// reported honestly; rule-based detection is unaffected (§32).
pub fn run_validated(provider: &dyn AiProvider, exam: &ExaminedCase, report: &AnalysisReport) -> ValidatedAnalysis {
    match provider.analyze(exam, report) {
        Ok(raw) => validate_against_case(exam, provider.info(), raw),
        Err(e) => ValidatedAnalysis {
            provider: provider.info(),
            findings: Vec::new(),
            rejected: Vec::new(),
            error: Some(format!(
                "{e} — deterministic rule detection ran independently (§32: AI is an enhancement layer)."
            )),
        },
    }
}

// ---------------------------------------------------------------------
// Validation gate — the no-fabrication rule for the AI layer
// ---------------------------------------------------------------------

/// Core gate, testable against any artifact-ID resolver.
pub fn validate_raw(provider: ProviderInfo, raw: Vec<AiFinding>, exists: impl Fn(&str) -> bool) -> ValidatedAnalysis {
    let mut findings = Vec::new();
    let mut rejected = Vec::new();

    for mut f in raw {
        let (known, unknown): (Vec<String>, Vec<String>) = f
            .evidence_artifacts
            .drain(..)
            .partition(|id| exists(id));

        if known.is_empty() {
            let cited = if unknown.is_empty() {
                "no artifact IDs".to_string()
            } else {
                unknown.join(", ")
            };
            rejected.push(RejectedFinding {
                title: f.title,
                reason: format!(
                    "cited {cited}, none of which exist in this case — dropped per the no-fabrication rule"
                ),
            });
            continue;
        }

        let mut grounded = known;
        grounded.sort();
        grounded.dedup();
        f.evidence_artifacts = grounded;
        if let Some(c) = f.confidence {
            f.confidence = Some(c.clamp(0.0, 1.0));
        }
        let up = f.title.to_ascii_uppercase();
        if !(up.starts_with("POTENTIAL") || up.starts_with("SUSPECTED")) {
            f.title = format!("POTENTIAL INDICATOR — {}", f.title);
        }
        if f.limitations.trim().is_empty() {
            f.limitations =
                "Analytical indicator, not a confirmation — the evidence shows behavior, not intent.".into();
        }
        findings.push(f);
    }

    ValidatedAnalysis { provider, findings, rejected, error: None }
}

/// Gate wired to the real case index.
pub fn validate_against_case(exam: &ExaminedCase, provider: ProviderInfo, raw: Vec<AiFinding>) -> ValidatedAnalysis {
    validate_raw(provider, raw, |id| exam.artifact_by_id(id).is_some())
}

// ---------------------------------------------------------------------
// LocalRuleProvider — offline, deterministic, always available (§33)
// ---------------------------------------------------------------------

pub struct LocalRuleProvider;

impl AiProvider for LocalRuleProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "LocalRuleProvider".into(),
            mode: ProviderMode::LocalOffline,
            description: "Deterministic rules + local isolation-forest ML over the open case. \
                          No external calls; fully offline."
                .into(),
        }
    }

    fn analyze(&self, _exam: &ExaminedCase, report: &AnalysisReport) -> Result<Vec<AiFinding>, String> {
        let mut out = Vec::new();

        // Rule findings re-presented in the §29 structured shape.
        for f in &report.findings {
            out.push(AiFinding {
                title: f.title.clone(),
                severity: f.severity,
                confidence: f.confidence,
                evidence_artifacts: f.supporting_artifacts.clone(),
                reasoning: format!("{} Why flagged: {}", f.summary, f.indicators.join("; ")),
                limitations: "Deterministic indicator — behavior consistent with the rule, \
                              not proof of operator intent."
                    .into(),
                method: f.method,
            });
        }

        // ML anomalies: reported with their real model identity and
        // without a fabricated confidence (an anomaly score is not a
        // detection confidence).
        if matches!(report.ml.status, ml::MlStatus::Completed) {
            for a in &report.ml.anomalies {
                out.push(AiFinding {
                    title: format!(
                        "POTENTIAL PROCESS ANOMALY — STATISTICAL OUTLIER (pid {} '{}')",
                        a.pid, a.process_name
                    ),
                    severity: Severity::Low,
                    confidence: None,
                    evidence_artifacts: a.supporting_artifact.iter().cloned().collect(),
                    reasoning: format!(
                        "Isolation-forest {} anomaly score {:.3}; dominant features: {}.",
                        report.ml.model_id,
                        a.score,
                        a.dominant_features.join(", ")
                    ),
                    limitations: "Statistical outlier within this case's process sample only — \
                                  not a detection by itself."
                        .into(),
                    method: DetectionMethod::Ml,
                });
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------
// EndpointProvider — OpenAI-compatible / Alibaba-compatible / custom
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointFlavor {
    OpenAiCompatible,
    AlibabaCompatible,
    CustomApi,
}

impl EndpointFlavor {
    pub fn label(self) -> &'static str {
        match self {
            EndpointFlavor::OpenAiCompatible => "OpenAI-compatible",
            EndpointFlavor::AlibabaCompatible => "Alibaba-compatible",
            // Selected explicitly via Settings for local/custom servers
            // whose URL does not match auto-detection; same chat JSON
            // contract, response may be a bare array or an envelope.
            EndpointFlavor::CustomApi => "Custom API",
        }
    }
    fn default_model(self) -> &'static str {
        match self {
            EndpointFlavor::OpenAiCompatible => "gpt-4o-mini",
            EndpointFlavor::AlibabaCompatible => "qwen-plus",
            EndpointFlavor::CustomApi => "local-model",
        }
    }
}

pub struct EndpointProvider {
    pub flavor: EndpointFlavor,
    pub endpoint: String,
    /// Optional fixed model; env override wins, flavor default is last.
    pub model: Option<String>,
}

impl EndpointProvider {
    fn resolved_model(&self) -> String {
        std::env::var(MODEL_ENV)
            .ok()
            .filter(|m| !m.trim().is_empty())
            .or_else(|| self.model.clone())
            .unwrap_or_else(|| self.flavor.default_model().to_string())
    }

    /// Keys live in the environment only — never persisted, never
    /// logged (§32/§47).
    pub fn resolve_api_key() -> Result<String, String> {
        std::env::var(API_KEY_ENV)
            .ok()
            .filter(|k| !k.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "no API key configured — set the {API_KEY_ENV} environment variable \
                     (keys are never stored or logged)"
                )
            })
    }
}

/// Contract given to external models — grounding, not creativity.
const SYSTEM_PROMPT: &str = "You are a forensic analysis assistant working on an indexed evidence \
container (AIF). You may ONLY reference artifact IDs listed in the evidence digest and ONLY state \
facts present in it; if evidence for a question is absent, say so. Never invent artifact IDs, \
processes, network endpoints or conclusions. Respond with a JSON array only, each element: \
{\"title\": string starting with POTENTIAL or SUSPECTED, \"severity\": LOW|MEDIUM|HIGH|CRITICAL, \
\"confidence\": number 0..1 or null, \"evidence\": [\"ART-xxxxxx\", ...], \"reasoning\": string, \
\"limitations\": string}. Findings without real artifact IDs from the digest are worthless.";

impl AiProvider for EndpointProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: format!("EndpointProvider ({})", self.flavor.label()),
            mode: ProviderMode::External,
            description: format!(
                "External {} chat endpoint at {} — every response passes the artifact-grounding \
                 gate before display.",
                self.flavor.label(),
                self.endpoint
            ),
        }
    }

    fn analyze(&self, exam: &ExaminedCase, report: &AnalysisReport) -> Result<Vec<AiFinding>, String> {
        let key = Self::resolve_api_key()?;

        let digest = evidence_digest(exam, report);
        let request = serde_json::json!({
            "model": self.resolved_model(),
            "temperature": 0.0,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": format!(
                    "Evidence digest for case {}:\n{digest}\n\nProduce structured findings per the contract.",
                    exam.case_id()
                ) },
            ],
        });

        let response = ureq::post(&self.endpoint)
            .set("Authorization", &format!("Bearer {key}"))
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(30))
            .send_json(request)
            .map_err(|e| format!("endpoint call to {} failed: {e}", self.endpoint))?;
        let body = response
            .into_string()
            .map_err(|e| format!("endpoint response could not be read: {e}"))?;

        let (mut findings, _) = parse_provider_response(&body)?;
        for f in &mut findings {
            f.method = DetectionMethod::LlmAi; // external output is LLM-AI (§33)
        }
        Ok(findings)
    }
}

/// Digest of REAL indexed evidence sent as provider input (§29):
/// artifact metadata, processes, network, persistence, events, GPU,
/// memory indicators and existing grounded findings.
pub fn evidence_digest(exam: &ExaminedCase, report: &AnalysisReport) -> serde_json::Value {
    use serde_json::json;

    let artifacts: Vec<serde_json::Value> = exam
        .artifacts
        .iter()
        .take(300)
        .map(|a| json!({ "artifact_id": a.artifact_id, "category": a.category, "path": a.relative_path }))
        .collect();

    let processes: Vec<serde_json::Value> = exam
        .streams
        .processes
        .as_ref()
        .map(|ps| {
            ps.processes
                .iter()
                .take(120)
                .map(|p| {
                    json!({
                        "pid": p.pid,
                        "name": p.name,
                        "path": p.executable_path,
                        "command_line": p.command_line,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let connections: Vec<serde_json::Value> = exam
        .streams
        .network
        .as_ref()
        .map(|n| {
            n.connections
                .iter()
                .take(120)
                .map(|c| {
                    json!({
                        "pid": c.pid,
                        "process": c.process,
                        "remote": format!("{}:{}", c.remote_address, c.remote_port),
                        "state": c.state,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let persistence: Vec<serde_json::Value> = exam
        .streams
        .persistence
        .as_ref()
        .map(|p| {
            p.run_keys
                .iter()
                .flat_map(|k| {
                    k.values.iter().take(40).map(move |v| {
                        json!({ "hive": k.hive, "key": k.key_path, "value": v.value_name, "data": v.data })
                    })
                })
                .take(120)
                .collect()
        })
        .unwrap_or_default();

    let events: Vec<serde_json::Value> = exam
        .streams
        .events
        .as_ref()
        .map(|e| {
            e.channels
                .iter()
                .map(|c| json!({ "channel": c.label, "events": c.event_count }))
                .collect()
        })
        .unwrap_or_default();

    let rule_findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| json!({ "rule_id": f.rule_id, "title": f.title, "artifacts": f.supporting_artifacts }))
        .collect();

    json!({
        "case_id": exam.case_id(),
        "artifact_index": artifacts,
        "processes": processes,
        "network_connections": connections,
        "persistence": persistence,
        "event_channels": events,
        "gpu": exam.streams.gpu.as_ref().map(|g| json!({
            "process_count": g.gpu_processes.as_ref().map(|d| d.processes.len()).unwrap_or(0),
            "note": g.gpu_processes.as_ref().and_then(|d| d.note.clone()),
        })),
        "memory_present": exam.streams.memory_present,
        "grounded_rule_findings": rule_findings,
    })
}

/// Parse an OpenAI-style (or bare-array) response body into raw
/// findings. Malformed entries become recorded rejects — never silent.
pub fn parse_provider_response(body: &str) -> Result<(Vec<AiFinding>, Vec<RejectedFinding>), String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("provider response was not valid JSON: {e}"))?;

    if value.is_array() {
        return parse_findings_array(&value);
    }
    let content = value
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|m| m.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| "response is neither a findings array nor an OpenAI-style envelope".to_string())?;

    let trimmed = strip_code_fence(content);
    let arr: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("model content was not valid JSON: {e}"))?;
    parse_findings_array(&arr)
}

fn strip_code_fence(s: &str) -> &str {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        let rest = rest.strip_prefix("json").unwrap_or(rest);
        if let Some(end) = rest.rfind("```") {
            return rest[..end].trim();
        }
    }
    t
}

#[derive(Deserialize)]
struct WireFinding {
    #[serde(default)]
    title: String,
    severity: Option<String>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default, alias = "evidence_artifacts", alias = "evidence", alias = "artifacts")]
    evidence: Vec<String>,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    limitations: String,
}

fn parse_findings_array(arr: &serde_json::Value) -> Result<(Vec<AiFinding>, Vec<RejectedFinding>), String> {
    let items = arr
        .as_array()
        .ok_or_else(|| "findings payload is not a JSON array".to_string())?;

    let mut findings = Vec::new();
    let mut rejected = Vec::new();
    for item in items {
        let wire: WireFinding = match serde_json::from_value(item.clone()) {
            Ok(w) => w,
            Err(e) => {
                rejected.push(RejectedFinding {
                    title: "(unparseable entry)".into(),
                    reason: format!("malformed finding entry dropped: {e}"),
                });
                continue;
            }
        };
        if wire.title.trim().is_empty() {
            rejected.push(RejectedFinding {
                title: "(untitled)".into(),
                reason: "finding had no title — dropped".into(),
            });
            continue;
        }
        let severity = match wire.severity.as_deref().map(parse_severity) {
            Some(Some(s)) => s,
            _ => {
                rejected.push(RejectedFinding {
                    title: wire.title,
                    reason: format!(
                        "severity '{}' is not LOW/MEDIUM/HIGH/CRITICAL — dropped rather than guessed",
                        wire.severity.as_deref().unwrap_or("(missing)")
                    ),
                });
                continue;
            }
        };
        findings.push(AiFinding {
            title: wire.title,
            severity,
            confidence: wire.confidence,
            evidence_artifacts: wire.evidence,
            reasoning: wire.reasoning,
            limitations: wire.limitations,
            method: DetectionMethod::LlmAi,
        });
    }
    Ok((findings, rejected))
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_uppercase().as_str() {
        "LOW" => Some(Severity::Low),
        "MEDIUM" => Some(Severity::Medium),
        "HIGH" => Some(Severity::High),
        "CRITICAL" => Some(Severity::Critical),
        _ => None,
    }
}

/// Endpoint protocol selection from persisted settings (§32). An
/// explicit choice in the Settings dialog wins; "auto" detects from
/// the endpoint URL.
pub fn flavor_for(settings: &AppSettings, endpoint: &str) -> EndpointFlavor {
    match settings.ai_flavor.trim().to_ascii_lowercase().as_str() {
        "openai" => EndpointFlavor::OpenAiCompatible,
        "alibaba" => EndpointFlavor::AlibabaCompatible,
        "custom" => EndpointFlavor::CustomApi,
        _ => {
            let lower = endpoint.to_ascii_lowercase();
            if lower.contains("dashscope") || lower.contains("aliyun") || lower.contains("alibaba") {
                EndpointFlavor::AlibabaCompatible
            } else {
                EndpointFlavor::OpenAiCompatible
            }
        }
    }
}

/// Provider selection from persisted settings (§32: configurable, not
/// hard-coded). Empty endpoint = local/offline.
pub fn from_settings(settings: &AppSettings) -> Box<dyn AiProvider> {
    let endpoint = settings.ai_endpoint.trim().to_string();
    if endpoint.is_empty() {
        return Box::new(LocalRuleProvider);
    }
    let flavor = flavor_for(settings, &endpoint);
    Box::new(EndpointProvider { flavor, endpoint, model: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_info() -> ProviderInfo {
        ProviderInfo {
            name: "TestProvider".into(),
            mode: ProviderMode::External,
            description: "test".into(),
        }
    }

    fn raw_finding(title: &str, ids: &[&str], confidence: Option<f64>) -> AiFinding {
        AiFinding {
            title: title.into(),
            severity: Severity::Medium,
            confidence,
            evidence_artifacts: ids.iter().map(|s| s.to_string()).collect(),
            reasoning: "test reasoning".into(),
            limitations: String::new(),
            method: DetectionMethod::LlmAi,
        }
    }

    /// The core no-fabrication gate: a finding citing only artifact
    /// IDs that don't exist in the case is rejected, never shown.
    #[test]
    fn validation_gate_rejects_fully_fabricated_evidence() {
        let known = ["ART-000001".to_string()];
        let out = validate_raw(
            provider_info(),
            vec![raw_finding("POTENTIAL X", &["ART-999999"], Some(0.9))],
            |id| known.contains(&id.to_string()),
        );
        assert!(out.findings.is_empty(), "fabricated finding must not survive");
        assert_eq!(out.rejected.len(), 1);
        assert!(out.rejected[0].reason.contains("ART-999999"));
        assert!(out.rejected[0].reason.contains("no-fabrication"));
    }

    /// Mixed citation: unknown IDs are stripped, the finding survives
    /// grounded on the real ID only.
    #[test]
    fn validation_gate_keeps_grounded_and_strips_unknown() {
        let known = ["ART-000001".to_string()];
        let out = validate_raw(
            provider_info(),
            vec![raw_finding("POTENTIAL X", &["ART-000001", "ART-777777"], Some(0.5))],
            |id| known.contains(&id.to_string()),
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].evidence_artifacts, vec!["ART-000001"]);
        assert!(out.rejected.is_empty());
    }

    /// Confidence clamping, §22 wording enforcement and mandatory
    /// limitations — applied to ANY provider output.
    #[test]
    fn validation_normalizes_confidence_wording_and_limitations() {
        let known = ["ART-000001".to_string()];
        let out = validate_raw(
            provider_info(),
            vec![
                raw_finding("Confirmed malware infection", &["ART-000001"], Some(1.7)),
                raw_finding("suspected beaconing", &["ART-000001"], None),
            ],
            |id| known.contains(&id.to_string()),
        );
        assert_eq!(out.findings.len(), 2);
        assert_eq!(out.findings[0].confidence, Some(1.0), "clamped, not dropped");
        assert!(out.findings[0].title.starts_with("POTENTIAL"), "{}", out.findings[0].title);
        assert!(!out.findings[0].limitations.is_empty(), "limitations filled");
        assert!(out.findings[1].title.to_ascii_uppercase().starts_with("SUSPECTED")
            || out.findings[1].title.starts_with("POTENTIAL"));
        assert_eq!(out.findings[1].confidence, None, "None stays 'not recorded'");
        assert!(out.findings[1].confidence_label().contains("not recorded"));
    }

    /// OpenAI-style envelope parsing, bare arrays, code fences and
    /// honest rejection of malformed entries.
    #[test]
    fn parse_provider_response_shapes() {
        let envelope = serde_json::json!({
            "choices": [{ "message": { "content": "```json\n[{\"title\":\"POTENTIAL MINER\",\
                \"severity\":\"high\",\"confidence\":0.91,\"evidence\":[\"ART-000001\"],\
                \"reasoning\":\"r\",\"limitations\":\"l\"}]```" } }]
        });
        let (findings, rejects) = parse_provider_response(&envelope.to_string()).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(rejects.is_empty());
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].method, DetectionMethod::LlmAi);

        // Malformed severity + missing title are recorded, not hidden.
        let mixed = r#"[{"title":"X","severity":"EXTREME","evidence":["ART-1"]},
                        {"severity":"LOW","evidence":["ART-1"]},
                        {"title":"POTENTIAL OK","severity":"LOW","evidence":["ART-1"]}]"#;
        let (findings, rejects) = parse_provider_response(mixed).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(rejects.len(), 2);
        assert!(rejects[0].reason.contains("EXTREME"));

        // Whole-body garbage is an honest error, not a panic.
        assert!(parse_provider_response("not json at all").is_err());
    }

    /// Endpoint provider without a key fails honestly BEFORE any
    /// network call; the message names the env var and embeds no key.
    #[test]
    fn endpoint_without_key_degrades_honestly() {
        // Ensure the env var is absent for this assertion.
        std::env::remove_var(API_KEY_ENV);
        let err = EndpointProvider::resolve_api_key().expect_err("no key must fail");
        assert!(err.contains(API_KEY_ENV), "{err}");
        assert!(err.contains("never stored or logged"));
        let provider = EndpointProvider {
            flavor: EndpointFlavor::OpenAiCompatible,
            endpoint: "https://example.invalid/v1/chat/completions".into(),
            model: None,
        };
        assert_eq!(provider.info().mode, ProviderMode::External);
    }

    /// Settings decide the provider: empty endpoint = local/offline.
    #[test]
    fn provider_selection_from_settings() {
        let mut settings = AppSettings::default();
        settings.ai_endpoint = String::new();
        assert_eq!(from_settings(&settings).info().mode, ProviderMode::LocalOffline);
        settings.ai_endpoint = "https://api.openai.example/v1/chat/completions".into();
        let p = from_settings(&settings);
        assert_eq!(p.info().mode, ProviderMode::External);
        assert!(p.info().name.contains("OpenAI-compatible"));
        settings.ai_endpoint = "https://dashscope.aliyuncs.example/compatible-mode/v1".into();
        assert!(from_settings(&settings).info().name.contains("Alibaba-compatible"));
        // Explicit protocol selection overrides URL auto-detection,
        // including the Custom API path (§32, wired via Settings).
        settings.ai_flavor = "custom".into();
        assert!(from_settings(&settings).info().name.contains("Custom API"));
        settings.ai_flavor = "openai".into();
        assert!(from_settings(&settings).info().name.contains("OpenAI-compatible"));
        settings.ai_flavor = "bogus".into(); // unknown falls back to auto
        assert!(from_settings(&settings).info().name.contains("Alibaba-compatible"));
    }

    /// Real case: the local provider's structured output is fully
    /// grounded — every cited artifact resolves in the case index.
    #[test]
    fn local_provider_output_is_fully_grounded_on_real_case() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = AnalysisReport::run(&exam);
        let outcome = run_validated(&LocalRuleProvider, &exam, &report);
        assert!(outcome.error.is_none());
        assert!(outcome.rejected.is_empty(), "local output must never be rejected");
        assert_eq!(outcome.findings.len(), report.findings.len() + report.ml.anomalies.len());
        for f in &outcome.findings {
            for id in &f.evidence_artifacts {
                assert!(exam.artifact_by_id(id).is_some(), "ungrounded {id}");
            }
            assert!(["RULE-BASED", "HEURISTIC", "ML", "LLM-AI"].contains(&f.method.label()));
            assert!(!f.limitations.is_empty());
        }
    }

    /// Real case end-to-end: digest only references indexed artifacts.
    #[test]
    fn digest_lists_only_indexed_artifacts() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = AnalysisReport::run(&exam);
        let digest = evidence_digest(&exam, &report);
        let ids = digest["artifact_index"].as_array().expect("artifact_index array");
        assert!(!ids.is_empty());
        for entry in ids {
            let id = entry["artifact_id"].as_str().unwrap();
            assert!(exam.artifact_by_id(id).is_some(), "digest cites unknown {id}");
        }
    }
}
