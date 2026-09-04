//! Deterministic detection rules running on REAL decoded evidence.
//!
//! Every finding cites the collector artifact ID(s) the conclusion was
//! drawn from (`ART-xxxxxx`). Streams absent from the evidence image
//! simply produce no rules — nothing is ever invented.

use serde::{Deserialize, Serialize};

use crate::ingest::streams::{ConnectionEntry, EventEntry, ProcessEntry, RunValue};
use crate::ingest::DecodedStreams;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Findings are analytical indicators, never confirmations.
pub const ANALYTICAL_INDICATOR: &str = "ANALYTICAL INDICATOR";

/// How a finding was produced (§33): deterministic rule, heuristic,
/// statistical ML model, or LLM reasoning. Heuristics must never be
/// presented as machine learning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    #[default]
    RuleBased,
    Heuristic,
    Ml,
    LlmAi,
}

impl DetectionMethod {
    pub fn label(self) -> &'static str {
        match self {
            DetectionMethod::RuleBased => "RULE-BASED",
            DetectionMethod::Heuristic => "HEURISTIC",
            DetectionMethod::Ml => "ML",
            DetectionMethod::LlmAi => "LLM-AI",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `CRYPTO-001`.
    pub rule_id: String,
    /// Always worded as a potential indicator.
    pub title: String,
    pub severity: Severity,
    pub summary: String,
    /// Collector artifact IDs (`ART-xxxxxx`) this finding is grounded on.
    pub supporting_artifacts: Vec<String>,
    /// Per-rule indicator accounting.
    pub indicators: Vec<String>,
    pub evidence_class: String,
    /// Process context where applicable.
    pub pid: Option<i64>,
    pub process_name: Option<String>,
    /// Exact evidence values this finding was triggered on. The
    /// Explorer highlights these bytes/fields in the Hex and Parsed
    /// View tabs (§20). Empty when the rule has no single value to pin.
    #[serde(default)]
    pub flagged_values: Vec<String>,
    /// Detection confidence in [0.0, 1.0] (§24/§29 audit gap, closed
    /// in Phase 6). `None` means "confidence not recorded" (legacy
    /// persisted payloads) — no sentinel value can be mistaken for a
    /// real score.
    #[serde(default)]
    pub confidence: Option<f64>,
    /// RULE-BASED / HEURISTIC / ML / LLM-AI label (§33).
    #[serde(default)]
    pub method: DetectionMethod,
}

impl Finding {
    fn new(
        rule_id: &str,
        title: &str,
        severity: Severity,
        summary: String,
        supporting: Vec<String>,
        indicators: Vec<String>,
        confidence: f64,
        method: DetectionMethod,
    ) -> Self {
        debug_assert!((0.0..=1.0).contains(&confidence), "confidence must stay within [0,1]");
        Finding {
            rule_id: rule_id.into(),
            title: title.into(),
            severity,
            summary,
            supporting_artifacts: supporting,
            indicators,
            evidence_class: ANALYTICAL_INDICATOR.into(),
            pid: None,
            process_name: None,
            flagged_values: Vec::new(),
            confidence: Some(confidence),
            method,
        }
    }

    /// Display form that never invents a score: legacy payloads with
    /// no recorded confidence say so explicitly.
    pub fn confidence_label(&self) -> String {
        match self.confidence {
            Some(c) => format!("confidence {c:.2}"),
            None => "confidence not recorded".into(),
        }
    }
}

/// §27-style honest coverage accounting: what the engine evaluated and
/// what it could NOT evaluate, and why. Kept separate from findings so
/// detection counts stay purely evidence-driven (§24 live counts).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    Evaluated,
    NotEvaluated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageNote {
    pub category: String,
    pub status: CoverageStatus,
    /// Exact statement shown to the examiner.
    pub detail: String,
}

/// Known mining executables (matched against lowercase name/path).
const MINER_NAMES: &[&str] = &[
    "xmrig", "minerd", "cpuminer", "ethminer", "nbminer", "lolminer", "phoenixminer", "t-rex",
    "xmr-stak", "gminer", "bminer", "claymore", "cgminer", "bfgminer", "nicehashminer",
];

/// Command-line keywords typical of mining software.
const MINING_KEYWORDS: &[&str] = &[
    "stratum+tcp", "stratum2+tcp", "--donate-level", "-o pool.", "--nicehash", ":3333", ":4444",
    ":5555", ":7777", ":14444",
];

/// Mining-pool domain keywords (matched against remote addresses/DNS).
const POOL_DOMAIN_KEYWORDS: &[&str] = &[
    "xmrpool", "supportxmr", "nanopool", "minergate", "moneroocean", "nicehash", "f2pool",
    "hashvault", "herominers",
];

/// Remote-access tool process names (flagged, not condemned).
const REMOTE_ACCESS_TOOLS: &[&str] = &[
    "anydesk", "teamviewer", "rustdesk", "ultraviewer", "splashtop", "logmein", "vncviewer",
    "tvnserver", "mstsc",
];

/// Ports commonly associated with RATs/miners/backdoors (watch list only).
const WATCH_PORTS: &[u16] = &[1337, 31337, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 3333, 14444];

/// Core system processes that should only run from Windows directories.
const SYSTEM_PROCESS_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "services.exe", "smss.exe",
    "explorer.exe", "wininit.exe",
];

/// Path fragments considered suspicious for persistence payloads.
const SUSPICIOUS_PATH_MARKERS: &[&str] = &[
    "\\temp\\", "\\appdata\\local\\temp", "\\downloads\\", "\\users\\public\\", "\\programdata\\",
    ".vbs", ".js ", ".js\"", ".hta", ".scr", "powershell", "cmd.exe /c", "mshta", "rundll32",
    "regsvr32", "-enc ", "wscript", "certutil",
];

/// Run every deterministic rule over the decoded streams of the case.
pub fn run_all(streams: &DecodedStreams) -> Vec<Finding> {
    let mut detections = Vec::new();

    if let Some(proc_stream) = &streams.processes {
        let anchor = proc_stream.list_artifact.clone();
        for p in &proc_stream.processes {
            detections.extend(process_rules(p, anchor.as_deref()));
        }
    }
    if let Some(net) = &streams.network {
        let anchor = net.connections_artifact.clone();
        for c in &net.connections {
            detections.extend(connection_rules(c, anchor.as_deref()));
        }
    }
    if let Some(persist) = &streams.persistence {
        let anchor = persist.run_keys_artifact.clone();
        for key in &persist.run_keys {
            for value in &key.values {
                detections.extend(run_value_rules(&key.hive, &key.key_path, value, anchor.as_deref()));
            }
        }
    }
    if let Some(events) = &streams.events {
        for channel in &events.channels {
            let anchor = channel.artifact_id.clone();
            detections.extend(event_rules(&channel.label, &channel.events, anchor.as_deref()));
        }
    }
    detections.extend(gpu_rules(streams));

    // Deterministic ordering for stable reports.
    detections.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    detections
}

fn process_rules(p: &ProcessEntry, anchor: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    let supporting = anchor.map(|a| vec![a.to_string()]).unwrap_or_default();
    let name_lower = p.name.to_ascii_lowercase();
    let path_lower = p.executable_path.as_deref().unwrap_or("").to_ascii_lowercase();
    let cmd_lower = p.command_line.to_ascii_lowercase();

    // CRYPTO-001: known miner executable present.
    if MINER_NAMES.iter().any(|m| name_lower.contains(m) || path_lower.contains(m)) {
        let mut f = Finding::new(
            "CRYPTO-001",
            "POTENTIAL CRYPTO MINING INDICATOR — KNOWN MINER EXECUTABLE",
            Severity::High,
            format!("Process '{}' (pid {}) matches a known mining executable name.", p.name, p.pid),
            supporting.clone(),
            vec![format!("process name '{}' matches miner signature list", p.name)],
            0.90,
            DetectionMethod::RuleBased,
        );
        f.pid = Some(p.pid);
        f.process_name = Some(p.name.clone());
        f.flagged_values.push(p.name.clone());
        out.push(f);
    }

    // CRYPTO-002: mining command-line arguments.
    let hits: Vec<&str> = MINING_KEYWORDS.iter().filter(|k| cmd_lower.contains(**k)).copied().collect();
    if !hits.is_empty() {
        let mut f = Finding::new(
            "CRYPTO-002",
            "POTENTIAL CRYPTO MINING INDICATOR — MINING COMMAND-LINE ARGUMENTS",
            Severity::High,
            format!(
                "Process '{}' (pid {}) command line contains mining-associated arguments ({}).",
                p.name, p.pid, hits.join(", ")
            ),
            supporting.clone(),
            hits.iter().map(|h| format!("command line contains '{h}'")).collect(),
            0.85,
            DetectionMethod::RuleBased,
        );
        f.pid = Some(p.pid);
        f.process_name = Some(p.name.clone());
        f.flagged_values.extend(hits.iter().map(|h| h.to_string()));
        out.push(f);
    }

    // CRYPTO-003: mining-pool domain referenced on the command line.
    if let Some(pool) = POOL_DOMAIN_KEYWORDS.iter().find(|k| cmd_lower.contains(**k)) {
        let mut f = Finding::new(
            "CRYPTO-003",
            "POTENTIAL CRYPTO MINING INDICATOR — POOL DOMAIN REFERENCE",
            Severity::Medium,
            format!("Process '{}' (pid {}) command line references mining-pool pattern '{pool}'.", p.name, p.pid),
            supporting.clone(),
            vec![format!("command line contains pool keyword '{pool}'")],
            0.70,
            DetectionMethod::RuleBased,
        );
        f.pid = Some(p.pid);
        f.process_name = Some(p.name.clone());
        f.flagged_values.push(pool.to_string());
        out.push(f);
    }

    // MAL-001: executable running from a suspicious location.
    if !path_lower.is_empty() {
        let markers: Vec<&str> = ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public\\", "\\downloads\\", "\\programdata\\"]
            .iter()
            .filter(|m| path_lower.contains(**m))
            .copied()
            .collect();
        if !markers.is_empty() {
            let mut f = Finding::new(
                "MAL-001",
                "POTENTIAL MALWARE INDICATOR — EXECUTABLE IN SUSPICIOUS LOCATION",
                Severity::Medium,
                format!(
                    "Process '{}' (pid {}) runs from '{}' — a location commonly abused for droppers.",
                    p.name, p.pid, p.executable_path.as_deref().unwrap_or("?")
                ),
                supporting.clone(),
                markers.iter().map(|m| format!("executable path contains '{m}'")).collect(),
                0.55,
                DetectionMethod::Heuristic,
            );
            f.pid = Some(p.pid);
            f.process_name = Some(p.name.clone());
            f.flagged_values
                .push(p.executable_path.as_deref().unwrap_or("").to_string());
            out.push(f);
        }
    }

    // MAL-002: core system process masquerading outside Windows dirs.
    if SYSTEM_PROCESS_NAMES.contains(&name_lower.as_str()) && !path_lower.is_empty() {
        let in_windows = path_lower.contains("\\windows\\system32")
            || path_lower.contains("\\windows\\syswow64")
            || name_lower == "explorer.exe" && path_lower.contains("\\windows\\");
        if !in_windows {
            let mut f = Finding::new(
                "MAL-002",
                "POTENTIAL MALWARE INDICATOR — SYSTEM PROCESS MASQUERADING",
                Severity::High,
                format!(
                    "'{}' (pid {}) is running from '{}' — core system binaries normally live in System32.",
                    p.name, p.pid, p.executable_path.as_deref().unwrap_or("?")
                ),
                supporting.clone(),
                vec![format!("system-named process outside expected Windows directories: {}", path_lower)],
                0.80,
                DetectionMethod::RuleBased,
            );
            f.pid = Some(p.pid);
            f.process_name = Some(p.name.clone());
            f.flagged_values
                .push(p.executable_path.as_deref().unwrap_or("").to_string());
            out.push(f);
        }
    }

    out
}

fn connection_rules(c: &ConnectionEntry, anchor: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    let supporting = anchor.map(|a| vec![a.to_string()]).unwrap_or_default();
    let proc_lower = c.process.to_ascii_lowercase();

    // NET-001: remote-access tool with live sockets.
    if REMOTE_ACCESS_TOOLS.iter().any(|t| proc_lower.contains(t))
        && matches!(c.state.to_ascii_lowercase().as_str(), "established" | "listening")
    {
        let mut f = Finding::new(
            "NET-001",
            "POTENTIAL NETWORK INDICATOR — REMOTE-ACCESS TOOL WITH ACTIVE CONNECTION",
            Severity::Medium,
            format!(
                "Remote-access process '{}' (pid {}) shows {} {}:{} -> {}:{}",
                c.process, c.pid, c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port
            ),
            supporting.clone(),
            vec![
                format!("process '{}' matches remote-access tool list", c.process),
                format!("socket state '{}'", c.state),
            ],
            0.60,
            DetectionMethod::Heuristic,
        );
        f.pid = Some(c.pid);
        f.process_name = Some(c.process.clone());
        f.flagged_values.push(c.process.clone());
        out.push(f);
    }

    // NET-002: watch-list port in use.
    if WATCH_PORTS.contains(&c.remote_port) || WATCH_PORTS.contains(&c.local_port) {
        let mut f = Finding::new(
            "NET-002",
            "POTENTIAL NETWORK INDICATOR — WATCH-LIST PORT IN USE",
            Severity::Medium,
            format!(
                "Connection by '{}' (pid {}) uses port {} which is on the analyst watch list.",
                c.process, c.pid, c.remote_port.max(c.local_port)
            ),
            supporting.clone(),
            vec![format!("local/remote port {} matches watch list", c.remote_port.max(c.local_port))],
            0.45,
            DetectionMethod::Heuristic,
        );
        f.pid = Some(c.pid);
        f.process_name = Some(c.process.clone());
        f.flagged_values
            .push(c.remote_port.max(c.local_port).to_string());
        out.push(f);
    }

    out
}

fn run_value_rules(hive: &str, key_path: &str, value: &RunValue, anchor: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    let data_lower = value.data.to_ascii_lowercase();
    let hits: Vec<&str> = SUSPICIOUS_PATH_MARKERS
        .iter()
        .filter(|m| data_lower.contains(*m))
        .copied()
        .collect();
    if hits.is_empty() {
        return out;
    }
    let mut f = Finding::new(
        "PERSIST-001",
        "POTENTIAL PERSISTENCE INDICATOR — RUN KEY POINTING TO SUSPICIOUS PAYLOAD",
        Severity::High,
        format!(
            "Run value '{}' under {}\\{} launches '{}' — markers: {}.",
            value.value_name, hive, key_path, value.data, hits.join(", ")
        ),
        anchor.map(|a| vec![a.to_string()]).unwrap_or_default(),
        hits.iter().map(|h| format!("run-key data contains '{h}'")).collect(),
        0.70,
        DetectionMethod::Heuristic,
    );
    f.flagged_values.push(value.data.clone());
    out.push(f);
    out
}

fn event_rules(channel: &str, events: &[EventEntry], anchor: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    let supporting = anchor.map(|a| vec![a.to_string()]).unwrap_or_default();

    // EVT-001: Windows audit log cleared (EventID 1102).
    let cleared = events.iter().filter(|e| e.event_id == 1102).count();
    if cleared > 0 {
        let mut f = Finding::new(
            "EVT-001",
            "POTENTIAL ANTI-FORENSICS INDICATOR — AUDIT LOG CLEARED",
            Severity::High,
            format!("Channel '{channel}' recorded {cleared} EventID 1102 (security log cleared) event(s)."),
            supporting.clone(),
            vec!["EventID 1102 present in security channel".into()],
            0.95,
            DetectionMethod::RuleBased,
        );
        f.flagged_values.push("1102".into());
        out.push(f);
    }

    // EVT-002: burst of failed logons (EventID 4625) — possible brute force.
    let failed_logons = events.iter().filter(|e| e.event_id == 4625).count();
    if failed_logons >= 10 {
        let mut f = Finding::new(
            "EVT-002",
            "POTENTIAL INTRUSION INDICATOR — BURST OF FAILED LOGONS",
            Severity::Medium,
            format!("Channel '{channel}' recorded {failed_logons} EventID 4625 failed-logon event(s)."),
            supporting,
            vec![format!("{failed_logons} EventID 4625 events (threshold 10)")],
            0.60,
            DetectionMethod::Heuristic,
        );
        f.flagged_values.push("4625".into());
        out.push(f);
    }

    out
}

// ---------------------------------------------------------------------
// GPU abuse (§28) — never fires on GPU evidence alone
// ---------------------------------------------------------------------

/// GPU-001: GPU compute evidence composed with at least one OTHER
/// grounded signal (live network socket, persistence entry, or mining
/// IOC). GPU process presence by itself is never a finding.
fn gpu_rules(streams: &DecodedStreams) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(gpu) = &streams.gpu else { return out };
    let Some(doc) = &gpu.gpu_processes else { return out };
    if doc.processes.is_empty() {
        return out; // honest emptiness (e.g. nvidia-smi unavailable).
    }
    let Some(gpu_artifact) = &gpu.gpu_processes_artifact else { return out };

    let conns: Vec<&crate::ingest::streams::ConnectionEntry> = streams
        .network
        .as_ref()
        .map(|n| n.connections.iter().collect())
        .unwrap_or_default();
    let conn_artifact = streams.network.as_ref().and_then(|n| n.connections_artifact.clone());
    let run_values: Vec<&RunValue> = streams
        .persistence
        .as_ref()
        .map(|p| p.run_keys.iter().flat_map(|k| k.values.iter()).collect())
        .unwrap_or_default();
    let run_artifact = streams.persistence.as_ref().and_then(|p| p.run_keys_artifact.clone());

    for entry in &doc.processes {
        let gpid = gpu_i64(entry, &["pid", "process_id", "ProcessId"]);
        let gname = gpu_str(entry, &["process_name", "name", "ProcessName"])
            .unwrap_or_default()
            .to_ascii_lowercase();

        let mut signals: Vec<String> = Vec::new();
        let mut supporting = vec![gpu_artifact.clone()];

        // Signal A: live socket owned by the same pid.
        if let Some(pid) = gpid {
            let live = conns.iter().filter(|c| {
                c.pid == pid
                    && matches!(c.state.to_ascii_lowercase().as_str(), "established" | "listening")
            }).count();
            if live > 0 {
                if let Some(id) = &conn_artifact {
                    signals.push(format!("{live} live network connection(s) on the same pid {pid}"));
                    supporting.push(id.clone());
                }
            }
        }

        // Signal B: a persistence Run key launches the same binary.
        if !gname.is_empty() {
            for value in &run_values {
                if run_value_binary(&value.data).as_deref() == Some(gname.as_str()) {
                    if let Some(id) = &run_artifact {
                        signals.push(format!("Run key launches '{gname}' (persistence)"));
                        supporting.push(id.clone());
                        break;
                    }
                }
            }
        }

        // Signal C: mining IOC on the GPU process identity itself.
        if !gname.is_empty() && MINER_NAMES.iter().any(|m| gname.contains(m)) {
            signals.push(format!("GPU process name '{gname}' matches miner signature list"));
        }

        if signals.is_empty() {
            continue; // GPU evidence alone is never a finding.
        }
        supporting.sort();
        supporting.dedup();
        let confidence = (0.5 + 0.15 * signals.len() as f64).min(0.85);
        let severity = if signals.len() >= 2 { Severity::High } else { Severity::Medium };
        let label = gname.clone();
        let mut f = Finding::new(
            "GPU-001",
            "POTENTIAL SUSPICIOUS GPU COMPUTE ACTIVITY",
            severity,
            format!(
                "GPU process '{}'{} is corroborated by other grounded evidence: {}.",
                if label.is_empty() { "(unnamed)" } else { label.as_str() },
                gpid.map(|p| format!(" (pid {p})")).unwrap_or_default(),
                signals.join("; ")
            ),
            supporting,
            signals.clone(),
            confidence,
            DetectionMethod::Heuristic,
        );
        f.pid = gpid;
        if !label.is_empty() {
            f.process_name = Some(label.clone());
            f.flagged_values.push(label);
        }
        out.push(f);
    }
    out
}

fn gpu_i64(v: &serde_json::Value, keys: &[&str]) -> Option<i64> {
    for k in keys {
        if let Some(n) = v.get(k) {
            if let Some(i) = n.as_i64() {
                return Some(i);
            }
            if let Ok(i) = n.as_str().unwrap_or("").parse::<i64>() {
                return Some(i);
            }
        }
    }
    None
}

fn gpu_str(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Launched binary basename from a Run value payload (quoted paths
/// with spaces supported) — shared with persistence matching logic.
fn run_value_binary(data: &str) -> Option<String> {
    let d = data.trim();
    if d.is_empty() {
        return None;
    }
    let candidate = if let Some(rest) = d.strip_prefix('"') {
        rest.find('"').map(|end| &rest[..end]).unwrap_or(rest)
    } else {
        d.split_whitespace().next().unwrap_or(d)
    };
    let binary = candidate.rsplit(['\\', '/']).next()?.to_ascii_lowercase();
    if binary.is_empty() {
        None
    } else {
        Some(binary)
    }
}

// ---------------------------------------------------------------------
// Detection coverage (§27): never silently skip a category
// ---------------------------------------------------------------------

/// Honest per-category coverage. "Not evaluated" is reported with the
/// exact reason — it is a different statement than "nothing found".
pub fn coverage(streams: &DecodedStreams) -> Vec<CoverageNote> {
    let mut notes = Vec::new();

    // §27 injection: needs memory-region / RWX evidence this AIF
    // contract does not carry (§10 keeps memory as presence only).
    notes.push(if !streams.memory_present {
        CoverageNote {
            category: "PROCESS INJECTION (§27)".into(),
            status: CoverageStatus::NotEvaluated,
            detail: "Not evaluated: no memory evidence in this case.".into(),
        }
    } else {
        CoverageNote {
            category: "PROCESS INJECTION (§27)".into(),
            status: CoverageStatus::NotEvaluated,
            detail: "Not evaluated: memory artifacts are present, but this AIF carries no \
                     memory-region/RWX stream — injection indicators require region-level \
                     evidence that was not acquired."
                .into(),
        }
    });

    // §28 GPU: state exactly what was and wasn't observable.
    let gpu_note = match &streams.gpu {
        None => CoverageNote {
            category: "GPU ABUSE (§28)".into(),
            status: CoverageStatus::NotEvaluated,
            detail: "Not evaluated: no GPU evidence stream in this case.".into(),
        },
        Some(gpu) => match &gpu.gpu_processes {
            None => CoverageNote {
                category: "GPU ABUSE (§28)".into(),
                status: CoverageStatus::NotEvaluated,
                detail: "Not evaluated: GPU metadata present but no GPU process enumeration artifact.".into(),
            },
            Some(doc) if doc.processes.is_empty() => CoverageNote {
                category: "GPU ABUSE (§28)".into(),
                status: CoverageStatus::Evaluated,
                detail: format!(
                    "Evaluated: GPU process enumeration is honestly empty{}— no GPU process finding produced.",
                    doc.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default()
                ),
            },
            Some(_) => CoverageNote {
                category: "GPU ABUSE (§28)".into(),
                status: CoverageStatus::Evaluated,
                detail: "Evaluated: GPU processes checked against network, persistence and \
                         mining-IOC signals (composition required — GPU evidence alone never fires)."
                    .into(),
            },
        },
    };
    notes.push(gpu_note);

    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::streams::{
        ConnectionEntry, GpuProcessesDoc, GpuStream, NetworkStream, PersistenceStream,
        ProcessStream, RunKey,
    };

    fn process(pid: i64, name: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            name: name.into(),
            parent_pid: None,
            command_line: String::new(),
            executable_path: None,
            user: None,
            cpu_usage_percent: 0.0,
            memory_bytes: 0,
            virtual_memory_bytes: 0,
            thread_count: 0,
            handle_count: None,
            integrity_level: None,
            status: String::new(),
            start_time_rfc3339: String::new(),
            start_time_unix: 0,
            run_time_seconds: 0,
        }
    }

    fn network(pid: i64, proc_name: &str) -> NetworkStream {
        NetworkStream {
            connections: vec![ConnectionEntry {
                protocol: "TCP".into(),
                local_address: "10.0.0.5".into(),
                local_port: 49152,
                remote_address: "192.168.1.1".into(),
                remote_port: 3333,
                state: "ESTABLISHED".into(),
                pid,
                process: proc_name.into(),
            }],
            connections_artifact: Some("ART-000002".into()),
            dns_adapters: Vec::new(),
            interfaces: Vec::new(),
            interfaces_artifact: None,
            adapters_raw: None,
            routes_raw: None,
            arp_raw: None,
        }
    }

    fn gpu_with(processes: Vec<serde_json::Value>, artifact: Option<&str>) -> GpuStream {
        let mut gpu = GpuStream::default();
        gpu.gpu_processes = Some(GpuProcessesDoc {
            acquired_at: String::new(),
            note: None,
            processes,
            source_available: true,
        });
        gpu.gpu_processes_artifact = artifact.map(|a| a.to_string());
        gpu
    }

    #[test]
    fn every_finding_carries_confidence_and_method_label() {
        let mut streams = DecodedStreams::default();
        let mut ps = ProcessStream::default();
        ps.list_artifact = Some("ART-000010".into());
        let mut miner = process(4242, "xmrig.exe");
        miner.command_line = "xmrig.exe -o pool.supportxmr.com:3333".into();
        miner.executable_path = Some("C:\\Users\\Public\\xmrig.exe".into());
        ps.processes.push(miner);
        streams.processes = Some(ps);
        let detections = run_all(&streams);
        assert!(!detections.is_empty());
        for d in &detections {
            let conf = d.confidence.unwrap_or_else(|| panic!("{} missing confidence", d.rule_id));
            assert!(conf > 0.0 && conf <= 1.0, "{} confidence {}", d.rule_id, conf);
            // Labels are exactly the §33 vocabulary.
            assert!(["RULE-BASED", "HEURISTIC", "ML", "LLM-AI"].contains(&d.method.label()));
            assert!(d.title.starts_with("POTENTIAL"), "{} drifts into certainty", d.rule_id);
        }
    }

    #[test]
    fn empty_streams_produce_no_findings() {
        let detections = run_all(&DecodedStreams::default());
        assert!(detections.is_empty(), "no evidence, no findings");
        // But coverage must still speak (§27): not silently skipped.
        let notes = coverage(&DecodedStreams::default());
        let inj = notes.iter().find(|n| n.category.starts_with("PROCESS INJECTION")).unwrap();
        assert_eq!(inj.status, CoverageStatus::NotEvaluated);
        assert_eq!(inj.detail, "Not evaluated: no memory evidence in this case.");
        let gpu = notes.iter().find(|n| n.category.starts_with("GPU ABUSE")).unwrap();
        assert_eq!(gpu.status, CoverageStatus::NotEvaluated);
    }

    /// Memory present but no region stream → a DIFFERENT explicit
    /// statement than "no memory evidence" (§27 wording contract).
    #[test]
    fn injection_coverage_distinguishes_memory_presence() {
        let mut streams = DecodedStreams::default();
        streams.memory_present = true;
        let notes = coverage(&streams);
        let inj = notes.iter().find(|n| n.category.starts_with("PROCESS INJECTION")).unwrap();
        assert_eq!(inj.status, CoverageStatus::NotEvaluated);
        assert!(inj.detail.contains("no memory-region/RWX stream"), "{}", inj.detail);
    }

    /// §28 evidentiary bar: GPU process evidence ALONE never fires.
    #[test]
    fn gpu_evidence_alone_produces_no_finding() {
        let mut streams = DecodedStreams::default();
        streams.gpu = Some(gpu_with(
            vec![serde_json::json!({"pid": 777, "process_name": "compute.exe"})],
            Some("ART-000004"),
        ));
        assert!(run_all(&streams).is_empty(), "GPU-only evidence must not fire");
    }

    /// §28: GPU + live network socket on the same pid → GPU-001 with
    /// both artifacts grounded and honest sub-1.0 confidence.
    #[test]
    fn gpu_composes_with_network_signal() {
        let mut streams = DecodedStreams::default();
        let mut ps = ProcessStream::default();
        ps.list_artifact = Some("ART-000001".into());
        ps.processes.push(process(777, "compute.exe"));
        streams.processes = Some(ps);
        streams.network = Some(network(777, "compute.exe"));
        streams.gpu = Some(gpu_with(
            vec![serde_json::json!({"pid": 777, "process_name": "compute.exe"})],
            Some("ART-000004"),
        ));
        let detections = run_all(&streams);
        let gpu_f = detections.iter().find(|d| d.rule_id == "GPU-001").expect("GPU-001 fires on composition");
        assert!(gpu_f.supporting_artifacts.contains(&"ART-000004".to_string()));
        assert!(gpu_f.supporting_artifacts.contains(&"ART-000002".to_string()));
        let conf = gpu_f.confidence.expect("GPU-001 records confidence");
        assert!(conf < 1.0, "confidence never claims certainty");
        assert_eq!(gpu_f.method, DetectionMethod::Heuristic);
        assert!(gpu_f.title.starts_with("POTENTIAL"));
    }

    /// §28 alternate composition: persistence Run key launches the GPU
    /// binary. Miner-name IOC alone (no other stream) is also a valid
    /// second signal.
    #[test]
    fn gpu_composes_with_persistence_or_ioc() {
        // Persistence composition.
        let mut streams = DecodedStreams::default();
        streams.persistence = Some(PersistenceStream {
            run_keys: vec![RunKey {
                hive: "HKCU".into(),
                key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                label: "Run".into(),
                values: vec![RunValue { value_name: "C".into(), data: "C:\\bin\\compute.exe".into() }],
            }],
            services: Vec::new(),
            run_keys_artifact: Some("ART-000003".into()),
            services_artifact: None,
            scheduled_tasks_raw: None,
            startup_raw: None,
            wmi_subscriptions_raw: None,
            logon_raw: None,
        });
        streams.gpu = Some(gpu_with(
            vec![serde_json::json!({"pid": 777, "process_name": "compute.exe"})],
            Some("ART-000004"),
        ));
        let detections = run_all(&streams);
        assert!(detections.iter().any(|d| d.rule_id == "GPU-001"));

        // IOC composition (miner-named GPU process).
        let mut streams2 = DecodedStreams::default();
        streams2.gpu = Some(gpu_with(
            vec![serde_json::json!({"pid": 888, "process_name": "xmrig.exe"})],
            Some("ART-000004"),
        ));
        let detections2 = run_all(&streams2);
        assert!(detections2.iter().any(|d| d.rule_id == "GPU-001"));
    }

    /// GPU coverage language matches the real-case shape: honestly
    /// empty enumeration is Evaluated-with-note, never a finding.
    #[test]
    fn gpu_coverage_reports_honest_empty_enumeration() {
        let mut streams = DecodedStreams::default();
        let mut gpu = GpuStream::default();
        gpu.gpu_processes = Some(GpuProcessesDoc {
            acquired_at: String::new(),
            note: Some("nvidia-smi not installed".into()),
            processes: Vec::new(),
            source_available: false,
        });
        gpu.gpu_processes_artifact = Some("ART-000004".into());
        streams.gpu = Some(gpu);
        let notes = coverage(&streams);
        let gpu_note = notes.iter().find(|n| n.category.starts_with("GPU ABUSE")).unwrap();
        assert_eq!(gpu_note.status, CoverageStatus::Evaluated);
        assert!(gpu_note.detail.contains("honestly empty"));
        assert!(gpu_note.detail.contains("nvidia-smi not installed"));
        assert!(run_all(&streams).is_empty());
    }

    #[test]
    fn miner_process_flagged_and_grounded() {
        let mut streams = DecodedStreams::default();
        let mut ps = ProcessStream::default();
        ps.list_artifact = Some("ART-000010".into());
        ps.processes.push(ProcessEntry {
            pid: 4242,
            name: "xmrig.exe".into(),
            command_line: "xmrig.exe -o pool.supportxmr.com:3333".into(),
            executable_path: Some("C:\\Users\\Public\\xmrig.exe".into()),
            ..Default::default()
        });
        streams.processes = Some(ps);
        let detections = run_all(&streams);
        assert!(detections.iter().any(|d| d.rule_id == "CRYPTO-001"));
        assert!(detections.iter().any(|d| d.rule_id == "CRYPTO-002"));
        assert!(detections.iter().any(|d| d.rule_id == "MAL-001"));
        for d in &detections {
            assert!(d.title.starts_with("POTENTIAL"));
            assert_eq!(d.supporting_artifacts, vec!["ART-000010"]);
        }
        // §20 highlight grounding: every miner finding pins the exact
        // evidence values it fired on.
        let crypto1 = detections.iter().find(|d| d.rule_id == "CRYPTO-001").unwrap();
        assert_eq!(crypto1.flagged_values, vec!["xmrig.exe"]);
        let crypto2 = detections.iter().find(|d| d.rule_id == "CRYPTO-002").unwrap();
        assert!(crypto2.flagged_values.iter().any(|v| v.contains("stratum") || v.contains(":3333")));
    }
}
