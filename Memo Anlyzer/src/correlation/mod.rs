//! Forensic correlation engine (§23): links evidence across streams —
//! process ↔ connection ↔ executable path ↔ hash ↔ GPU activity ↔
//! persistence entry.
//!
//! Ground rules (no-fabrication):
//! - every link cites real collector artifact IDs on BOTH sides,
//! - the exact shared evidence value (pid, path, name) is recorded,
//! - a stream that is absent or empty contributes nothing,
//! - cases with too few cross-stream links yield an honest empty
//!   report ("No correlated evidence") rather than forced links,
//! - no scoring or suspicion judgements here — detection is §24.

use std::collections::{HashMap, HashSet};

use crate::ingest::{DecodedStreams, ExaminedCase};

/// Kind of evidence relationship. Kept as plain labels so every link
/// can explain itself in the UI and in reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// Same pid in process_list.json and connections.json.
    ProcessConnection,
    /// Same pid in process_list.json and executable_paths.json.
    ProcessExecutablePath,
    /// Process executable path is one of the hashed files.
    ProcessHash,
    /// Same pid/name in gpu_processes.json and process_list.json.
    ProcessGpu,
    /// A registry Run value launches a binary that is running now.
    PersistenceProcess,
    /// A hashed file is also mapped in executable_paths.json.
    HashRunningBinary,
}

impl LinkKind {
    pub fn label(self) -> &'static str {
        match self {
            LinkKind::ProcessConnection => "PROCESS ↔ NETWORK CONNECTION",
            LinkKind::ProcessExecutablePath => "PROCESS ↔ EXECUTABLE PATH",
            LinkKind::ProcessHash => "PROCESS ↔ EXECUTABLE HASH",
            LinkKind::ProcessGpu => "PROCESS ↔ GPU ACTIVITY",
            LinkKind::PersistenceProcess => "PERSISTENCE ↔ RUNNING PROCESS",
            LinkKind::HashRunningBinary => "HASH ↔ RUNNING BINARY",
        }
    }
}

/// One side of a correlation link. Always carries the collector
/// artifact ID that grounds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub artifact_id: String,
    pub label: String,
}

/// One traceable evidence pair. `matched` is the exact value shared by
/// both sides (pid, path or binary name) — never a paraphrase.
#[derive(Clone, Debug)]
pub struct CorrelationLink {
    pub kind: LinkKind,
    pub a: Endpoint,
    pub b: Endpoint,
    pub matched: String,
}

/// §23 chain: one process joined with every other artifact that the
/// evidence actually connects it to. Only emitted when at least one
/// cross-stream partner exists — never padded.
#[derive(Clone, Debug)]
pub struct CorrelatedActivity {
    pub process_pid: i64,
    pub process_name: String,
    pub process_artifact: String,
    /// Distinct partner artifact IDs (excludes the process artifact).
    pub partners: Vec<String>,
    /// Link labels realized for this process (for display).
    pub kinds: Vec<&'static str>,
}

#[derive(Clone, Debug, Default)]
pub struct CorrelationReport {
    pub links: Vec<CorrelationLink>,
    pub activities: Vec<CorrelatedActivity>,
}

impl CorrelationReport {
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// Convenience wrapper over a fully ingested case.
pub fn build(exam: &ExaminedCase) -> CorrelationReport {
    correlate_streams(&exam.streams)
}

/// Pure correlation over decoded streams (testable without an AIF).
pub fn correlate_streams(streams: &DecodedStreams) -> CorrelationReport {
    let mut report = CorrelationReport::default();
    let Some(processes) = &streams.processes else {
        return report; // no process baseline → nothing to correlate.
    };
    let Some(process_artifact) = &processes.list_artifact else {
        return report; // no grounding artifact → no traceable links.
    };

    let by_pid: HashMap<i64, &crate::ingest::streams::ProcessEntry> = processes
        .processes
        .iter()
        .filter(|p| p.pid > 0)
        .map(|p| (p.pid, p))
        .collect();
    let mut by_name: HashMap<String, Vec<&crate::ingest::streams::ProcessEntry>> = HashMap::new();
    for p in &processes.processes {
        if !p.name.is_empty() {
            by_name.entry(p.name.to_ascii_lowercase()).or_default().push(p);
        }
    }

    // Per-process partner tracking for the activity chains.
    let mut partners: HashMap<i64, HashSet<String>> = HashMap::new();
    let mut kinds: HashMap<i64, Vec<&'static str>> = HashMap::new();
    let mut record = |report: &mut CorrelationReport,
                      pid: i64,
                      kind: LinkKind,
                      a: Endpoint,
                      b: Endpoint,
                      matched: String| {
        partners.entry(pid).or_default().insert(b.artifact_id.clone());
        partners.entry(pid).or_default().insert(a.artifact_id.clone());
        let ks = kinds.entry(pid).or_default();
        let label = kind.label();
        if !ks.contains(&label) {
            ks.push(label);
        }
        report.links.push(CorrelationLink { kind, a, b, matched });
    };

    // 1. PROCESS ↔ NETWORK CONNECTION (shared pid — the connection's
    //    owning process id is the traceable identifier; name-only
    //    matching would be inference, so it is deliberately absent).
    if let Some(net) = &streams.network {
        if let Some(conn_artifact) = &net.connections_artifact {
            let mut conns_by_pid: HashMap<i64, Vec<&crate::ingest::streams::ConnectionEntry>> =
                HashMap::new();
            for c in &net.connections {
                if c.pid > 0 && by_pid.contains_key(&c.pid) {
                    conns_by_pid.entry(c.pid).or_default().push(c);
                }
            }
            for (pid, conns) in &conns_by_pid {
                let proc = by_pid[pid];
                record(
                    &mut report,
                    *pid,
                    LinkKind::ProcessConnection,
                    Endpoint { artifact_id: process_artifact.clone(), label: format!("Process '{}' (pid {})", proc.name, pid) },
                    Endpoint { artifact_id: conn_artifact.clone(), label: format!("{} network connection(s)", conns.len()) },
                    summarize_conns(conns),
                );
            }
        }
    }

    // 2. PROCESS ↔ EXECUTABLE PATH (shared pid).
    if !processes.executable_paths.is_empty() {
        if let Some(ep_artifact) = &processes.executable_paths_artifact {
            for ep in &processes.executable_paths {
                if let Some(proc) = by_pid.get(&ep.pid) {
                    record(
                        &mut report,
                        ep.pid,
                        LinkKind::ProcessExecutablePath,
                        Endpoint { artifact_id: process_artifact.clone(), label: format!("Process '{}' (pid {})", proc.name, ep.pid) },
                        Endpoint { artifact_id: ep_artifact.clone(), label: "Executable path mapping".into() },
                        ep.path.clone(),
                    );
                }
            }
        }
    }

    // 3. PROCESS ↔ EXECUTABLE HASH (executable path ∈ hashed files).
    //    Requires the hashes.json grounding artifact — no ID, no link.
    if let (Some(hashes), Some(hash_artifact)) = (&streams.hashes, &streams.hashes_artifact) {
        let hash_paths: HashMap<String, &crate::ingest::streams::HashEntry> = hashes
            .iter()
            .filter(|h| !h.relative_path.is_empty())
            .map(|h| (normalize_path(&h.relative_path), h))
            .collect();
        for p in &processes.processes {
            let Some(exec) = &p.executable_path else { continue };
            let norm = normalize_path(exec);
            for (hp, h) in &hash_paths {
                if path_matches(&norm, hp) {
                    record(
                        &mut report,
                        p.pid,
                        LinkKind::ProcessHash,
                        Endpoint { artifact_id: process_artifact.clone(), label: format!("Process '{}' (pid {})", p.name, p.pid) },
                        Endpoint {
                            artifact_id: hash_artifact.clone(),
                            label: format!("Hashed file '{}' ({})", h.relative_path, short_hash(&h.sha256)),
                        },
                        h.sha256.clone(),
                    );
                    break;
                }
            }
        }
        // 4. HASH ↔ RUNNING BINARY (hashed file present in
        //    executable_paths.json).
        if let Some(ep_artifact) = &processes.executable_paths_artifact {
            for ep in &processes.executable_paths {
                let norm = normalize_path(&ep.path);
                for (hp, h) in &hash_paths {
                    if path_matches(&norm, hp) {
                        report.links.push(CorrelationLink {
                            kind: LinkKind::HashRunningBinary,
                            a: Endpoint {
                                artifact_id: hash_artifact.clone(),
                                label: format!("Hashed file '{}'", h.relative_path),
                            },
                            b: Endpoint { artifact_id: ep_artifact.clone(), label: "Executable path mapping".into() },
                            matched: ep.path.clone(),
                        });
                        break;
                    }
                }
            }
        }
    }

    // 5. PROCESS ↔ GPU ACTIVITY (shared pid or name in
    //    gpu_processes.json). Honest degradation: the real reference
    //    case reports `source_available=false` → no links, no guesses.
    if let Some(gpu) = &streams.gpu {
        if let (Some(doc), Some(gpu_artifact)) = (&gpu.gpu_processes, &gpu.gpu_processes_artifact) {
            for entry in &doc.processes {
                let gpid = json_i64(entry, &["pid", "process_id", "ProcessId"]);
                let gname = json_str(entry, &["process_name", "name", "ProcessName"]);
                let matched_procs: Vec<&crate::ingest::streams::ProcessEntry> = if let Some(pid) = gpid {
                    by_pid.get(&pid).into_iter().copied().collect()
                } else if let Some(name) = &gname {
                    by_name.get(&name.to_ascii_lowercase()).cloned().unwrap_or_default()
                } else {
                    Vec::new()
                };
                for proc in matched_procs {
                    record(
                        &mut report,
                        proc.pid,
                        LinkKind::ProcessGpu,
                        Endpoint { artifact_id: process_artifact.clone(), label: format!("Process '{}' (pid {})", proc.name, proc.pid) },
                        Endpoint { artifact_id: gpu_artifact.clone(), label: "GPU process enumeration".into() },
                        gname.clone().unwrap_or_else(|| format!("pid {}", proc.pid)),
                    );
                }
            }
        }
    }

    // 6. PERSISTENCE ↔ RUNNING PROCESS (Run value launches a binary
    //    that is currently running — exact basename match only).
    if let Some(persist) = &streams.persistence {
        if let Some(run_artifact) = &persist.run_keys_artifact {
            for key in &persist.run_keys {
                for value in &key.values {
                    let Some(binary) = run_value_binary(&value.data) else { continue };
                    let Some(procs) = by_name.get(&binary) else { continue };
                    for proc in procs {
                        record(
                            &mut report,
                            proc.pid,
                            LinkKind::PersistenceProcess,
                            Endpoint { artifact_id: run_artifact.clone(), label: format!("Run key '{}\\{}' → '{}'", key.hive, key.key_path, value.value_name) },
                            Endpoint { artifact_id: process_artifact.clone(), label: format!("Process '{}' (pid {})", proc.name, proc.pid) },
                            value.data.clone(),
                        );
                    }
                }
            }
        }
    }

    // Activity chains: processes with at least one grounded partner.
    for p in &processes.processes {
        let Some(ps) = partners.get(&p.pid) else { continue };
        let partner_ids: Vec<String> = ps
            .iter()
            .filter(|id| id.as_str() != process_artifact.as_str() && !id.is_empty())
            .cloned()
            .collect();
        if partner_ids.is_empty() {
            continue;
        }
        let mut partner_ids = partner_ids;
        partner_ids.sort();
        report.activities.push(CorrelatedActivity {
            process_pid: p.pid,
            process_name: p.name.clone(),
            process_artifact: process_artifact.clone(),
            partners: partner_ids,
            kinds: kinds.get(&p.pid).cloned().unwrap_or_default(),
        });
    }
    report.activities.sort_by(|a, b| b.partners.len().cmp(&a.partners.len()));

    // Grounding invariant: no link may carry an empty artifact ID.
    debug_assert!(report
        .links
        .iter()
        .all(|l| !l.a.artifact_id.is_empty() && !l.b.artifact_id.is_empty()));
    report
}

// ---------------------------------------------------------------------
// Helpers — exact matching only, no fuzzy inference.
// ---------------------------------------------------------------------

fn summarize_conns(conns: &[&crate::ingest::streams::ConnectionEntry]) -> String {
    let first = conns.first().map(|c| {
        format!(
            "{} {}:{} → {}:{} ({})",
            c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port, c.state
        )
    });
    match (first, conns.len()) {
        (Some(f), 1) => f,
        (Some(f), n) => format!("{f} · +{} more", n - 1),
        (None, _) => String::new(),
    }
}

/// Normalize Windows/container paths to lowercase forward slashes.
fn normalize_path(p: &str) -> String {
    p.replace('\\', "/").to_ascii_lowercase()
}

/// Exact suffix match on a path-separator boundary: an absolute
/// executable path (`C:/users/...`) matches a collector-relative hash
/// entry (`users/...`), but `evil.exe` never matches `notevil.exe`.
fn path_matches(candidate_norm: &str, hash_norm: &str) -> bool {
    if candidate_norm == hash_norm {
        return true;
    }
    candidate_norm
        .strip_suffix(hash_norm)
        .map(|prefix| prefix.ends_with('/'))
        .unwrap_or(false)
}

/// Extract the launched binary name from a Run value's data string.
/// Handles quoted paths with spaces and bare `exe /args` forms.
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

fn json_i64(v: &serde_json::Value, keys: &[&str]) -> Option<i64> {
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

fn json_str(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn short_hash(h: &str) -> String {
    if h.len() > 12 {
        format!("{}…", &h[..12])
    } else {
        h.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::streams::*;

    fn proc(pid: i64, name: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            name: name.into(),
            parent_pid: None,
            command_line: format!("C:\\bin\\{name}"),
            executable_path: Some(format!("C:\\Users\\x\\{name}")),
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

    fn base_processes() -> ProcessStream {
        ProcessStream {
            list_artifact: Some("ART-000001".into()),
            processes: vec![proc(100, "miner.exe"), proc(200, "svchost.exe")],
            tree: Vec::new(),
            loaded_module_count: 0,
            executable_paths: Vec::new(),
            executable_paths_present: false,
            executable_paths_artifact: None,
        }
    }

    #[test]
    fn correlates_process_to_connection_by_pid() {
        let mut streams = DecodedStreams::default();
        streams.processes = Some(base_processes());
        streams.network = Some(NetworkStream {
            connections: vec![ConnectionEntry {
                protocol: "TCP".into(),
                local_address: "10.0.0.5".into(),
                local_port: 49152,
                remote_address: "192.168.1.1".into(),
                remote_port: 3333,
                state: "ESTABLISHED".into(),
                pid: 100,
                process: String::new(),
            }],
            connections_artifact: Some("ART-000002".into()),
            dns_adapters: Vec::new(),
            interfaces: Vec::new(),
            interfaces_artifact: None,
            adapters_raw: None,
            routes_raw: None,
            arp_raw: None,
        });
        let report = correlate_streams(&streams);
        assert_eq!(report.links.len(), 1);
        let link = &report.links[0];
        assert_eq!(link.kind, LinkKind::ProcessConnection);
        assert_eq!(link.a.artifact_id, "ART-000001");
        assert_eq!(link.b.artifact_id, "ART-000002");
        assert!(link.matched.contains("3333"), "real endpoint cited");
        assert_eq!(report.activities.len(), 1);
        assert_eq!(report.activities[0].process_name, "miner.exe");
    }

    #[test]
    fn correlates_process_to_hash_by_path_suffix() {
        let mut streams = DecodedStreams::default();
        let mut procs = base_processes();
        procs.processes[0].executable_path = Some("C:\\Users\\x\\miner.exe".into());
        streams.processes = Some(procs);
        streams.hashes_artifact = Some("ART-000009".into());
        streams.hashes = Some(vec![HashEntry {
            sha256: "ab".repeat(32),
            relative_path: "Users/x/miner.exe".into(), // collector-relative
            size: 100,
            source: String::new(),
            status: "SUCCESS".into(),
            acquisition_time: String::new(),
            note: None,
        }]);
        let report = correlate_streams(&streams);
        assert_eq!(report.links.len(), 1);
        assert_eq!(report.links[0].kind, LinkKind::ProcessHash);
        assert_eq!(report.links[0].b.artifact_id, "ART-000009");

        // Without the grounding artifact: no link, never a dangling ID.
        streams.hashes_artifact = None;
        assert!(correlate_streams(&streams).is_empty());
    }

    #[test]
    fn path_matching_is_boundary_exact() {
        assert!(path_matches("c:/users/x/miner.exe", "users/x/miner.exe"));
        assert!(!path_matches("c:/users/x/evilminer.exe", "miner.exe"));
        assert!(path_matches("users/x/miner.exe", "users/x/miner.exe"));
    }

    #[test]
    fn correlates_run_key_to_running_process_exact_name() {
        let mut streams = DecodedStreams::default();
        streams.processes = Some(base_processes());
        streams.persistence = Some(PersistenceStream {
            run_keys: vec![RunKey {
                hive: "HKCU".into(),
                key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                label: "Run".into(),
                values: vec![
                    RunValue { value_name: "Miner".into(), data: "\"C:\\Users\\x\\miner.exe\" /silent".into() },
                    RunValue { value_name: "Other".into(), data: "notinstalled.exe".into() },
                ],
            }],
            services: Vec::new(),
            run_keys_artifact: Some("ART-000003".into()),
            services_artifact: None,
            scheduled_tasks_raw: None,
            startup_raw: None,
            wmi_subscriptions_raw: None,
            logon_raw: None,
        });
        let report = correlate_streams(&streams);
        assert_eq!(report.links.len(), 1, "only the running binary is linked");
        assert_eq!(report.links[0].kind, LinkKind::PersistenceProcess);
        assert_eq!(report.links[0].a.artifact_id, "ART-000003");
    }

    #[test]
    fn honest_degradation_no_cross_stream_evidence() {
        // Processes only — nothing to correlate, nothing invented.
        let mut streams = DecodedStreams::default();
        streams.processes = Some(base_processes());
        let report = correlate_streams(&streams);
        assert!(report.is_empty());
        assert!(report.activities.is_empty());

        // No process baseline at all → empty as well.
        let empty = correlate_streams(&DecodedStreams::default());
        assert!(empty.is_empty());
    }

    #[test]
    fn gpu_link_requires_grounded_artifact_and_real_pid() {
        let mut streams = DecodedStreams::default();
        streams.processes = Some(base_processes());
        let mut gpu = GpuStream::default();
        gpu.gpu_processes = Some(GpuProcessesDoc {
            acquired_at: String::new(),
            note: None,
            processes: vec![serde_json::json!({"pid": 100, "process_name": "miner.exe"})],
            source_available: true,
        });
        // No grounding artifact → no link, even with matching data.
        streams.gpu = Some(gpu.clone());
        assert!(correlate_streams(&streams).is_empty());
        // Grounded → exactly one traceable link.
        gpu.gpu_processes_artifact = Some("ART-000004".into());
        streams.gpu = Some(gpu);
        let report = correlate_streams(&streams);
        assert_eq!(report.links.len(), 1);
        assert_eq!(report.links[0].kind, LinkKind::ProcessGpu);
        assert_eq!(report.links[0].b.artifact_id, "ART-000004");
    }

    /// §23 over the real case: every link endpoint must resolve to an
    /// indexed artifact — correlations are never dangling references.
    #[test]
    fn real_case_correlations_are_fully_grounded() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else {
            eprintln!("sample AIF not present - skipping");
            return;
        };
        let report = build(&exam);
        assert!(!report.is_empty(), "real case has cross-stream evidence");
        for link in &report.links {
            assert!(
                exam.artifact_by_id(&link.a.artifact_id).is_some(),
                "link side A '{}' not a real artifact ({})",
                link.a.artifact_id,
                link.kind.label()
            );
            assert!(
                exam.artifact_by_id(&link.b.artifact_id).is_some(),
                "link side B '{}' not a real artifact ({})",
                link.b.artifact_id,
                link.kind.label()
            );
            assert!(!link.matched.is_empty(), "every link cites the shared value");
        }
        for act in &report.activities {
            assert!(exam.artifact_by_id(&act.process_artifact).is_some());
            for partner in &act.partners {
                assert!(
                    exam.artifact_by_id(partner).is_some(),
                    "activity partner '{partner}' not a real artifact"
                );
            }
        }
        let kinds: HashSet<LinkKind> = report.links.iter().map(|l| l.kind).collect();
        assert!(kinds.contains(&LinkKind::ProcessConnection), "real case: process↔connection");
        assert!(!report.activities.is_empty(), "real case: at least one activity chain");
    }
}
