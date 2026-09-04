//! Evidence ingestion: open an AIF image, verify integrity, index the
//! manifest artifacts, decode the evidence streams and assemble an
//! [`ExaminedCase`] — the single source of truth for every screen.
//!
//! Nothing here is simulated: every value traces to a container entry,
//! and absent streams stay `None` ("Not present in evidence").

pub mod index;
pub mod streams;

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::aifzip::container::{open_aif, AifOpenError, OpenedAif};
use crate::aifzip::integrity::{deep_verify_progress, ArtifactCheck, ContainerCheck};
use crate::aifzip::schema::{CaseDocument, Custody, Manifest};

use index::{build_index, index_json_value, push_field, EvidenceTree, FieldEntry, IndexedArtifact};
use streams::{
    decode_json, decode_raw, parse_executable_paths, parse_hashes, parse_raw_xml_events,
    ConnectionsDoc, CpuStream, EventChannel, EventStream, EventsDoc, GpuStream, HashEntry,
    InterfacesDoc, NetworkStream, OsDoc, PersistenceStream, ProcessEntry, ProcessStream,
    ProcessTreeNode, RawXmlEvent, RegistryRunsDoc, RegistryStream, ServicesDoc, SystemStream,
};

/// All decoded evidence streams. `None` = not present in evidence.
#[derive(Clone, Debug, Default)]
pub struct DecodedStreams {
    pub system: Option<SystemStream>,
    pub os: Option<OsDoc>,
    pub cpu: Option<CpuStream>,
    pub gpu: Option<GpuStream>,
    pub memory_present: bool,
    pub processes: Option<ProcessStream>,
    pub network: Option<NetworkStream>,
    pub events: Option<EventStream>,
    pub persistence: Option<PersistenceStream>,
    pub registry: Option<RegistryStream>,
    pub hashes: Option<Vec<HashEntry>>,
    /// Collector artifact ID behind hashes.json (§23 grounding).
    pub hashes_artifact: Option<String>,
}

/// A fully ingested evidence image, ready for examination.
pub struct ExaminedCase {
    pub image_path: PathBuf,
    pub image_name: String,
    pub size_bytes: u64,
    pub manifest: Manifest,
    pub case_doc: CaseDocument,
    pub custody: Option<Custody>,
    pub container_check: ContainerCheck,
    pub artifact_checks: Vec<ArtifactCheck>,
    pub artifacts: Vec<IndexedArtifact>,
    pub tree: EvidenceTree,
    pub streams: DecodedStreams,
    /// Prebuilt field-value index (§21): global search matches against
    /// this, never re-reads container entries per keystroke.
    pub field_index: Vec<FieldEntry>,
    /// Step-by-step ingest log (shown in the loading overlay).
    pub ingest_log: Vec<String>,
    pub warnings: Vec<String>,
    /// Retained for streamed entry access (hex view, strings, raw).
    pub aif: OpenedAif,
}

impl ExaminedCase {
    pub fn case_id(&self) -> &str {
        &self.manifest.case_id
    }

    pub fn is_demo(&self) -> bool {
        self.case_doc.case.demo_mode
            || self.manifest.artifacts.iter().any(|a| a.synthetic)
    }

    pub fn artifact_by_id(&self, id: &str) -> Option<&IndexedArtifact> {
        self.artifacts.iter().find(|a| a.artifact_id == id)
    }

    /// Number of artifacts whose hash re-verification failed.
    pub fn failed_verifications(&self) -> usize {
        self.artifact_checks.iter().filter(|c| !c.ok).count()
    }
}

// ---------------------------------------------------------------------
// Pre-ingest validation (§7: signature, version, manifest, integrity)
// ---------------------------------------------------------------------

/// Positive result of the pre-ingest AIF validation screen.
#[derive(Clone, Debug)]
pub struct ValidationReport {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub detected_format: String,
    pub aif_version: u32,
    pub entry_count: usize,
    pub artifact_count: usize,
    /// One summary line per collector module listed in the manifest.
    pub modules: Vec<String>,
    pub container_sha256: String,
    pub expected_sha256: Option<String>,
    pub expected_source: Option<String>,
    pub container_verified: Option<bool>,
    pub case_id: String,
    pub demo_mode: bool,
    pub warnings: Vec<String>,
}

/// Structured negative result (§7): expected format, detected format,
/// AIF version if detected, reason, file path, offset where relevant.
#[derive(Clone, Debug)]
pub struct ValidationFailure {
    pub path: PathBuf,
    pub expected_format: String,
    pub detected_format: String,
    pub detected_version: Option<u32>,
    pub reason: String,
    pub offset: Option<u64>,
}

pub const EXPECTED_FORMAT: &str =
    "AIF v1 ZIP container (local-file-header signature PK\\x03\\x04), contract in docs/AIF-SPEC.md";

/// Collector-side notices that reflect the acquired host's capabilities
/// (no GPU telemetry, absent/empty optional event channels) rather than
/// integrity problems with the evidence. These are normal on many
/// hosts and are presented as informational notes, not alarms.
pub fn is_host_capability_note(warning: &str) -> bool {
    [
        "Win32_VideoController",
        "GPU",
        "TaskScheduler",
        "Sysmon",
        "not installed",
        "No events were found",
        "query failed",
        "skipped",
    ]
    .iter()
    .any(|m| warning.contains(m))
}

/// Plain-language explanation for known host-capability notes so the
/// examiner understands they are expected and harmless.
pub fn host_capability_explanation(warning: &str) -> Option<&'static str> {
    if warning.contains("Win32_VideoController") || warning.contains("GPU") {
        Some("the acquired host exposes no GPU telemetry — GPU-dependent checks are skipped.")
    } else if warning.contains("Sysmon") {
        Some("Sysmon was not installed on the acquired host — this channel is optional.")
    } else if warning.contains("TaskScheduler") {
        Some("the scheduled-task event channel was empty or unavailable on the acquired host.")
    } else {
        None
    }
}

/// Classify a file's leading bytes for the "detected format" field.
fn detect_format(path: &Path) -> String {
    use std::io::Read;
    let mut head = [0u8; 16];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    if n < 4 {
        return format!("empty or truncated file ({n} readable byte(s))");
    }
    if &head[..4] == [0x50, 0x4B, 0x03, 0x04] {
        return "ZIP container (PK\\x03\\x04 local-file header)".to_string();
    }
    let text: &str = std::str::from_utf8(&head[..n]).unwrap_or("");
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return "plain JSON text (legacy export — not an AIF container)".to_string();
    }
    format!(
        "unrecognized binary header ({:02X} {:02X} {:02X} {:02X})",
        head[0], head[1], head[2], head[3]
    )
}

/// Validate one candidate evidence file without deep per-artifact
/// verification or stream decoding. Fast enough to run before the
/// examiner commits to a full ingest.
pub fn validate_image(path: &Path) -> Result<ValidationReport, ValidationFailure> {
    let make_failure = |detected_format: String, reason: String, offset: Option<u64>| {
        ValidationFailure {
            path: path.to_path_buf(),
            expected_format: EXPECTED_FORMAT.to_string(),
            detected_format,
            detected_version: None,
            reason,
            offset,
        }
    };

    let header_format = detect_format(path);
    let aif = match open_aif(path) {
        Ok(aif) => aif,
        Err(e) => {
            let detected = match &e {
                AifOpenError::LooksLikeJson => {
                    "plain JSON text (legacy export — not an AIF container)".to_string()
                }
                AifOpenError::NotZipArchive(_) => {
                    "ZIP signature present but archive is unreadable/corrupt".to_string()
                }
                _ => header_format.clone(),
            };
            return Err(make_failure(detected, e.to_string(), Some(0)));
        }
    };

    let container_check = ContainerCheck::from(&aif);
    let mut warnings = Vec::new();
    match container_check.ok {
        Some(false) => warnings.push(format!(
            "CONTAINER HASH MISMATCH: calculated {} but {} records {}.",
            container_check.calculated,
            container_check.expected_source.as_deref().unwrap_or("sidecar"),
            container_check.expected.as_deref().unwrap_or("?")
        )),
        None => warnings.push(
            "No external container hash (.AIF.sha256 / custody sidecar) found next to the file."
                .to_string(),
        ),
        Some(true) => {}
    }
    for w in &aif.manifest.warnings {
        warnings.push(format!("Collector warning: {w}"));
    }
    for e in &aif.manifest.errors {
        warnings.push(format!("Collector error: {e}"));
    }

    let modules = aif
        .manifest
        .modules
        .iter()
        .map(|m| {
            let name = if m.module_name.is_empty() { &m.module_id } else { &m.module_name };
            format!("{name} — {}", if m.status.is_empty() { "unknown status" } else { &m.status })
        })
        .collect();

    let demo_mode = aif.case_doc.case.demo_mode
        || aif.manifest.artifacts.iter().any(|a| a.synthetic);

    Ok(ValidationReport {
        path: path.to_path_buf(),
        size_bytes: aif.size_bytes,
        detected_format: "ZIP container (PK\\x03\\x04)".to_string(),
        aif_version: aif.case_doc.format_version,
        entry_count: aif.entry_names.len(),
        artifact_count: aif.manifest.artifacts.len(),
        modules,
        container_sha256: aif.container_sha256.clone(),
        expected_sha256: container_check.expected.clone(),
        expected_source: container_check.expected_source.clone(),
        container_verified: container_check.ok,
        case_id: aif.manifest.case_id.clone(),
        demo_mode,
        warnings,
    })
}

/// Ingest one AIF evidence image end-to-end.
pub fn examine_image(path: &Path) -> Result<ExaminedCase, String> {
    examine_image_progress(path, None)
}

/// Ingest with optional live progress reporting (one short status line
/// per real pipeline step — never simulated progress).
pub fn examine_image_progress(
    path: &Path,
    progress: Option<&std::sync::mpsc::Sender<String>>,
) -> Result<ExaminedCase, String> {
    let report = |msg: &str| {
        if let Some(tx) = progress {
            let _ = tx.send(msg.to_string());
        }
    };
    let mut log = Vec::new();
    let mut warnings = Vec::new();

    report("Opening & validating AIF container (streaming SHA-256)…");
    log.push(format!("Opening evidence image {}", path.display()));
    let mut aif = open_aif(path).map_err(|e| e.to_string())?;
    log.push(format!(
        "AIF v{} container detected ({} bytes, {} entries)",
        aif.case_doc.format_version,
        aif.size_bytes,
        aif.entry_names.len()
    ));

    log.push(format!("Container SHA-256: {}", aif.container_sha256));
    let container_check = ContainerCheck::from(&aif);
    match container_check.ok {
        Some(true) => log.push(format!(
            "Container hash VERIFIED against {}",
            container_check.expected_source.as_deref().unwrap_or("sidecar")
        )),
        Some(false) => warnings.push(format!(
            "CONTAINER HASH MISMATCH: calculated {} but {} records {}. The evidence image may have been modified after acquisition.",
            container_check.calculated,
            container_check.expected_source.as_deref().unwrap_or("sidecar"),
            container_check.expected.as_deref().unwrap_or("?")
        )),
        None => warnings.push(
            "No external container hash (.AIF.sha256 / custody sidecar) found — container integrity could not be independently verified.".into(),
        ),
    }

    log.push(format!(
        "manifest.json parsed: case {}, {} artifact record(s)",
        aif.manifest.case_id,
        aif.manifest.artifacts.len()
    ));
    log.push("Deep integrity verification (per-artifact SHA-256)…".into());
    let total = aif.manifest.artifacts.len();
    report(&format!("Deep-verifying {total} artifact hash(es)…"));
    let artifact_checks = deep_verify_progress(&mut aif, progress);
    let failed = artifact_checks.iter().filter(|c| !c.ok).count();
    if failed == 0 {
        log.push(format!("All {} artifact hashes verified OK", artifact_checks.len()));
    } else {
        warnings.push(format!(
            "{failed} artifact(s) failed SHA-256 verification or are missing from the container."
        ));
        log.push(format!("WARNING: {failed} artifact hash problem(s)"));
    }

    let has_entry = |p: &str| aif.has_entry(p);
    let artifacts = build_index(&aif.manifest, &has_entry, &artifact_checks);
    let tree = EvidenceTree::build(&artifacts);
    report("Evidence index built.");
    log.push(format!(
        "Evidence index built: {} artifacts in {} stream categor(ies)",
        tree.total_artifacts,
        tree.categories.len()
    ));

    // Manifest warnings/errors carry collector-side caveats.
    for w in &aif.manifest.warnings {
        warnings.push(format!("Collector warning: {w}"));
    }
    for e in &aif.manifest.errors {
        warnings.push(format!("Collector error: {e}"));
    }

    let mut exam = ExaminedCase {
        image_name: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("evidence.aif")
            .to_string(),
        image_path: path.to_path_buf(),
        size_bytes: aif.size_bytes,
        manifest: aif.manifest.clone(),
        case_doc: aif.case_doc.clone(),
        custody: aif.custody.clone(),
        container_check,
        artifact_checks,
        artifacts,
        tree,
        streams: DecodedStreams::default(),
        field_index: Vec::new(),
        ingest_log: Vec::new(),
        warnings,
        aif,
    };
    log.push("Decoding evidence streams…".into());
    report("Decoding evidence streams…");
    decode_streams(&mut exam);
    exam.ingest_log = log;
    report("Ingest complete.");
    Ok(exam)
}

/// Decode every known stream from the container entries. Unknown or
/// malformed entries are reported as warnings, never invented around.
fn decode_streams(exam: &mut ExaminedCase) {
    // Collect targets first so the archive borrow can be mutable.
    let targets: Vec<(String, String)> = exam
        .manifest
        .artifacts
        .iter()
        .map(|a| (a.artifact_id.clone(), a.relative_path.clone()))
        .collect();

    let mut sys = SystemStream::default();
    let mut cpu = CpuStream::default();
    let mut gpu = GpuStream::default();
    let mut proc = ProcessStream::default();
    let mut net = NetworkStream::default();
    let mut events = EventStream::default();
    let mut persist = PersistenceStream::default();
    let mut registry = RegistryStream::default();
    let mut hashes: Option<Vec<HashEntry>> = None;
    let mut os_doc: Option<OsDoc> = None;
    let mut memory_present = false;
    // Raw XML exports awaiting channel attachment after the loop.
    let mut raw_xml: Vec<(String, String, Vec<RawXmlEvent>)> = Vec::new();
    let fi = &mut exam.field_index;

    let mut seen_sys = false;
    let mut seen_cpu = false;
    let mut seen_gpu = false;
    let mut seen_proc = false;
    let mut seen_net = false;
    let mut seen_events = false;
    let mut seen_persist = false;
    let mut seen_registry = false;

    for (artifact_id, entry) in targets {
        let lower = entry.to_ascii_lowercase();
        let bytes = match exam.aif.read_entry(&entry) {
            Ok(b) => b,
            Err(e) => {
                exam.warnings.push(e);
                continue;
            }
        };

        let result: Result<(), String> = (|| {
            if lower == "processes/process_list.json" {
                proc.processes = decode_json::<Vec<ProcessEntry>>(&bytes, &entry)?;
                proc.list_artifact = Some(artifact_id.clone());
                seen_proc = true;
                for (i, p) in proc.processes.iter().enumerate() {
                    let pre = format!("processes[{i}]");
                    push_field(fi, &artifact_id, &format!("{pre}.pid"), &p.pid.to_string());
                    push_field(fi, &artifact_id, &format!("{pre}.name"), &p.name);
                    if !p.command_line.is_empty() {
                        push_field(fi, &artifact_id, &format!("{pre}.command_line"), &p.command_line);
                    }
                    if let Some(path) = &p.executable_path {
                        push_field(fi, &artifact_id, &format!("{pre}.executable_path"), path);
                    }
                    if let Some(user) = &p.user {
                        push_field(fi, &artifact_id, &format!("{pre}.user"), user);
                    }
                }
            } else if lower == "processes/process_tree.json" {
                #[derive(serde::Deserialize)]
                struct TreeDoc {
                    #[serde(default)]
                    tree: Vec<ProcessTreeNode>,
                }
                proc.tree = decode_json::<TreeDoc>(&bytes, &entry)?.tree;
            } else if lower == "processes/modules.json" {
                let v = decode_raw(&bytes, &entry)?;
                proc.loaded_module_count = count_module_entries(&v);
            } else if lower == "processes/executable_paths.json" {
                proc.executable_paths = parse_executable_paths(&bytes)
                    .map_err(|e| format!("'{entry}' could not be decoded: {e}"))?;
                proc.executable_paths_present = true;
                proc.executable_paths_artifact = Some(artifact_id.clone());
                seen_proc = true;
                for (i, e) in proc.executable_paths.iter().enumerate() {
                    push_field(fi, &artifact_id, &format!("executable_paths[{i}].pid"), &e.pid.to_string());
                    push_field(fi, &artifact_id, &format!("executable_paths[{i}].path"), &e.path);
                }
            } else if lower == "network/connections.json" {
                let doc: ConnectionsDoc = decode_json(&bytes, &entry)?;
                net.connections = doc.connections;
                net.connections_artifact = Some(artifact_id.clone());
                seen_net = true;
                for (i, c) in net.connections.iter().enumerate() {
                    let pre = format!("connections[{i}]");
                    push_field(fi, &artifact_id, &format!("{pre}.protocol"), &c.protocol);
                    push_field(fi, &artifact_id, &format!("{pre}.local"), &format!("{}:{}", c.local_address, c.local_port));
                    push_field(fi, &artifact_id, &format!("{pre}.remote"), &format!("{}:{}", c.remote_address, c.remote_port));
                    push_field(fi, &artifact_id, &format!("{pre}.state"), &c.state);
                    push_field(fi, &artifact_id, &format!("{pre}.process"), &c.process);
                    push_field(fi, &artifact_id, &format!("{pre}.pid"), &c.pid.to_string());
                }
            } else if lower == "network/interfaces.json" {
                let doc: InterfacesDoc = decode_json(&bytes, &entry)?;
                net.interfaces = doc.interfaces;
                net.interfaces_artifact = Some(artifact_id.clone());
                seen_net = true;
                for (i, n) in net.interfaces.iter().enumerate() {
                    push_field(fi, &artifact_id, &format!("interfaces[{i}].name"), &n.name);
                    push_field(fi, &artifact_id, &format!("interfaces[{i}].mac_address"), &n.mac_address);
                }
            } else if lower == "network/dns.json" {
                #[derive(serde::Deserialize)]
                struct DnsDoc {
                    #[serde(default)]
                    entries: Vec<streams::DnsAdapterEntry>,
                }
                net.dns_adapters = decode_json::<DnsDoc>(&bytes, &entry)?.entries;
                seen_net = true;
                for (i, d) in net.dns_adapters.iter().enumerate() {
                    push_field(fi, &artifact_id, &format!("dns[{i}].adapter"), &d.adapter);
                    if let Some(domain) = &d.dns_domain {
                        push_field(fi, &artifact_id, &format!("dns[{i}].dns_domain"), domain);
                    }
                    for (s, server) in d.dns_servers.iter().enumerate() {
                        push_field(fi, &artifact_id, &format!("dns[{i}].dns_servers[{s}]"), server);
                    }
                }
            } else if lower == "network/adapters.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                net.adapters_raw = Some(v);
                seen_net = true;
            } else if lower == "network/routes.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                net.routes_raw = Some(v);
                seen_net = true;
            } else if lower == "network/arp.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                net.arp_raw = Some(v);
                seen_net = true;
            } else if lower.starts_with("windows_events/") && lower.ends_with("/events_raw.xml") {
                let raws = parse_raw_xml_events(&bytes)
                    .map_err(|e| format!("'{entry}' could not be decoded: {e}"))?;
                for (i, r) in raws.iter().enumerate() {
                    let pre = format!("events_raw[{i}]");
                    push_field(fi, &artifact_id, &format!("{pre}.event_id"), &r.event_id);
                    push_field(fi, &artifact_id, &format!("{pre}.provider"), &r.provider);
                    push_field(fi, &artifact_id, &format!("{pre}.time_created"), &r.time_created);
                    for (name, value) in &r.data {
                        let key = if name.is_empty() { format!("{pre}.data") } else { format!("{pre}.data.{name}") };
                        push_field(fi, &artifact_id, &key, value);
                    }
                }
                raw_xml.push((entry.clone(), artifact_id.clone(), raws));
                seen_events = true;
            } else if lower.starts_with("windows_events/") && lower.ends_with("/events.json") {
                let doc: EventsDoc = decode_json(&bytes, &entry)?;
                let label = event_channel_label(&entry);
                events.total_events += doc.event_count;
                for (i, e) in doc.events.iter().enumerate() {
                    let pre = format!("events[{i}]");
                    push_field(fi, &artifact_id, &format!("{pre}.event_id"), &e.event_id.to_string());
                    push_field(fi, &artifact_id, &format!("{pre}.provider"), &e.provider);
                    push_field(fi, &artifact_id, &format!("{pre}.level"), &e.level);
                    push_field(fi, &artifact_id, &format!("{pre}.time_created"), &e.time_created);
                    push_field(fi, &artifact_id, &format!("{pre}.message"), &e.message);
                }
                events.channels.push(EventChannel {
                    label,
                    entry_path: entry.clone(),
                    artifact_id: Some(artifact_id),
                    event_count: doc.event_count,
                    events: doc.events,
                    raw_events: Vec::new(),
                    raw_artifact_id: None,
                });
                seen_events = true;
            } else if lower == "persistence/registry_runs.json" {
                let doc: RegistryRunsDoc = decode_json(&bytes, &entry)?;
                persist.run_keys = doc.keys;
                persist.run_keys_artifact = Some(artifact_id.clone());
                seen_persist = true;
                for (i, key) in persist.run_keys.iter().enumerate() {
                    push_field(fi, &artifact_id, &format!("run_keys[{i}].hive"), &key.hive);
                    push_field(fi, &artifact_id, &format!("run_keys[{i}].key_path"), &key.key_path);
                    for (v, value) in key.values.iter().enumerate() {
                        push_field(fi, &artifact_id, &format!("run_keys[{i}].values[{v}].value_name"), &value.value_name);
                        push_field(fi, &artifact_id, &format!("run_keys[{i}].values[{v}].data"), &value.data);
                    }
                }
            } else if lower == "persistence/services.json" {
                let doc: ServicesDoc = decode_json(&bytes, &entry)?;
                persist.services = doc.services;
                persist.services_artifact = Some(artifact_id.clone());
                seen_persist = true;
                for (i, s) in persist.services.iter().enumerate() {
                    push_field(fi, &artifact_id, &format!("services[{i}].name"), &s.name);
                    push_field(fi, &artifact_id, &format!("services[{i}].display_name"), &s.display_name);
                }
            } else if lower == "persistence/scheduled_tasks.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                persist.scheduled_tasks_raw = Some(v);
                seen_persist = true;
            } else if lower == "persistence/startup.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                persist.startup_raw = Some(v);
                seen_persist = true;
            } else if lower == "persistence/wmi_subscriptions.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                persist.wmi_subscriptions_raw = Some(v);
                seen_persist = true;
            } else if lower == "persistence/logon_and_other.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                persist.logon_raw = Some(v);
                seen_persist = true;
            } else if lower == "hashes/hashes.json" {
                let records = parse_hashes(&bytes)?;
                for (i, h) in records.iter().enumerate() {
                    push_field(fi, &artifact_id, &format!("records[{i}].relative_path"), &h.relative_path);
                    push_field(fi, &artifact_id, &format!("records[{i}].sha256"), &h.sha256);
                    push_field(fi, &artifact_id, &format!("records[{i}].source"), &h.source);
                }
                hashes = Some(records);
                exam.streams.hashes_artifact = Some(artifact_id.clone());
            } else if lower == "cpu/cpu_metadata.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                cpu.metadata = Some(
                    serde_json::from_value::<streams::CpuMetadataDoc>(v.clone())
                        .map_err(|e| format!("'{entry}' could not be decoded: {e}"))?,
                );
                seen_cpu = true;
            } else if lower == "cpu/topology.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                cpu.topology_raw = Some(v);
                seen_cpu = true;
            } else if lower == "cpu/wmi_processors.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                cpu.wmi_processors_raw = Some(v);
                seen_cpu = true;
            } else if lower == "gpu/gpu_metadata.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                gpu.metadata_raw = Some(v);
                seen_gpu = true;
            } else if lower == "gpu/gpu_processes.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                gpu.gpu_processes = Some(
                    serde_json::from_value::<streams::GpuProcessesDoc>(v.clone())
                        .map_err(|e| format!("'{entry}' could not be decoded: {e}"))?,
                );
                gpu.gpu_processes_artifact = Some(artifact_id.clone());
                seen_gpu = true;
            } else if lower == "gpu/compute_metadata.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                gpu.compute_raw = Some(v);
                seen_gpu = true;
            } else if lower == "gpu/driver_files.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                gpu.driver_files_raw = Some(v);
                seen_gpu = true;
            } else if lower == "system/os.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                os_doc = Some(
                    serde_json::from_value::<OsDoc>(v.clone())
                        .map_err(|e| format!("'{entry}' could not be decoded: {e}"))?,
                );
                sys.os_raw = Some(v);
                seen_sys = true;
            } else if lower == "system/disks.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                sys.disks_raw = Some(v);
                seen_sys = true;
            } else if lower == "system/environment.json" {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                sys.environment_raw = Some(v);
                seen_sys = true;
            } else if lower.starts_with("system/wmi_") {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                sys.wmi_raw.push((entry.clone(), v));
                seen_sys = true;
            } else if lower.starts_with("registry/artifacts/") {
                let v = decode_raw(&bytes, &entry)?;
                index_json_value(fi, &artifact_id, "", &v, 0);
                registry.artifacts.push((entry.clone(), v));
                seen_registry = true;
            } else if lower.starts_with("memory/") {
                memory_present = true;
            }
            Ok(())
        })();

        if let Err(e) = result {
            exam.warnings.push(format!("Stream decode problem: {e}"));
        }
    }

    // Attach raw XML exports to their channels (§15 raw event data).
    // Manifest ordering may place events_raw.xml before its events.json.
    for (entry, artifact, raws) in raw_xml {
        let dir = channel_dir(&entry);
        if let Some(ch) = events.channels.iter_mut().find(|c| channel_dir(&c.entry_path) == dir) {
            ch.raw_events = raws;
            ch.raw_artifact_id = Some(artifact);
        } else {
            let count = raws.len() as u32;
            events.total_events += count;
            events.channels.push(EventChannel {
                label: event_channel_label(&entry),
                entry_path: entry,
                artifact_id: None,
                event_count: count,
                events: Vec::new(),
                raw_events: raws,
                raw_artifact_id: Some(artifact),
            });
        }
    }

    exam.streams.system = seen_sys.then_some(sys);
    exam.streams.os = os_doc;
    exam.streams.cpu = seen_cpu.then_some(cpu);
    exam.streams.gpu = seen_gpu.then_some(gpu);
    exam.streams.memory_present = memory_present;
    exam.streams.processes = seen_proc.then_some(proc);
    exam.streams.network = seen_net.then_some(net);
    exam.streams.events = seen_events.then_some(events);
    exam.streams.persistence = seen_persist.then_some(persist);
    exam.streams.registry = seen_registry.then_some(registry);
    exam.streams.hashes = hashes;
}

fn count_module_entries(v: &Value) -> usize {
    // Preferred: {processes: {pid: [module, ...]}} — sum all module arrays.
    if let Some(map) = v.get("processes").and_then(|p| p.as_object()) {
        let total: usize = map
            .values()
            .map(|m| m.as_array().map(|a| a.len()).unwrap_or(0))
            .sum();
        if total > 0 {
            return total;
        }
    }
    // Fallbacks: bare array or first array-valued field.
    if let Some(arr) = v.as_array() {
        return arr.len();
    }
    if let Some(obj) = v.as_object() {
        for (_, value) in obj {
            if let Some(arr) = value.as_array() {
                return arr.len();
            }
        }
    }
    0
}

/// "windows_events/other/defender/events.json" -> "Defender (other)".
/// Also works for `events_raw.xml` entries (see `channel_dir`).
fn event_channel_label(entry: &str) -> String {
    let trimmed = channel_dir(entry);
    let parts: Vec<&str> = trimmed.split('/').collect();
    match parts.as_slice() {
        [name] => capitalize(name),
        [group, name] => format!("{} ({})", capitalize(name), group),
        _ => trimmed.to_string(),
    }
}

/// Channel directory inside `windows_events/`, independent of the
/// concrete file name (events.json and events_raw.xml pair up).
fn channel_dir(entry: &str) -> String {
    entry
        .trim_start_matches("windows_events/")
        .trim_end_matches("/events.json")
        .trim_end_matches("/events_raw.xml")
        .to_string()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Count `<Event ` / `<Event>` open tags in raw export bytes (the
/// `<EventID>` child tag must not count). Used by tests to prove the
/// parser never drops records.
fn count_event_open_tags(bytes: &[u8]) -> usize {
    bytes
        .windows(7)
        .filter(|w| w == b"<Event " || w == b"<Event>")
        .count()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const REAL_AIF: &str = r"E:\Desktop\thE rEAL\CASE-2026-1070.AIF";

    /// Shared helper: ingest the reference case when it is present.
    pub fn real_exam_if_available() -> Option<ExaminedCase> {
        let path = Path::new(REAL_AIF);
        if !path.is_file() {
            return None;
        }
        Some(examine_image(path).expect("ingest real case"))
    }

    #[test]
    fn real_case_ingests_all_streams() {
        let path = Path::new(REAL_AIF);
        if !path.is_file() {
            eprintln!("sample AIF not present - skipping");
            return;
        }
        let mut exam = examine_image(path).expect("ingest real case");
        assert_eq!(exam.case_id(), "CASE-2026-1070");
        assert!(!exam.is_demo());
        assert_eq!(exam.failed_verifications(), 0);

        // Evidence tree contains the real streams.
        let keys: Vec<&str> = exam.tree.categories.iter().map(|c| c.key).collect();
        for expected in ["system", "cpu", "gpu", "processes", "network", "windows_events", "persistence", "registry", "hashes"] {
            assert!(keys.contains(&expected), "tree missing {expected}: {keys:?}");
        }
        // Memory was not acquired in this case -> honest absence.
        assert!(!exam.streams.memory_present);
        assert!(exam.streams.hashes.as_ref().is_some());

        let procs = exam.streams.processes.as_ref().expect("process stream");
        assert!(procs.processes.len() > 100, "expected full process list");
        assert!(procs.loaded_module_count > 0);
        assert!(!procs.tree.is_empty());
        // Pulled-forward decoder: executable_paths.json exists and decodes.
        // The collector recorded an empty list here — the honest result
        // is "present but zero mappings", not an invented table.
        assert!(procs.executable_paths_present);
        assert!(procs.executable_paths.is_empty());
        assert!(procs.executable_paths_artifact.is_some());

        let net = exam.streams.network.as_ref().expect("network stream");
        assert!(net.connections.iter().any(|c| c.process.eq_ignore_ascii_case("AnyDesk.exe")));
        // Pulled-forward decoder: interfaces.json adapter statistics.
        assert!(!net.interfaces.is_empty(), "interfaces.json decoded");
        assert!(net.interfaces.iter().any(|i| !i.mac_address.is_empty()));
        assert!(net.interfaces_artifact.is_some());

        let events = exam.streams.events.as_ref().expect("events stream");
        assert!(events.channels.len() >= 5);
        assert!(events.total_events > 1000);
        // Pulled-forward decoder: events_raw.xml attached to its channel.
        // The reference case carries exactly 6 channels, each with a
        // raw XML export (collector-side capped at 500 records each).
        assert_eq!(events.channels.len(), 6, "six event channels expected");
        for channel in &events.channels {
            assert!(
                channel.raw_artifact_id.is_some(),
                "channel '{}' has no raw XML artifact attached",
                channel.label
            );
            assert!(
                !channel.raw_events.is_empty(),
                "channel '{}' raw XML decoded to zero events",
                channel.label
            );
        }
        // No silent truncation: parsed record count equals the number of
        // `<Event `/`<Event>` open tags physically present in each export.
        for channel in &events.channels {
            let Some(raw_id) = &channel.raw_artifact_id else { continue };
            let raw_path = exam
                .artifact_by_id(raw_id)
                .map(|a| a.relative_path.clone())
                .expect("raw XML artifact indexed");
            let raw_bytes = exam.aif.read_entry(&raw_path).expect("raw XML readable");
            let tag_count = count_event_open_tags(&raw_bytes);
            assert_eq!(
                channel.raw_events.len(),
                tag_count,
                "channel '{}': parsed {} of {} raw events",
                channel.label,
                channel.raw_events.len(),
                tag_count
            );
        }

        // §21: the field index is built and searchable across streams.
        assert!(!exam.field_index.is_empty());
        assert!(exam
            .field_index
            .iter()
            .any(|f| f.value.to_ascii_lowercase().contains("anydesk")));

        let persist = exam.streams.persistence.as_ref().expect("persistence stream");
        assert!(!persist.run_keys.is_empty());
        assert!(!persist.services.is_empty());

        // Traceability: every indexed artifact points to a real entry.
        for a in &exam.artifacts {
            assert!(a.present, "artifact {} entry missing", a.artifact_id);
            assert_eq!(a.hash_verified, Some(true), "artifact {} hash", a.artifact_id);
        }
    }

    #[test]
    fn absent_streams_stay_none() {
        let path = build_minimal_aif();
        let exam = examine_image(&path).expect("minimal case ingests");
        assert!(exam.streams.system.is_some());
        assert!(exam.streams.processes.is_none());
        assert!(exam.streams.network.is_none());
        assert!(exam.streams.events.is_none());
        assert!(exam.streams.hashes.is_none());
        assert!(!exam.streams.memory_present);
        // The tree must not contain categories without evidence.
        let keys: Vec<&str> = exam.tree.categories.iter().map(|c| c.key).collect();
        assert_eq!(keys, vec!["system"]);
    }

    /// Build a one-artifact AIF container for deterministic tests.
    fn build_minimal_aif() -> PathBuf {
        use std::io::Write;
        use zip::write::FileOptions;
        use zip::ZipWriter;

        let dir = std::env::temp_dir().join("neuroforensics_ingest_tests").join("minimal");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("MINIMAL.AIF");
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = FileOptions::default();

        let body = r#"{"os_name":"Windows","hostname":"X"}"#;
        let manifest = format!(
            r#"{{"case_id":"MIN","case_name":"M","artifacts":[{{
                "artifact_id":"ART-000001","relative_path":"system/os.json","size":{},
                "sha256":"{}","acquisition_time":"t","source":"s","collector":"system",
                "status":"ACQUIRED"}}]}}"#,
            body.len(),
            {
                use sha2::Digest;
                let mut h = sha2::Sha256::new();
                h.update(body.as_bytes());
                hex::encode(h.finalize())
            }
        );
        zip.start_file("case.json", opts).unwrap();
        zip.write_all(br#"{"format":"AIF","format_version":1,"case":{"case_id":"MIN","case_name":"M","investigator_name":"","organization":"","evidence_description":"","acquisition_notes":"","destination":"","demo_mode":false,"created_at":""},"container_sha256":null}"#).unwrap();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();
        zip.start_file("system/os.json", opts).unwrap();
        zip.write_all(body.as_bytes()).unwrap();
        zip.finish().unwrap();
        path
    }

    #[test]
    fn validation_accepts_minimal_aif() {
        let path = build_minimal_aif();
        let report = validate_image(&path).expect("minimal AIF validates");
        assert_eq!(report.aif_version, 1);
        assert_eq!(report.artifact_count, 1);
        assert!(report.detected_format.contains("ZIP"));
        assert_eq!(report.case_id, "MIN");
        assert!(!report.demo_mode);
        // No sidecar next to a temp file: honest "not verifiable".
        assert_eq!(report.container_verified, None);
        assert!(report.warnings.iter().any(|w| w.contains("No external container hash")));
    }

    #[test]
    fn validation_rejects_plain_json_with_structured_fields() {
        let dir = std::env::temp_dir().join("neuroforensics_ingest_tests").join("invalid");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.json.AIF");
        std::fs::write(&path, br#"{"case_id":"LEGACY","artifacts":[]}"#).unwrap();

        let failure = validate_image(&path).expect_err("JSON must be rejected");
        assert!(failure.detected_format.contains("JSON"), "{}", failure.detected_format);
        assert!(failure.expected_format.contains("AIF v1"));
        assert_eq!(failure.detected_version, None);
        assert_eq!(failure.offset, Some(0));
        assert_eq!(failure.path, path);
        assert!(!failure.reason.is_empty());
    }

    #[test]
    fn validation_rejects_unknown_binary() {
        let dir = std::env::temp_dir().join("neuroforensics_ingest_tests").join("binary");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("noise.AIF");
        std::fs::write(&path, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]).unwrap();

        let failure = validate_image(&path).expect_err("binary noise must be rejected");
        assert!(failure.detected_format.contains("DE AD BE EF"), "{}", failure.detected_format);
        assert_eq!(failure.offset, Some(0));
    }

    #[test]
    fn validation_passes_real_case() {
        let path = Path::new(REAL_AIF);
        if !path.is_file() {
            eprintln!("sample AIF not present - skipping");
            return;
        }
        let report = validate_image(path).expect("real AIF validates");
        assert_eq!(report.aif_version, 1);
        assert_eq!(report.case_id, "CASE-2026-1070");
        assert!(report.artifact_count > 0);
        assert!(!report.modules.is_empty());
        // The reference case ships with its sidecar hash present.
        assert!(report.container_verified.is_some());
    }
}
