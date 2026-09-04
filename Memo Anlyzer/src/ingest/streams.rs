//! Typed decoders for the evidence streams inside a real AIF container.
//!
//! Every decoder maps one collector output file to a typed view. When a
//! stream is absent from the container the corresponding view is
//! `None` and the UI displays "Not present in evidence" — nothing is
//! ever generated to fill the gap.

use serde::Deserialize;
use serde_json::Value;

// The collector writes `null` for values it could not capture; every
// typed field must tolerate that instead of failing the whole stream.

fn null_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let v: Option<String> = Option::deserialize(d)?;
    Ok(v.unwrap_or_default())
}

macro_rules! null_num {
    ($name:ident, $t:ty) => {
        #[allow(dead_code)]
        fn $name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
            let v: Option<$t> = Option::deserialize(d)?;
            Ok(v.unwrap_or_default())
        }
    };
}
null_num!(null_u16, u16);
null_num!(null_u32, u32);
null_num!(null_u64, u64);
null_num!(null_i64, i64);
null_num!(null_f64, f64);

// ---------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProcessEntry {
    #[serde(default, deserialize_with = "null_i64")]
    pub pid: i64,
    #[serde(default, deserialize_with = "null_string")]
    pub name: String,
    #[serde(default)]
    pub parent_pid: Option<i64>,
    #[serde(default, deserialize_with = "null_string")]
    pub command_line: String,
    #[serde(default)]
    pub executable_path: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default, deserialize_with = "null_f64")]
    pub cpu_usage_percent: f64,
    #[serde(default, deserialize_with = "null_u64")]
    pub memory_bytes: u64,
    #[serde(default, deserialize_with = "null_u64")]
    pub virtual_memory_bytes: u64,
    #[serde(default, deserialize_with = "null_u32")]
    pub thread_count: u32,
    #[serde(default)]
    pub handle_count: Option<u32>,
    #[serde(default)]
    pub integrity_level: Option<String>,
    #[serde(default, deserialize_with = "null_string")]
    pub status: String,
    #[serde(default, deserialize_with = "null_string")]
    pub start_time_rfc3339: String,
    #[serde(default, deserialize_with = "null_i64")]
    pub start_time_unix: i64,
    #[serde(default, deserialize_with = "null_i64")]
    pub run_time_seconds: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProcessTreeNode {
    #[serde(default)]
    pub pid: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub children: Vec<ProcessTreeNode>,
}

#[derive(Clone, Debug, Default)]
pub struct ProcessStream {
    pub list_artifact: Option<String>,
    pub processes: Vec<ProcessEntry>,
    pub tree: Vec<ProcessTreeNode>,
    pub loaded_module_count: usize,
    /// Decoded `processes/executable_paths.json` (pid → executable path).
    pub executable_paths: Vec<ExecutablePathEntry>,
    /// True when the file existed, even if empty — distinguishes
    /// "acquired and empty" from "not present in evidence".
    pub executable_paths_present: bool,
    pub executable_paths_artifact: Option<String>,
}

/// One pid → executable path mapping. The collector's exact key names
/// are not contractually pinned, so decoding is lenient (see
/// `parse_executable_paths`).
#[derive(Clone, Debug)]
pub struct ExecutablePathEntry {
    pub pid: i64,
    pub path: String,
}

/// Lenient decoder for `executable_paths.json`: tolerates an array of
/// `{pid, path}`-like objects or a `{ "<pid>": "<path>" }` map. Never
/// invents entries — unknown shapes yield an empty list.
pub fn parse_executable_paths(bytes: &[u8]) -> Result<Vec<ExecutablePathEntry>, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let pid_of = |obj: &serde_json::Map<String, Value>| -> Option<i64> {
        for key in ["pid", "process_id", "Pid", "PID"] {
            if let Some(n) = obj.get(key).and_then(|v| v.as_i64()) {
                return Some(n);
            }
        }
        None
    };
    let path_of = |obj: &serde_json::Map<String, Value>| -> Option<String> {
        for key in ["path", "executable_path", "image_path", "exe", "Path"] {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                return Some(s.to_string());
            }
        }
        None
    };
    match &v {
        Value::Array(items) => {
            for item in items {
                if let Some(obj) = item.as_object() {
                    if let (Some(pid), Some(path)) = (pid_of(obj), path_of(obj)) {
                        out.push(ExecutablePathEntry { pid, path });
                    }
                }
            }
        }
        Value::Object(map) => {
            // A wrapper object may hold the array under any key, or be a
            // direct pid → path map.
            let mut found_array = false;
            for (_, value) in map {
                if let Some(items) = value.as_array() {
                    found_array = true;
                    for item in items {
                        if let Some(obj) = item.as_object() {
                            if let (Some(pid), Some(path)) = (pid_of(obj), path_of(obj)) {
                                out.push(ExecutablePathEntry { pid, path });
                            }
                        }
                    }
                }
            }
            if !found_array {
                for (key, value) in map {
                    if let (Ok(pid), Some(path)) = (key.parse::<i64>(), value.as_str()) {
                        out.push(ExecutablePathEntry { pid, path: path.to_string() });
                    }
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct ConnectionEntry {
    #[serde(default, deserialize_with = "null_string")]
    pub protocol: String,
    #[serde(default, deserialize_with = "null_string")]
    pub local_address: String,
    #[serde(default, deserialize_with = "null_u16")]
    pub local_port: u16,
    #[serde(default, deserialize_with = "null_string")]
    pub remote_address: String,
    #[serde(default, deserialize_with = "null_u16")]
    pub remote_port: u16,
    #[serde(default, deserialize_with = "null_string")]
    pub state: String,
    #[serde(default, deserialize_with = "null_i64")]
    pub pid: i64,
    #[serde(default, deserialize_with = "null_string")]
    pub process: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConnectionsDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub connections: Vec<ConnectionEntry>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DnsAdapterEntry {
    #[serde(default)]
    pub adapter: String,
    #[serde(default)]
    pub dns_domain: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkStream {
    pub connections: Vec<ConnectionEntry>,
    /// Collector artifact ID behind connections.json (grounding).
    pub connections_artifact: Option<String>,
    pub dns_adapters: Vec<DnsAdapterEntry>,
    /// Decoded `network/interfaces.json` adapter statistics.
    pub interfaces: Vec<InterfaceStat>,
    pub interfaces_artifact: Option<String>,
    /// adapters.json / routes.json / arp.json kept as raw JSON for the
    /// viewer — their exact shape is collector-side detail.
    pub adapters_raw: Option<Value>,
    pub routes_raw: Option<Value>,
    pub arp_raw: Option<Value>,
}

/// One network interface with traffic counters (real collector schema).
#[derive(Clone, Debug, Deserialize)]
pub struct InterfaceStat {
    #[serde(default, deserialize_with = "null_string")]
    pub name: String,
    #[serde(default, deserialize_with = "null_string")]
    pub mac_address: String,
    #[serde(default, deserialize_with = "null_u64")]
    pub total_packets_received: u64,
    #[serde(default, deserialize_with = "null_u64")]
    pub total_packets_transmitted: u64,
    #[serde(default, deserialize_with = "null_u64")]
    pub total_received_bytes: u64,
    #[serde(default, deserialize_with = "null_u64")]
    pub total_transmitted_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InterfacesDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub interfaces: Vec<InterfaceStat>,
}

// ---------------------------------------------------------------------
// Windows events
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct EventEntry {
    #[serde(rename = "EventId", default, deserialize_with = "null_u32")]
    pub event_id: u32,
    #[serde(rename = "Level", default, deserialize_with = "null_string")]
    pub level: String,
    #[serde(rename = "Provider", default, deserialize_with = "null_string")]
    pub provider: String,
    #[serde(rename = "RecordId", default, deserialize_with = "null_u64")]
    pub record_id: u64,
    #[serde(rename = "TimeCreated", default, deserialize_with = "null_string")]
    pub time_created: String,
    #[serde(rename = "Message", default, deserialize_with = "null_string")]
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventsDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub event_count: u32,
    #[serde(default)]
    pub events: Vec<EventEntry>,
}

#[derive(Clone, Debug)]
pub struct EventChannel {
    /// Display label, e.g. "System" or "Defender (Operational)".
    pub label: String,
    /// Entry path inside the container.
    pub entry_path: String,
    pub artifact_id: Option<String>,
    pub events: Vec<EventEntry>,
    pub event_count: u32,
    /// Raw Windows event XML export (`events_raw.xml`) when present.
    pub raw_events: Vec<RawXmlEvent>,
    pub raw_artifact_id: Option<String>,
}

/// One event parsed from the collector's raw XML export.
#[derive(Clone, Debug)]
pub struct RawXmlEvent {
    pub event_id: String,
    pub time_created: String,
    pub provider: String,
    pub level: String,
    /// EventData name/value pairs (order preserved).
    pub data: Vec<(String, String)>,
}

/// Lenient decoder for the collector's `events_raw.xml` export (Windows
/// event XML). Hand-rolled scanning — no XML crate dependency — that
/// only reports what is actually present in the bytes.
pub fn parse_raw_xml_events(bytes: &[u8]) -> Result<Vec<RawXmlEvent>, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = find_event_start(rest) {
        rest = &rest[start..];
        let end = match rest.find("</Event>") {
            Some(pos) => pos + "</Event>".len(),
            None => rest.len(),
        };
        let block = &rest[..end];
        rest = &rest[end.min(rest.len())..];

        let event_id = tag_text(block, "EventID").unwrap_or_default();
        let time_created = tag_attr(block, "TimeCreated", "SystemTime").unwrap_or_default();
        let provider = tag_attr(block, "Provider", "Name").unwrap_or_default();
        let level = tag_text(block, "Level").as_deref().map(level_name).unwrap_or_default();

        let mut data = Vec::new();
        if let Some(ed_start) = block.find("<EventData") {
            let ed_block = &block[ed_start..];
            let ed_end = ed_block.find("</EventData>").unwrap_or(ed_block.len());
            let mut scan = &ed_block[..ed_end];
            while let Some(ds) = scan.find("<Data") {
                scan = &scan[ds..];
                let de = match scan.find("</Data>") {
                    Some(pos) => pos + "</Data>".len(),
                    None => break,
                };
                let item = &scan[..de];
                scan = &scan[de..];
                let name = tag_attr(item, "Data", "Name").unwrap_or_default();
                let value = match item.find('>') {
                    Some(g) => decode_entities(item[g + 1..].trim_end_matches("</Data>").trim()),
                    None => String::new(),
                };
                data.push((name, value));
            }
        }

        out.push(RawXmlEvent { event_id, time_created, provider, level, data });
    }
    Ok(out)
}

/// `<Event ...>` or `<Event>` — the export may or may not carry the
/// XML namespace declaration on the opening tag.
fn find_event_start(s: &str) -> Option<usize> {
    match (s.find("<Event "), s.find("<Event>")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Text content of the first `<tag ...>text</tag>` occurrence.
fn tag_text(s: &str, tag: &str) -> Option<String> {
    let open = s.find(&format!("<{tag}"))?;
    let rest = &s[open..];
    let gt = rest.find('>')?;
    let close = rest.find(&format!("</{tag}>"))?;
    if close < gt {
        return None; // self-closing tag
    }
    Some(decode_entities(rest[gt + 1..close].trim()))
}

/// Value of `<tag ... attr="value" .../>` for the first occurrence.
fn tag_attr(s: &str, tag: &str, attr: &str) -> Option<String> {
    let open = s.find(&format!("<{tag}"))?;
    let rest = &s[open..];
    let gt = rest.find('>')?;
    let head = &rest[..gt];
    for quote in ['"', '\''] {
        let pat = format!("{attr}={quote}");
        if let Some(a) = head.find(&pat) {
            let start = a + pat.len();
            if let Some(b) = head[start..].find(quote) {
                return Some(decode_entities(&head[start..start + b]));
            }
        }
    }
    None
}

fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Windows event XML encodes levels numerically; map to the familiar
/// names, keeping anything unrecognized verbatim.
fn level_name(raw: &str) -> String {
    match raw.trim() {
        "0" => "Critical",
        "1" => "Error",
        "2" => "Warning",
        "3" => "Information",
        "4" => "Verbose",
        other => other,
    }
    .to_string()
}

#[derive(Clone, Debug, Default)]
pub struct EventStream {
    pub channels: Vec<EventChannel>,
    pub total_events: u32,
}

// ---------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct RunValue {
    #[serde(default, deserialize_with = "null_string")]
    pub value_name: String,
    #[serde(default, deserialize_with = "null_string")]
    pub data: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RunKey {
    #[serde(default, deserialize_with = "null_string")]
    pub hive: String,
    #[serde(default, deserialize_with = "null_string")]
    pub key_path: String,
    #[serde(default, deserialize_with = "null_string")]
    pub label: String,
    #[serde(default)]
    pub values: Vec<RunValue>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegistryRunsDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub keys: Vec<RunKey>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceEntry {
    #[serde(rename = "Name", default, deserialize_with = "null_string")]
    pub name: String,
    #[serde(rename = "DisplayName", default, deserialize_with = "null_string")]
    pub display_name: String,
    #[serde(rename = "StartType", default, deserialize_with = "null_u32")]
    pub start_type: u32,
    #[serde(rename = "Status", default, deserialize_with = "null_u32")]
    pub status: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServicesDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub service_count: u32,
    #[serde(default)]
    pub services: Vec<ServiceEntry>,
}

#[derive(Clone, Debug, Default)]
pub struct PersistenceStream {
    pub run_keys: Vec<RunKey>,
    pub services: Vec<ServiceEntry>,
    /// Collector artifact IDs behind the decoded files (grounding).
    pub run_keys_artifact: Option<String>,
    pub services_artifact: Option<String>,
    /// scheduled_tasks / startup / wmi_subscriptions / logon_and_other
    /// kept as raw JSON for the viewer.
    pub scheduled_tasks_raw: Option<Value>,
    pub startup_raw: Option<Value>,
    pub wmi_subscriptions_raw: Option<Value>,
    pub logon_raw: Option<Value>,
}

// ---------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct HashEntry {
    /// Nullable in the collector output for FAILED records.
    #[serde(rename = "SHA256", default, deserialize_with = "null_string")]
    pub sha256: String,
    #[serde(default, deserialize_with = "null_string")]
    pub relative_path: String,
    #[serde(default, deserialize_with = "null_u64")]
    pub size: u64,
    #[serde(default, deserialize_with = "null_string")]
    pub source: String,
    #[serde(default, deserialize_with = "null_string")]
    pub status: String,
    #[serde(default, deserialize_with = "null_string")]
    pub acquisition_time: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HashesDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub records: Vec<HashEntry>,
}

/// hashes.json uses `{records: [...]}` in MEMO Collector v1; tolerate
/// `entries`/bare-array variants as well.
pub fn parse_hashes(bytes: &[u8]) -> Result<Vec<HashEntry>, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    for key in ["records", "entries", "hashes"] {
        if let Some(entries) = v.get(key) {
            return serde_json::from_value(entries.clone()).map_err(|e| e.to_string());
        }
    }
    if v.is_array() {
        return serde_json::from_value(v).map_err(|e| e.to_string());
    }
    if let Some(obj) = v.as_object() {
        for (_, value) in obj {
            if value.is_array() {
                if let Ok(list) = serde_json::from_value::<Vec<HashEntry>>(value.clone()) {
                    return Ok(list);
                }
            }
        }
    }
    Err("hashes.json has an unrecognized structure".into())
}

// ---------------------------------------------------------------------
// CPU / GPU / System
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct CpuMetadataDoc {
    #[serde(default, deserialize_with = "null_string")]
    pub acquired_at: String,
    #[serde(default, deserialize_with = "null_f64")]
    pub global_usage_percent: f64,
    #[serde(default, deserialize_with = "null_u32")]
    pub logical_processor_count: u32,
    #[serde(default, deserialize_with = "null_u32")]
    pub physical_core_count: u32,
    #[serde(default)]
    pub capability_note: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CpuStream {
    pub metadata: Option<CpuMetadataDoc>,
    pub topology_raw: Option<Value>,
    pub wmi_processors_raw: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GpuProcessesDoc {
    #[serde(default)]
    pub acquired_at: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub processes: Vec<Value>,
    #[serde(default)]
    pub source_available: bool,
}

#[derive(Clone, Debug, Default)]
pub struct GpuStream {
    pub metadata_raw: Option<Value>,
    pub gpu_processes: Option<GpuProcessesDoc>,
    /// Collector artifact ID behind gpu_processes.json (§23 grounding).
    pub gpu_processes_artifact: Option<String>,
    pub compute_raw: Option<Value>,
    pub driver_files_raw: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct SystemStream {
    pub os_raw: Option<Value>,
    pub disks_raw: Option<Value>,
    pub environment_raw: Option<Value>,
    pub wmi_raw: Vec<(String, Value)>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OsDoc {
    #[serde(default, deserialize_with = "null_string")]
    pub os_name: String,
    #[serde(default, deserialize_with = "null_string")]
    pub os_version: String,
    #[serde(default, deserialize_with = "null_string")]
    pub hostname: String,
    #[serde(default, deserialize_with = "null_string")]
    pub username: String,
    #[serde(default, deserialize_with = "null_string")]
    pub boot_time_rfc3339: String,
    #[serde(default, deserialize_with = "null_i64")]
    pub uptime_seconds: i64,
    #[serde(default)]
    pub elevated: bool,
}

// ---------------------------------------------------------------------
// Registry artifacts
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct RegistryStream {
    /// relative_path -> raw JSON (installed software, USB history, …)
    pub artifacts: Vec<(String, Value)>,
}

/// Decode a JSON entry, mapping errors to readable messages.
pub fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8], entry: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("'{entry}' could not be decoded: {e}"))
}

/// Parse any JSON entry into a raw Value.
pub fn decode_raw(bytes: &[u8], entry: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("'{entry}' is not valid JSON: {e}"))
}

/// Extract printable ASCII strings with their byte offsets (min length
/// per §20) from arbitrary bytes — used by the artifact viewer's
/// Strings tab. Purely derived from the artifact's own bytes; nothing
/// is invented.
pub fn extract_strings(bytes: &[u8], min_len: usize, max: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut run = String::new();
    let mut run_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..0x7f).contains(&b) {
            if run.is_empty() {
                run_start = i;
            }
            run.push(b as char);
        } else {
            if run.len() >= min_len {
                out.push((run_start, std::mem::take(&mut run)));
                if out.len() >= max {
                    return out;
                }
            }
            run.clear();
        }
    }
    if run.len() >= min_len {
        out.push((run_start, run));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_process_entry_from_real_schema() {
        let json = r#"[{"command_line":"","cpu_usage_percent":0.0,"executable_path":null,
            "handle_count":null,"integrity_level":null,"memory_bytes":0,"name":"System",
            "parent_pid":null,"pid":4,"run_time_seconds":321314,
            "start_time_rfc3339":"2026-08-25T06:36:24+00:00","start_time_unix":1787639784,
            "status":"Run","thread_count":325,"user":null,"virtual_memory_bytes":0}]"#;
        let list: Vec<ProcessEntry> = decode_json(json.as_bytes(), "process_list.json").unwrap();
        assert_eq!(list[0].pid, 4);
        assert_eq!(list[0].name, "System");
    }

    #[test]
    fn decodes_connection_from_real_schema() {
        let json = r#"{"acquired_at":"x","connections":[{"local_address":"0.0.0.0",
            "local_port":7070,"pid":11328,"process":"AnyDesk.exe","protocol":"TCP",
            "remote_address":"0.0.0.0","remote_port":0,"state":"LISTENING"}]}"#;
        let doc: ConnectionsDoc = decode_json(json.as_bytes(), "connections.json").unwrap();
        assert_eq!(doc.connections[0].process, "AnyDesk.exe");
        assert_eq!(doc.connections[0].local_port, 7070);
    }

    #[test]
    fn decodes_event_from_real_schema() {
        let json = r#"{"acquired_at":"x","channel":"System","event_count":1,"events":[
            {"EventId":566,"Level":"Information","Message":"m","Provider":"P",
             "RecordId":248530,"TimeCreated":"2026-08-29T04:46:10.035+05:00"}]}"#;
        let doc: EventsDoc = decode_json(json.as_bytes(), "events.json").unwrap();
        assert_eq!(doc.events[0].event_id, 566);
    }

    #[test]
    fn parses_hashes_both_wrappers() {
        let wrapped = r#"{"acquired_at":"x","records":[{"SHA256":"ab","relative_path":"C:\\a.exe",
            "size":1,"source":"s","status":"ACQUIRED"}]}"#;
        let list = parse_hashes(wrapped.as_bytes()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].sha256, "ab");

        let bare = r#"[{"SHA256":"cd","relative_path":"","size":0,"source":"","status":"FAILED"}]"#;
        let list = parse_hashes(bare.as_bytes()).unwrap();
        assert_eq!(list[0].status, "FAILED");

        // Collector v1 writes SHA256: null for failed records.
        let with_null = r#"{"records":[{"SHA256":null,"relative_path":"","size":0,
            "source":"s","status":"FAILED","note":"os error 3"}]}"#;
        let list = parse_hashes(with_null.as_bytes()).unwrap();
        assert_eq!(list[0].sha256, "");
        assert_eq!(list[0].note.as_deref(), Some("os error 3"));
    }

    #[test]
    fn extracts_only_real_strings_with_offsets() {
        let bytes = b"abc\x00HELLO WORLD\x01\x02short_ok\x00no";
        let strings = extract_strings(bytes, 4, 100);
        assert_eq!(
            strings,
            vec![(4, "HELLO WORLD".to_string()), (17, "short_ok".to_string())]
        );
    }

    #[test]
    fn executable_paths_array_shape() {
        let json = r#"[{"pid":1234,"path":"C:\\bin\\tool.exe"},{"process_id":7,"executable_path":"C:\\x.exe"}]"#;
        let list = parse_executable_paths(json.as_bytes()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].pid, 1234);
        assert_eq!(list[0].path, r"C:\bin\tool.exe");
        assert_eq!(list[1].pid, 7);
    }

    #[test]
    fn executable_paths_map_and_empty_shapes() {
        // Direct pid -> path map.
        let json = r#"{"4":"C:\\Windows\\System32\\System","400":"C:\\a.exe"}"#;
        let list = parse_executable_paths(json.as_bytes()).unwrap();
        assert_eq!(list.len(), 2);
        // The real case ships an empty array — must decode to zero
        // entries without erroring.
        let empty = parse_executable_paths(b"[]").unwrap();
        assert!(empty.is_empty());
        // Unknown shape: honest empty result, never invented entries.
        let unknown = parse_executable_paths(br#""stray""#).unwrap();
        assert!(unknown.is_empty());
    }

    #[test]
    fn decodes_interfaces_from_real_schema() {
        let json = r#"{"acquired_at":"2026-08-25T06:41:00+00:00","interfaces":[{
            "mac_address":"00:11:22:33:44:55","name":"Ethernet",
            "total_packets_received":100,"total_packets_transmitted":90,
            "total_received_bytes":900000,"total_transmitted_bytes":45000}]}"#;
        let doc: InterfacesDoc = decode_json(json.as_bytes(), "interfaces.json").unwrap();
        assert_eq!(doc.interfaces.len(), 1);
        let i = &doc.interfaces[0];
        assert_eq!(i.name, "Ethernet");
        assert_eq!(i.mac_address, "00:11:22:33:44:55");
        assert_eq!(i.total_packets_received, 100);
        assert_eq!(i.total_received_bytes, 900000);
    }

    #[test]
    fn parses_raw_event_xml_with_entities_and_named_data() {
        let xml = r#"<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
              <Provider Name="Microsoft-Windows-Security-Auditing"/>
              <EventID Qualifiers="0">4625</EventID>
              <Level>1</Level>
              <TimeCreated SystemTime="2026-08-25T06:40:12.123Z"/>
            </System>
            <EventData>
              <Data Name="TargetUserName">admin &amp; co</Data>
              <Data Name="IpAddress">10.0.0.9</Data>
            </EventData>
          </Event>
          <Event xmlns="..."><System><EventID>1102</EventID></System></Event></Events>"#;
        let events = parse_raw_xml_events(xml.as_bytes()).unwrap();
        assert_eq!(events.len(), 2);
        let e = &events[0];
        assert_eq!(e.event_id, "4625");
        assert_eq!(e.level, "Error");
        assert_eq!(e.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(e.time_created, "2026-08-25T06:40:12.123Z");
        assert_eq!(e.data.len(), 2);
        assert_eq!(e.data[0], ("TargetUserName".to_string(), "admin & co".to_string()));
        assert_eq!(events[1].event_id, "1102");
    }

    #[test]
    fn parses_raw_event_xml_empty_input_is_empty_result() {
        assert!(parse_raw_xml_events(b"").unwrap().is_empty());
        assert!(parse_raw_xml_events(b"<NoEvents/>").unwrap().is_empty());
    }

    /// Structural guard: the parser must never stop short of the
    /// number of `<Event` open tags physically present in the bytes.
    /// Prevents silent truncation bugs (e.g. an accidental cap) from
    /// masquerading as "the collector only exported N events".
    #[test]
    fn raw_xml_parser_captures_every_event_tag() {
        let single = r#"<Event><System><Provider Name='P'/><EventID>1</EventID>
            <TimeCreated SystemTime='2026-08-26T16:47:32Z'/></System></Event>"#;
        let big = single.repeat(650); // deliberately above any plausible cap
        let bytes = big.as_bytes();
        // `<Event ` / `<Event>` open tags only — `<EventID>` must not count.
        let open_tags = bytes.windows(7).filter(|w| w == b"<Event " || w == b"<Event>").count();
        let parsed = parse_raw_xml_events(bytes).unwrap();
        assert_eq!(parsed.len(), open_tags);
        assert_eq!(parsed.len(), 650);
        // Single-quote attributes (the real export style) decode too.
        assert_eq!(parsed[0].provider, "P");
        assert_eq!(parsed[0].time_created, "2026-08-26T16:47:32Z");
    }
}
