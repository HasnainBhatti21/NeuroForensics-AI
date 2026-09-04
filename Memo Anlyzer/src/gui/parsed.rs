//! Parsed View tab (§20): a readable, collapsible field/value tree of
//! the artifact's actual parsed content.
//!
//! Never-empty guarantee: every reachable selection yields either a
//! non-empty node tree or an explicit message ("Failed to parse: …",
//! binary/absence notice). Silence is impossible by construction — the
//! regression test in this module and in `ingest` enforces it against
//! the real reference case.

use eframe::egui::{self, text::LayoutJob, Align, RichText, TextFormat, Ui};
use serde_json::Value;

use crate::ingest::streams::{
    decode_json, parse_executable_paths, parse_hashes, parse_raw_xml_events, ConnectionEntry,
    ConnectionsDoc, EventEntry, EventsDoc, HashEntry, InterfacesDoc, ProcessEntry, RawXmlEvent,
    RegistryRunsDoc, RunKey, ServiceEntry, ServicesDoc,
};

use super::explorer::ArtifactRow;
use super::state::Session;
use super::theme::Palette;

/// Maximum list rows rendered per artifact; the rest are announced,
/// never silently dropped.
const LIST_DISPLAY_CAP: usize = 400;
/// Cap for generic JSON children at one level.
const JSON_CHILDREN_CAP: usize = 300;
/// Cap for generic JSON nesting depth.
const JSON_DEPTH_CAP: usize = 10;
/// Values longer than this are truncated for display (full value stays
/// in the Raw/Hex tab).
const VALUE_DISPLAY_CAP: usize = 500;

/// One node of the Parsed View tree. `field` is the canonical field
/// path (identical to the §21 search index paths so search jumps can
/// locate the node); `label` is the display text.
#[derive(Clone, Debug)]
pub struct FieldNode {
    pub field: String,
    pub label: String,
    pub value: Option<String>,
    pub children: Vec<FieldNode>,
}

fn leaf(field: &str, value: String) -> FieldNode {
    FieldNode {
        field: field.to_string(),
        label: field.to_string(),
        value: Some(value),
        children: Vec::new(),
    }
}

fn branch(field: &str, label: String, children: Vec<FieldNode>) -> FieldNode {
    FieldNode { field: field.to_string(), label, value: None, children }
}

fn note(text: String) -> FieldNode {
    FieldNode { field: "_note".to_string(), label: text.clone(), value: Some(text), children: Vec::new() }
}

fn opt(value: &str) -> String {
    if value.is_empty() { "(empty)".to_string() } else { value.to_string() }
}

/// Outcome for one selected artifact. `Nodes` = structured tree,
/// `Message` = explicit explanation (parse failure, binary stream,
/// unreadable entry). Neither variant may ever be empty.
#[derive(Clone, Debug)]
pub enum ParsedOutcome {
    Nodes(Vec<FieldNode>),
    Message(String),
}

impl ParsedOutcome {
    pub fn is_empty(&self) -> bool {
        match self {
            ParsedOutcome::Nodes(n) => n.is_empty(),
            ParsedOutcome::Message(m) => m.is_empty(),
        }
    }
}

fn failed(reason: impl std::fmt::Display) -> ParsedOutcome {
    ParsedOutcome::Message(format!(
        "Failed to parse: {reason} — this entry is not a recognized structured stream. Inspect the raw bytes in the Raw/Hex and Strings tabs."
    ))
}

/// Build the Parsed View for one artifact from its real bytes.
/// `bytes` may be capped (viewer streams only `PREVIEW_CAP` bytes);
/// `load_error` carries the honest reason when content is unavailable.
pub fn parsed_outcome(
    relative_path: &str,
    bytes: Option<&[u8]>,
    load_error: Option<&str>,
) -> ParsedOutcome {
    if let Some(err) = load_error {
        return ParsedOutcome::Message(format!("Content unavailable: {err}"));
    }
    let Some(bytes) = bytes else {
        return ParsedOutcome::Message(
            "Content unavailable — open the evidence image to stream this entry.".into(),
        );
    };

    let lower = relative_path.to_ascii_lowercase();

    if lower.starts_with("memory/") {
        return ParsedOutcome::Message(
            "Binary memory-capture stream — no structured parser applies to it. Inspect the raw bytes in the Raw/Hex and Strings tabs.".into(),
        );
    }

    let result: Result<Vec<FieldNode>, ParsedOutcome> = (|| {
        if lower == "processes/process_list.json" {
            let list: Vec<ProcessEntry> =
                decode_json(bytes, relative_path).map_err(|e| failed(e))?;
            return Ok(process_nodes(&list));
        }
        if lower == "processes/executable_paths.json" {
            let entries = parse_executable_paths(bytes)
                .map_err(|e| failed(format!("'{relative_path}' could not be decoded: {e}")))?;
            if entries.is_empty() {
                return Ok(vec![note(
                    "Acquired and decoded, but the collector recorded zero pid→path mappings (empty `[]`)."
                        .into(),
                )]);
            }
            return Ok(entries
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    branch(
                        &format!("executable_paths[{i}]"),
                        format!("executable_paths[{i}] — pid {}", e.pid),
                        vec![
                            leaf(&format!("executable_paths[{i}].pid"), e.pid.to_string()),
                            leaf(&format!("executable_paths[{i}].path"), e.path.clone()),
                        ],
                    )
                })
                .collect());
        }
        if lower == "network/connections.json" {
            let doc: ConnectionsDoc =
                decode_json(bytes, relative_path).map_err(|e| failed(e))?;
            return Ok(connection_nodes(&doc.connections));
        }
        if lower == "network/interfaces.json" {
            let doc: InterfacesDoc =
                decode_json(bytes, relative_path).map_err(|e| failed(e))?;
            return Ok(interface_nodes(&doc));
        }
        if lower.starts_with("windows_events/") && lower.ends_with("/events_raw.xml") {
            let raws = parse_raw_xml_events(bytes)
                .map_err(|e| failed(format!("'{relative_path}' could not be decoded: {e}")))?;
            return Ok(raw_event_nodes(&raws));
        }
        if lower.starts_with("windows_events/") && lower.ends_with("/events.json") {
            let doc: EventsDoc = decode_json(bytes, relative_path).map_err(|e| failed(e))?;
            return Ok(event_nodes(&doc));
        }
        if lower == "persistence/registry_runs.json" {
            let doc: RegistryRunsDoc = decode_json(bytes, relative_path).map_err(|e| failed(e))?;
            return Ok(run_key_nodes(&doc.keys));
        }
        if lower == "persistence/services.json" {
            let doc: ServicesDoc = decode_json(bytes, relative_path).map_err(|e| failed(e))?;
            return Ok(service_nodes(&doc.services));
        }
        if lower == "hashes/hashes.json" {
            let records = parse_hashes(bytes)
                .map_err(|e| failed(format!("'{relative_path}' could not be decoded: {e}")))?;
            return Ok(hash_nodes(&records));
        }
        // Everything else structured: generic JSON tree (os.json, disks,
        // adapters, routes, arp, cpu/gpu metadata, wmi exports, registry
        // artifacts, remaining persistence files, process tree, modules).
        let value: Value = serde_json::from_slice(bytes).map_err(|e| failed(e))?;
        let nodes = json_nodes("", &value, 0);
        if nodes.is_empty() {
            return Ok(vec![note("Decoded JSON carries no fields (null).".into())]);
        }
        Ok(nodes)
    })();

    match result {
        Ok(nodes) => ParsedOutcome::Nodes(nodes),
        Err(msg) => msg,
    }
}

// ---------------------------------------------------------------------
// Typed node builders (field paths mirror the §21 search index)
// ---------------------------------------------------------------------

fn capped_note(kind: &str, total: usize) -> Option<FieldNode> {
    (total > LIST_DISPLAY_CAP).then(|| {
        note(format!(
            "Showing the first {LIST_DISPLAY_CAP} of {total} {kind} — use the global search to locate specific records."
        ))
    })
}

fn process_nodes(list: &[ProcessEntry]) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = list
        .iter()
        .take(LIST_DISPLAY_CAP)
        .enumerate()
        .map(|(i, p)| {
            let pre = format!("processes[{i}]");
            branch(
                &pre,
                format!("processes[{i}] — {} (pid {})", opt(&p.name), p.pid),
                vec![
                    leaf(&format!("{pre}.pid"), p.pid.to_string()),
                    leaf(&format!("{pre}.name"), opt(&p.name)),
                    leaf(
                        &format!("{pre}.parent_pid"),
                        p.parent_pid.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                    ),
                    leaf(
                        &format!("{pre}.executable_path"),
                        p.executable_path.clone().unwrap_or_else(|| "null".into()),
                    ),
                    leaf(&format!("{pre}.command_line"), opt(&p.command_line)),
                    leaf(&format!("{pre}.user"), p.user.clone().unwrap_or_else(|| "null".into())),
                    leaf(&format!("{pre}.cpu_usage_percent"), p.cpu_usage_percent.to_string()),
                    leaf(&format!("{pre}.memory_bytes"), p.memory_bytes.to_string()),
                    leaf(&format!("{pre}.virtual_memory_bytes"), p.virtual_memory_bytes.to_string()),
                    leaf(&format!("{pre}.thread_count"), p.thread_count.to_string()),
                    leaf(
                        &format!("{pre}.handle_count"),
                        p.handle_count.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                    ),
                    leaf(
                        &format!("{pre}.integrity_level"),
                        p.integrity_level.clone().unwrap_or_else(|| "null".into()),
                    ),
                    leaf(&format!("{pre}.status"), opt(&p.status)),
                    leaf(&format!("{pre}.start_time_rfc3339"), opt(&p.start_time_rfc3339)),
                    leaf(&format!("{pre}.run_time_seconds"), p.run_time_seconds.to_string()),
                ],
            )
        })
        .collect();
    if list.is_empty() {
        nodes.push(note("Acquired, but the collector recorded zero processes.".into()));
    }
    if let Some(n) = capped_note("processes", list.len()) {
        nodes.push(n);
    }
    nodes
}

fn connection_nodes(list: &[ConnectionEntry]) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = Vec::new();
    for (i, c) in list.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("connections[{i}]");
        nodes.push(branch(
            &pre,
            format!(
                "connections[{i}] — {} {} {}:{} → {}:{} ({})",
                opt(&c.protocol),
                opt(&c.state),
                opt(&c.local_address),
                c.local_port,
                opt(&c.remote_address),
                c.remote_port,
                opt(&c.process)
            ),
            vec![
                leaf(&format!("{pre}.protocol"), opt(&c.protocol)),
                leaf(&format!("{pre}.local_address"), opt(&c.local_address)),
                leaf(&format!("{pre}.local_port"), c.local_port.to_string()),
                leaf(&format!("{pre}.remote_address"), opt(&c.remote_address)),
                leaf(&format!("{pre}.remote_port"), c.remote_port.to_string()),
                leaf(&format!("{pre}.state"), opt(&c.state)),
                leaf(&format!("{pre}.pid"), c.pid.to_string()),
                leaf(&format!("{pre}.process"), opt(&c.process)),
            ],
        ));
    }
    if list.is_empty() {
        nodes.push(note("Acquired, but the collector recorded zero connections.".into()));
    }
    if let Some(n) = capped_note("connections", list.len()) {
        nodes.push(n);
    }
    nodes
}

fn interface_nodes(doc: &InterfacesDoc) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = vec![leaf("acquired_at", opt(&doc.acquired_at))];
    for (i, n) in doc.interfaces.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("interfaces[{i}]");
        nodes.push(branch(
            &pre,
            format!("interfaces[{i}] — {}", opt(&n.name)),
            vec![
                leaf(&format!("{pre}.name"), opt(&n.name)),
                leaf(&format!("{pre}.mac_address"), opt(&n.mac_address)),
                leaf(&format!("{pre}.total_packets_received"), n.total_packets_received.to_string()),
                leaf(&format!("{pre}.total_packets_transmitted"), n.total_packets_transmitted.to_string()),
                leaf(&format!("{pre}.total_received_bytes"), n.total_received_bytes.to_string()),
                leaf(&format!("{pre}.total_transmitted_bytes"), n.total_transmitted_bytes.to_string()),
            ],
        ));
    }
    if doc.interfaces.is_empty() {
        nodes.push(note("Acquired, but the collector recorded zero interfaces.".into()));
    }
    if let Some(n) = capped_note("interfaces", doc.interfaces.len()) {
        nodes.push(n);
    }
    nodes
}

fn event_nodes(doc: &EventsDoc) -> Vec<FieldNode> {
    let mut nodes = vec![
        leaf("acquired_at", opt(&doc.acquired_at)),
        leaf("channel", opt(&doc.channel)),
        leaf("event_count", doc.event_count.to_string()),
    ];
    append_event_children(&mut nodes, &doc.events, "events");
    nodes
}

fn raw_event_nodes(raws: &[RawXmlEvent]) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = Vec::new();
    for (i, e) in raws.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("events_raw[{i}]");
        let mut children = vec![
            leaf(&format!("{pre}.event_id"), opt(&e.event_id)),
            leaf(&format!("{pre}.time_created"), opt(&e.time_created)),
            leaf(&format!("{pre}.provider"), opt(&e.provider)),
            leaf(&format!("{pre}.level"), opt(&e.level)),
        ];
        for (j, (name, value)) in e.data.iter().enumerate() {
            let key = if name.is_empty() {
                format!("{pre}.data[{j}]")
            } else {
                format!("{pre}.data.{name}")
            };
            children.push(leaf(&key, value.clone()));
        }
        nodes.push(branch(
            &pre,
            format!("events_raw[{i}] — EventID {} · {}", opt(&e.event_id), opt(&e.time_created)),
            children,
        ));
    }
    if raws.is_empty() {
        nodes.push(note("The raw XML export carried no <Event> records.".into()));
    }
    if let Some(n) = capped_note("raw events", raws.len()) {
        nodes.push(n);
    }
    nodes
}

fn append_event_children(nodes: &mut Vec<FieldNode>, events: &[EventEntry], prefix: &str) {
    for (i, e) in events.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("{prefix}[{i}]");
        nodes.push(branch(
            &pre,
            format!("{prefix}[{i}] — EventID {} · {} · {}", e.event_id, opt(&e.provider), opt(&e.time_created)),
            vec![
                leaf(&format!("{pre}.event_id"), e.event_id.to_string()),
                leaf(&format!("{pre}.level"), opt(&e.level)),
                leaf(&format!("{pre}.provider"), opt(&e.provider)),
                leaf(&format!("{pre}.record_id"), e.record_id.to_string()),
                leaf(&format!("{pre}.time_created"), opt(&e.time_created)),
                leaf(&format!("{pre}.message"), opt(&e.message)),
            ],
        ));
    }
    if events.is_empty() {
        nodes.push(note("Acquired, but the collector recorded zero events for this channel.".into()));
    }
    if let Some(n) = capped_note("events", events.len()) {
        nodes.push(n);
    }
}

fn run_key_nodes(keys: &[RunKey]) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = Vec::new();
    for (i, key) in keys.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("run_keys[{i}]");
        let mut children = vec![
            leaf(&format!("{pre}.hive"), opt(&key.hive)),
            leaf(&format!("{pre}.key_path"), opt(&key.key_path)),
            leaf(&format!("{pre}.label"), opt(&key.label)),
        ];
        for (v, value) in key.values.iter().enumerate() {
            children.push(leaf(
                &format!("{pre}.values[{v}].value_name"),
                opt(&value.value_name),
            ));
            children.push(leaf(&format!("{pre}.values[{v}].data"), opt(&value.data)));
        }
        if key.values.is_empty() {
            children.push(note("No values recorded under this key.".into()));
        }
        nodes.push(branch(
            &pre,
            format!("run_keys[{i}] — {}\\{}", opt(&key.hive), opt(&key.key_path)),
            children,
        ));
    }
    if keys.is_empty() {
        nodes.push(note("Acquired, but no Run keys were recorded.".into()));
    }
    if let Some(n) = capped_note("run keys", keys.len()) {
        nodes.push(n);
    }
    nodes
}

fn service_nodes(services: &[ServiceEntry]) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = Vec::new();
    for (i, s) in services.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("services[{i}]");
        nodes.push(branch(
            &pre,
            format!("services[{i}] — {}", opt(&s.name)),
            vec![
                leaf(&format!("{pre}.name"), opt(&s.name)),
                leaf(&format!("{pre}.display_name"), opt(&s.display_name)),
                leaf(&format!("{pre}.start_type"), s.start_type.to_string()),
                leaf(&format!("{pre}.status"), s.status.to_string()),
            ],
        ));
    }
    if services.is_empty() {
        nodes.push(note("Acquired, but no services were recorded.".into()));
    }
    if let Some(n) = capped_note("services", services.len()) {
        nodes.push(n);
    }
    nodes
}

fn hash_nodes(records: &[HashEntry]) -> Vec<FieldNode> {
    let mut nodes: Vec<FieldNode> = Vec::new();
    for (i, h) in records.iter().take(LIST_DISPLAY_CAP).enumerate() {
        let pre = format!("records[{i}]");
        nodes.push(branch(
            &pre,
            format!("records[{i}] — {}", opt(&h.relative_path)),
            vec![
                leaf(&format!("{pre}.relative_path"), opt(&h.relative_path)),
                leaf(&format!("{pre}.sha256"), opt(&h.sha256)),
                leaf(&format!("{pre}.size"), h.size.to_string()),
                leaf(&format!("{pre}.source"), opt(&h.source)),
                leaf(&format!("{pre}.status"), opt(&h.status)),
                leaf(&format!("{pre}.acquisition_time"), opt(&h.acquisition_time)),
                leaf(
                    &format!("{pre}.note"),
                    h.note.clone().unwrap_or_else(|| "null".into()),
                ),
            ],
        ));
    }
    if records.is_empty() {
        nodes.push(note("Acquired, but no hash records were saved.".into()));
    }
    if let Some(n) = capped_note("hash records", records.len()) {
        nodes.push(n);
    }
    nodes
}

/// Generic JSON renderer — field paths use the same `a.b[0].c` scheme
/// as the §21 value indexer, so search hits resolve to nodes.
fn json_nodes(path: &str, value: &Value, depth: usize) -> Vec<FieldNode> {
    if depth > JSON_DEPTH_CAP {
        return vec![note(format!("Nesting deeper than {JSON_DEPTH_CAP} levels is not expanded."))];
    }
    match value {
        Value::Null => vec![],
        Value::Bool(b) => vec![leaf(&display_path(path), b.to_string())],
        Value::Number(n) => vec![leaf(&display_path(path), n.to_string())],
        Value::String(s) => vec![leaf(&display_path(path), s.clone())],
        Value::Array(items) => items
            .iter()
            .take(JSON_CHILDREN_CAP)
            .enumerate()
            .flat_map(|(i, item)| {
                let child = format!("{path}[{i}]");
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        vec![branch(&child, child.clone(), json_nodes(&child, item, depth + 1))]
                    }
                    scalar => json_nodes(&child, scalar, depth + 1),
                }
            })
            .collect(),
        Value::Object(map) => {
            let mut out: Vec<FieldNode> = Vec::new();
            for (key, item) in map.iter().take(JSON_CHILDREN_CAP) {
                let child = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        out.push(branch(&child, child.clone(), json_nodes(&child, item, depth + 1)));
                    }
                    scalar => out.extend(json_nodes(&child, scalar, depth + 1)),
                }
            }
            if map.len() > JSON_CHILDREN_CAP {
                out.push(note(format!(
                    "Showing the first {JSON_CHILDREN_CAP} of {} fields at this level.",
                    map.len()
                )));
            }
            out
        }
    }
}

fn display_path(path: &str) -> String {
    if path.is_empty() { "(root)".to_string() } else { path.to_string() }
}

// ---------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------

pub fn draw(
    ui: &mut Ui,
    p: &Palette,
    session: &Session,
    row: &ArtifactRow,
    flagged: &[String],
) {
    egui::ScrollArea::vertical().id_salt("parsed_view").show(ui, |ui| {
        let err = session.preview.load_error.as_deref();
        let bytes: Option<&[u8]> = if session.preview.bytes.is_empty() {
            None
        } else {
            Some(&session.preview.bytes)
        };
        let outcome = if bytes.is_none() && err.is_none() {
            if session.preview.total_size == 0 {
                ParsedOutcome::Message(
                    "Entry is empty (0 bytes) — the collector recorded this file with no content."
                        .into(),
                )
            } else {
                ParsedOutcome::Message(
                    "Content unavailable — open the evidence image to stream this entry.".into(),
                )
            }
        } else {
            parsed_outcome(&row.relative_path, bytes, err)
        };

        match outcome {
            ParsedOutcome::Message(message) => {
                ui.add_space(6.0);
                ui.label(RichText::new(message).color(p.warn).size(12.5));
            }
            ParsedOutcome::Nodes(nodes) => {
                let focus = session.parsed_focus.as_deref();
                for node in &nodes {
                    draw_node(ui, p, node, 0, focus, flagged);
                }
            }
        }
    });
}

fn draw_node(
    ui: &mut Ui,
    p: &Palette,
    node: &FieldNode,
    depth: usize,
    focus: Option<&str>,
    flagged: &[String],
) {
    let is_focus = focus == Some(node.field.as_str());
    if node.children.is_empty() {
        let inner = |ui: &mut Ui| {
            ui.horizontal(|ui| {
                if node.field == "_note" {
                    ui.label(
                        RichText::new(node.value.as_deref().unwrap_or(""))
                            .color(p.text_dim)
                            .italics()
                            .size(12.0),
                    );
                    return;
                }
                ui.label(RichText::new(&node.label).color(p.text_dim).size(12.0));
                if let Some(value) = &node.value {
                    draw_value(ui, p, value, flagged);
                }
            });
        };
        if is_focus {
            let resp = egui::Frame::default()
                .fill(p.selection)
                .corner_radius(4.0)
                .inner_margin(3.0)
                .show(ui, inner);
            ui.scroll_to_rect(resp.response.rect, Some(Align::Center));
        } else {
            inner(ui);
        }
        return;
    }

    let header = RichText::new(&node.label).strong().size(12.0);
    let mut collapsing = egui::CollapsingHeader::new(header)
        .id_salt(format!("pv::{}", node.field))
        .default_open(depth < 1);
    if is_focus {
        collapsing = collapsing.open(Some(true));
    }
    collapsing.show(ui, |ui| {
        for child in &node.children {
            draw_node(ui, p, child, depth + 1, focus, flagged);
        }
    });
}

/// Value cell: monospace, truncated for display, with detection-flagged
/// substrings highlighted (§20).
fn draw_value(ui: &mut Ui, p: &Palette, value: &str, flagged: &[String]) {
    let display: String = value.chars().take(VALUE_DISPLAY_CAP).collect();
    let truncated = display.len() < value.len();
    let lower = display.to_ascii_lowercase();

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for f in flagged {
        if f.len() < 2 {
            continue;
        }
        let needle = f.to_ascii_lowercase();
        let mut start = 0usize;
        while let Some(pos) = lower[start..].find(&needle) {
            let abs = start + pos;
            ranges.push((abs, abs + needle.len()));
            start = abs + needle.len();
            if ranges.len() > 32 {
                break;
            }
        }
    }
    ranges.sort_unstable();

    let mono = egui::FontId::monospace(12.0);
    let mut job = LayoutJob::default();
    if ranges.is_empty() {
        job.append(
            &display,
            0.0,
            TextFormat { font_id: mono.clone(), color: p.text, ..Default::default() },
        );
    } else {
        let mut cursor = 0usize;
        for (a, b) in ranges {
            let (a, b) = (a.max(cursor), b.max(cursor));
            if a > cursor {
                job.append(
                    &display[cursor..a],
                    0.0,
                    TextFormat { font_id: mono.clone(), color: p.text, ..Default::default() },
                );
            }
            if b > a && b <= display.len() {
                job.append(
                    &display[a..b],
                    0.0,
                    TextFormat {
                        font_id: mono.clone(),
                        color: p.danger,
                        background: egui::Color32::from_rgba_premultiplied(
                            p.danger.r(),
                            p.danger.g(),
                            p.danger.b(),
                            55,
                        ),
                        ..Default::default()
                    },
                );
            }
            cursor = cursor.max(b);
        }
        if cursor < display.len() {
            job.append(
                &display[cursor..],
                0.0,
                TextFormat { font_id: mono.clone(), color: p.text, ..Default::default() },
            );
        }
    }
    if truncated {
        job.append(
            " …",
            0.0,
            TextFormat { font_id: mono, color: p.text_dim, ..Default::default() },
        );
    }
    ui.label(job);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_non_empty(outcome: &ParsedOutcome) {
        assert!(
            !outcome.is_empty(),
            "§20 violation: selection produced an empty detail panel"
        );
    }

    #[test]
    fn structured_json_yields_nodes() {
        let bytes = br#"{"os_name":"Windows 11","hostname":"WORKSTATION-7"}"#;
        let outcome = parsed_outcome("system/os.json", Some(bytes), None);
        assert_non_empty(&outcome);
        match outcome {
            ParsedOutcome::Nodes(nodes) => {
                assert!(nodes.iter().any(|n| n.field == "os_name"));
                assert!(nodes.iter().any(|n| n.field == "hostname"));
            }
            ParsedOutcome::Message(m) => panic!("expected nodes, got message: {m}"),
        }
    }

    #[test]
    fn malformed_json_yields_explicit_failure_message() {
        let bytes = br#"{"os_name":"broken"#;
        let outcome = parsed_outcome("system/os.json", Some(bytes), None);
        assert_non_empty(&outcome);
        match outcome {
            ParsedOutcome::Message(m) => assert!(m.starts_with("Failed to parse:"), "{m}"),
            ParsedOutcome::Nodes(_) => panic!("malformed JSON must not yield nodes"),
        }
    }

    #[test]
    fn binary_entry_yields_explicit_message_not_silence() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let outcome = parsed_outcome("registry/artifacts/usb.bin", Some(&bytes), None);
        assert_non_empty(&outcome);
        assert!(matches!(outcome, ParsedOutcome::Message(_)));
    }

    #[test]
    fn unavailable_content_yields_explicit_message() {
        let outcome = parsed_outcome("network/connections.json", None, Some("zip entry missing"));
        assert_non_empty(&outcome);
        match outcome {
            ParsedOutcome::Message(m) => assert!(m.contains("zip entry missing")),
            _ => panic!("expected message"),
        }
    }

    #[test]
    fn memory_stream_is_honestly_binary() {
        let outcome = parsed_outcome("memory/ram.img", Some(&[0u8; 16]), None);
        assert_non_empty(&outcome);
        assert!(matches!(outcome, ParsedOutcome::Message(_)));
    }

    #[test]
    fn empty_executable_paths_is_reported_not_invented() {
        let outcome = parsed_outcome("processes/executable_paths.json", Some(b"[]"), None);
        assert_non_empty(&outcome);
        match outcome {
            ParsedOutcome::Nodes(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert!(nodes[0].value.as_deref().unwrap().contains("zero pid"));
            }
            _ => panic!("expected note node"),
        }
    }

    #[test]
    fn raw_xml_events_render_with_field_paths_matching_the_index() {
        let xml = br#"<Event><System><EventID>4625</EventID></System>
            <EventData><Data Name="TargetUserName">root</Data></EventData></Event>"#;
        let outcome = parsed_outcome("windows_events/security/events_raw.xml", Some(xml), None);
        assert_non_empty(&outcome);
        match outcome {
            ParsedOutcome::Nodes(nodes) => {
                let branch = &nodes[0];
                assert_eq!(branch.field, "events_raw[0]");
                let fields: Vec<&str> = branch.children.iter().map(|c| c.field.as_str()).collect();
                assert!(fields.contains(&"events_raw[0].event_id"));
                assert!(fields.contains(&"events_raw[0].data.TargetUserName"));
            }
            _ => panic!("expected nodes"),
        }
    }

    /// §20/§48 regression: selecting ANY indexed artifact of the real
    /// reference case must populate a non-empty Parsed View — the exact
    /// bug class of the original broken build.
    #[test]
    fn regression_real_case_selection_never_blank() {
        let Some(mut exam) = crate::ingest::tests::real_exam_if_available() else {
            eprintln!("sample AIF not present - skipping");
            return;
        };
        for artifact in &exam.artifacts {
            assert!(artifact.present, "artifact {} missing entry", artifact.artifact_id);
            let bytes = exam
                .aif
                .read_entry(&artifact.relative_path)
                .expect("entry readable");
            let outcome = parsed_outcome(&artifact.relative_path, Some(&bytes), None);
            assert!(
                !outcome.is_empty(),
                "§20 violation for {} ({}): blank panel",
                artifact.artifact_id,
                artifact.relative_path
            );
            if let ParsedOutcome::Message(m) = &outcome {
                assert!(
                    m.starts_with("Failed to parse:")
                        || m.contains("Binary")
                        || m.contains("binary")
                        || m.contains("empty")
                        || m.contains("unavailable"),
                    "unexpected message for {}: {m}",
                    artifact.relative_path
                );
            }
        }
    }
}
