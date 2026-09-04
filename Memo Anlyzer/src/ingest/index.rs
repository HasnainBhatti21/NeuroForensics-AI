//! Artifact index + professional evidence tree built from the AIF
//! manifest. Every indexed artifact is traceable to a container entry
//! — artifact IDs are the collector's own `ART-xxxxxx` IDs.

use crate::aifzip::schema::{ArtifactRecord, ArtifactStatus, Manifest};
use crate::aifzip::integrity::ArtifactCheck;

/// Evidence tree categories in professional display order. A category
/// only appears when the container actually holds artifacts for it.
pub const CATEGORY_ORDER: &[&str] = &[
    "system",
    "cpu",
    "gpu",
    "memory",
    "processes",
    "network",
    "windows_events",
    "persistence",
    "registry",
    "hashes",
];

pub fn category_label(collector_id: &str) -> &'static str {
    match collector_id {
        "system" => "System Metadata",
        "cpu" => "CPU",
        "gpu" => "GPU",
        "memory" => "Memory / RAM",
        "processes" => "Processes",
        "network" => "Network",
        "windows_events" => "Windows Events",
        "events" => "Windows Events",
        "persistence" => "Persistence",
        "registry" => "Registry / System Artifacts",
        "hashes" => "File / Artifact Hashes",
        _ => "Other",
    }
}

/// Normalize collector module ids to tree category keys.
pub fn category_key(collector_id: &str) -> &'static str {
    match collector_id {
        "events" => "windows_events",
        "system" | "cpu" | "gpu" | "memory" | "processes" | "network" | "persistence"
        | "registry" | "hashes" => match collector_id {
            "system" => "system",
            "cpu" => "cpu",
            "gpu" => "gpu",
            "memory" => "memory",
            "processes" => "processes",
            "network" => "network",
            "persistence" => "persistence",
            "registry" => "registry",
            "hashes" => "hashes",
            _ => "other",
        },
        _ => "other",
    }
}

/// One indexed artifact — fully traceable to the evidence image.
#[derive(Clone, Debug)]
pub struct IndexedArtifact {
    pub artifact_id: String,
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub acquisition_time: String,
    pub source: String,
    pub collector: String,
    pub status: ArtifactStatus,
    pub notes: Option<String>,
    pub synthetic: bool,
    pub category: &'static str,
    /// Entry present in the archive?
    pub present: bool,
    /// Per-artifact hash re-verification result (None = not verified).
    pub hash_verified: Option<bool>,
}

impl IndexedArtifact {
    pub fn display_name(&self) -> &str {
        self.relative_path.rsplit('/').next().unwrap_or(&self.relative_path)
    }
}

/// Evidence tree: category -> artifacts (collector order preserved).
#[derive(Clone, Debug, Default)]
pub struct EvidenceTree {
    pub categories: Vec<TreeCategory>,
    pub total_artifacts: usize,
}

#[derive(Clone, Debug)]
pub struct TreeCategory {
    pub key: &'static str,
    pub label: &'static str,
    pub artifacts: Vec<usize>, // indices into ExaminedCase.artifacts
    pub bytes: u64,
}

impl EvidenceTree {
    pub fn build(artifacts: &[IndexedArtifact]) -> EvidenceTree {
        let mut cats: Vec<TreeCategory> = Vec::new();
        for (idx, art) in artifacts.iter().enumerate() {
            let key = art.category;
            if let Some(cat) = cats.iter_mut().find(|c| c.key == key) {
                cat.bytes += art.size;
                cat.artifacts.push(idx);
            } else {
                cats.push(TreeCategory {
                    key,
                    label: category_label(key),
                    artifacts: vec![idx],
                    bytes: art.size,
                });
            }
        }
        cats.sort_by_key(|c| {
            CATEGORY_ORDER
                .iter()
                .position(|k| *k == c.key)
                .unwrap_or(usize::MAX)
        });
        EvidenceTree { categories: cats, total_artifacts: artifacts.len() }
    }
}

/// Index every artifact listed in the manifest and cross-check against
/// the archive entries and the deep hash verification results.
pub fn build_index(manifest: &Manifest, has_entry: &dyn Fn(&str) -> bool, checks: &[ArtifactCheck]) -> Vec<IndexedArtifact> {
    manifest
        .artifacts
        .iter()
        .map(|rec: &ArtifactRecord| {
            let present = has_entry(&rec.relative_path);
            let hash_verified = checks
                .iter()
                .find(|c| c.artifact_id == rec.artifact_id)
                .map(|c| c.ok);
            IndexedArtifact {
                artifact_id: rec.artifact_id.clone(),
                relative_path: rec.relative_path.clone(),
                size: rec.size,
                sha256: rec.sha256.clone(),
                acquisition_time: rec.acquisition_time.clone(),
                source: rec.source.clone(),
                collector: rec.collector.clone(),
                status: rec.status,
                notes: rec.notes.clone(),
                synthetic: rec.synthetic,
                category: category_key(&rec.collector),
                present,
                hash_verified,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------
// Field-value index (§21 global keyword search)
// ---------------------------------------------------------------------

/// One indexed field value: the unit of the §21 global search. Built
/// once during ingest from decoded evidence — search never re-reads
/// container entries on every keystroke.
#[derive(Clone, Debug)]
pub struct FieldEntry {
    pub artifact_id: String,
    /// Readable field path, e.g. `connections[3].process`.
    pub field: String,
    /// The actual evidence value (display form, possibly truncated).
    pub value: String,
    /// Pre-lowercased `field + value` haystack for fast matching.
    pub haystack: String,
}

/// Per-artifact cap so one huge stream cannot drown the index.
const FIELD_ENTRIES_PER_ARTIFACT: usize = 4000;
/// Display/haystack truncation for very long values.
const FIELD_VALUE_CAP: usize = 200;

/// Append one field value, honoring the per-artifact cap.
pub fn push_field(index: &mut Vec<FieldEntry>, artifact_id: &str, field: &str, value: &str) {
    let count = index.iter().filter(|e| e.artifact_id == artifact_id).count();
    if count >= FIELD_ENTRIES_PER_ARTIFACT {
        return;
    }
    let truncated: String = value.chars().take(FIELD_VALUE_CAP).collect();
    let mut haystack = format!("{field} {truncated}");
    haystack.make_ascii_lowercase();
    index.push(FieldEntry {
        artifact_id: artifact_id.to_string(),
        field: field.to_string(),
        value: truncated,
        haystack,
    });
}

/// Recursively index every scalar inside an arbitrary JSON value
/// (raw-decoded collector files such as adapters.json, wmi exports).
pub fn index_json_value(
    index: &mut Vec<FieldEntry>,
    artifact_id: &str,
    path: &str,
    value: &serde_json::Value,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Bool(b) => push_field(index, artifact_id, path, &b.to_string()),
        serde_json::Value::Number(n) => push_field(index, artifact_id, path, &n.to_string()),
        serde_json::Value::String(s) => {
            if !s.is_empty() {
                push_field(index, artifact_id, path, s);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                index_json_value(index, artifact_id, &format!("{path}[{i}]"), item, depth + 1);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                index_json_value(index, artifact_id, &child, item, depth + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_index_truncates_and_lowercases() {
        let mut index = Vec::new();
        push_field(&mut index, "ART-000001", "process.name", "XMRig.EXE");
        assert_eq!(index.len(), 1);
        assert!(index[0].haystack.contains("xmrig.exe"));
        assert!(index[0].haystack.contains("process.name"));
    }

    #[test]
    fn json_value_indexer_visits_scalars() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"adapters":[{"name":"Ethernet","ipv4":"10.0.0.5"}],"count":2}"#,
        )
        .unwrap();
        let mut index = Vec::new();
        index_json_value(&mut index, "ART-000002", "", &v, 0);
        let fields: Vec<&str> = index.iter().map(|e| e.field.as_str()).collect();
        assert!(fields.contains(&"adapters[0].name"));
        assert!(fields.contains(&"adapters[0].ipv4"));
        assert!(fields.contains(&"count"));
    }

    fn art(id: &str, collector: &str, path: &str) -> IndexedArtifact {
        IndexedArtifact {
            artifact_id: id.into(),
            relative_path: path.into(),
            size: 10,
            sha256: String::new(),
            acquisition_time: String::new(),
            source: String::new(),
            collector: collector.into(),
            status: ArtifactStatus::Acquired,
            notes: None,
            synthetic: false,
            category: category_key(collector),
            present: true,
            hash_verified: Some(true),
        }
    }

    #[test]
    fn tree_groups_by_category_in_fixed_order() {
        let arts = vec![
            art("ART-000003", "network", "network/connections.json"),
            art("ART-000001", "system", "system/os.json"),
            art("ART-000002", "events", "windows_events/system/events.json"),
        ];
        let tree = EvidenceTree::build(&arts);
        let keys: Vec<&str> = tree.categories.iter().map(|c| c.key).collect();
        assert_eq!(keys, vec!["system", "network", "windows_events"]);
        assert_eq!(tree.categories[2].label, "Windows Events");
        assert_eq!(tree.total_artifacts, 3);
    }
}
