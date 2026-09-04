//! ML anomaly scoring over REAL process evidence.
//!
//! The isolation forest is fitted locally on features extracted from the
//! decoded `process_list.json` of the open case only. When the case has
//! too few processes the engine reports insufficient data instead of
//! inventing anomalies.

use serde::{Deserialize, Serialize};

use crate::ingest::DecodedStreams;
use crate::ml::models::{IsolationForest, MODEL_ID};

/// Minimum number of process samples before ML scoring is meaningful.
const MIN_SAMPLES: usize = 10;
const ANOMALY_SCORE_THRESHOLD: f64 = 0.62;
const MAX_ANOMALIES: usize = 10;
/// Fixed seed => identical results for identical evidence.
const SEED: u64 = 0x5153_4423_A5A5_0001;

const FEATURE_NAMES: &[&str] = &[
    "memory_mb",
    "virtual_mb",
    "thread_count",
    "cpu_percent",
    "cmdline_len",
    "suspicious_path",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlAnomaly {
    pub pid: i64,
    pub process_name: String,
    pub score: f64,
    /// Feature names that contributed most to the anomaly score (XAI).
    pub dominant_features: Vec<String>,
    /// Artifact ID of the process list the sample came from.
    pub supporting_artifact: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MlStatus {
    Completed,
    InsufficientData,
    NotAvailable,
}

impl MlStatus {
    pub fn label(&self) -> &'static str {
        match self {
            MlStatus::Completed => "COMPLETED",
            MlStatus::InsufficientData => "INSUFFICIENT DATA",
            MlStatus::NotAvailable => "NOT AVAILABLE — NO PROCESS EVIDENCE",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlReport {
    pub model_id: String,
    pub status: MlStatus,
    pub samples_used: usize,
    pub anomalies: Vec<MlAnomaly>,
    pub evidence_class: String,
}

/// Score every process observed in the decoded evidence streams.
pub fn run(streams: &DecodedStreams) -> MlReport {
    let proc_stream = match &streams.processes {
        Some(p) if !p.processes.is_empty() => p,
        _ => {
            return MlReport {
                model_id: MODEL_ID.to_string(),
                status: MlStatus::NotAvailable,
                samples_used: 0,
                anomalies: Vec::new(),
                evidence_class: "ML ANOMALY".to_string(),
            }
        }
    };

    let rows: Vec<Vec<f64>> = proc_stream
        .processes
        .iter()
        .map(|p| {
            let path_lower = p.executable_path.as_deref().unwrap_or("").to_ascii_lowercase();
            let suspicious = ["\\temp\\", "\\users\\public\\", "\\downloads\\", "\\programdata\\"]
                .iter()
                .any(|m| path_lower.contains(m)) as u32 as f64;
            vec![
                p.memory_bytes as f64 / (1024.0 * 1024.0),
                p.virtual_memory_bytes as f64 / (1024.0 * 1024.0),
                p.thread_count as f64,
                p.cpu_usage_percent,
                p.command_line.len() as f64,
                suspicious,
            ]
        })
        .collect();

    if rows.len() < MIN_SAMPLES {
        return MlReport {
            model_id: MODEL_ID.to_string(),
            status: MlStatus::InsufficientData,
            samples_used: rows.len(),
            anomalies: Vec::new(),
            evidence_class: "ML ANOMALY".to_string(),
        };
    }

    // Min-max normalization per feature (deterministic).
    let n_features = FEATURE_NAMES.len();
    let mut mins = vec![f64::INFINITY; n_features];
    let mut maxs = vec![f64::NEG_INFINITY; n_features];
    for row in &rows {
        for (i, v) in row.iter().enumerate() {
            mins[i] = mins[i].min(*v);
            maxs[i] = maxs[i].max(*v);
        }
    }
    let normalized: Vec<Vec<f64>> = rows
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(i, v)| {
                    let span = maxs[i] - mins[i];
                    if span > 0.0 {
                        (*v - mins[i]) / span
                    } else {
                        0.0
                    }
                })
                .collect()
        })
        .collect();

    let forest = IsolationForest::fit(&normalized, 50, 64.min(normalized.len()), SEED);

    let mut scored: Vec<MlAnomaly> = normalized
        .iter()
        .zip(rows.iter())
        .zip(proc_stream.processes.iter())
        .map(|((norm_row, raw_row), p)| MlAnomaly {
            pid: p.pid,
            process_name: p.name.clone(),
            score: forest.score(norm_row),
            dominant_features: dominant(raw_row, &mins, &maxs),
            supporting_artifact: proc_stream.list_artifact.clone(),
        })
        .filter(|a| a.score >= ANOMALY_SCORE_THRESHOLD)
        .collect();

    scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(MAX_ANOMALIES);

    MlReport {
        model_id: MODEL_ID.to_string(),
        status: MlStatus::Completed,
        samples_used: rows.len(),
        anomalies: scored,
        evidence_class: "ML ANOMALY".to_string(),
    }
}

/// Rank features by normalized magnitude for this row (XAI hook).
fn dominant(raw: &[f64], mins: &[f64], maxs: &[f64]) -> Vec<String> {
    let mut indexed: Vec<(f64, &str)> = raw
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let span = maxs[i] - mins[i];
            let norm = if span > 0.0 {
                (*v - mins[i]) / span
            } else {
                0.0
            };
            (norm, FEATURE_NAMES[i])
        })
        .collect();
    indexed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    indexed
        .into_iter()
        .take(3)
        .filter(|(v, _)| *v > 0.0)
        .map(|(_, n)| n.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::streams::{ProcessEntry, ProcessStream};
    fn streams_with_processes(count: usize) -> DecodedStreams {
        let mut streams = DecodedStreams::default();
        let mut ps = ProcessStream::default();
        ps.list_artifact = Some("ART-000010".into());
        for i in 0..count {
            ps.processes.push(ProcessEntry {
                pid: 1000 + i as i64,
                name: format!("proc{i}.exe"),
                memory_bytes: 10_000_000 + (i as u64) * 1000,
                thread_count: 5 + (i % 4) as u32,
                ..Default::default()
            });
        }
        streams.processes = Some(ps);
        streams
    }

    #[test]
    fn no_processes_reports_not_available() {
        let report = run(&DecodedStreams::default());
        assert!(matches!(report.status, MlStatus::NotAvailable));
        assert!(report.anomalies.is_empty());
    }

    #[test]
    fn too_few_processes_reports_insufficient_data() {
        let report = run(&streams_with_processes(3));
        assert!(matches!(report.status, MlStatus::InsufficientData));
        assert!(report.anomalies.is_empty());
    }

    #[test]
    fn enough_processes_completes_and_stays_grounded() {
        let report = run(&streams_with_processes(15));
        assert!(matches!(report.status, MlStatus::Completed));
        assert_eq!(report.samples_used, 15);
        for anomaly in &report.anomalies {
            assert_eq!(anomaly.supporting_artifact.as_deref(), Some("ART-000010"));
        }
    }
}
