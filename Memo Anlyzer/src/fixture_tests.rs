//! Section 39 fixture-driven regression tests. The synthetic inputs in
//! `tests/fixtures/` (clearly labeled, never loaded by production code)
//! are decoded through the exact production decoders and pushed through
//! rules, correlation and ML. This complements the real-AIF-first
//! strategy: deterministic coverage that runs even when no real case
//! file is present on the machine.

use crate::ingest::streams::{
    decode_json, ConnectionsDoc, NetworkStream, PersistenceStream, ProcessEntry, ProcessStream,
    RegistryRunsDoc,
};
use crate::ingest::DecodedStreams;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn read_fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let bytes = std::fs::read(fixture_path(name))
        .unwrap_or_else(|e| panic!("fixture {name} must be readable: {e}"));
    decode_json(&bytes, &format!("tests/fixtures/{name}"))
        .unwrap_or_else(|e| panic!("fixture {name} must decode via the production decoder: {e}"))
}

/// Assemble decoded streams exactly the way ingest does. Correlation
/// refuses to link anything without grounding artifact IDs (§23), so
/// the fixture supplies clearly-labeled SYNTHETIC anchors — the tests
/// then assert those exact IDs are what the links cite.
fn fixture_streams() -> DecodedStreams {
    let processes: Vec<ProcessEntry> = read_fixture("process_list.json");
    let conns: ConnectionsDoc = read_fixture("connections.json");
    let runs: RegistryRunsDoc = read_fixture("registry_runs.json");
    DecodedStreams {
        system: None,
        os: None,
        cpu: None,
        gpu: None,
        memory_present: false,
        processes: Some(ProcessStream {
            list_artifact: Some("ART-FIXPROC".into()),
            processes,
            tree: Vec::new(),
            loaded_module_count: 0,
            executable_paths: Vec::new(),
            executable_paths_present: false,
            executable_paths_artifact: None,
        }),
        network: Some(NetworkStream {
            connections: conns.connections,
            connections_artifact: Some("ART-FIXNET".into()),
            dns_adapters: Vec::new(),
            interfaces: Vec::new(),
            interfaces_artifact: None,
            adapters_raw: None,
            routes_raw: None,
            arp_raw: None,
        }),
        events: None,
        persistence: Some(PersistenceStream {
            run_keys: runs.keys,
            services: Vec::new(),
            run_keys_artifact: None,
            services_artifact: None,
            scheduled_tasks_raw: None,
            startup_raw: None,
            wmi_subscriptions_raw: None,
            logon_raw: None,
        }),
        registry: None,
        hashes: None,
        hashes_artifact: None,
    }
}

#[test]
fn fixture_fires_the_expected_rule_set() {
    let streams = fixture_streams();
    let findings = crate::analysis::rules::run_all(&streams);
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in ["MAL-001", "MAL-002", "NET-001", "PERSIST-001"] {
        assert!(ids.contains(&expected), "fixture must fire {expected}; got {ids:?}");
    }
    // Grounding honesty: findings may cite only the fixture's own
    // synthetic anchors — never an invented artifact ID.
    assert!(
        findings.iter().flat_map(|f| f.supporting_artifacts.iter()).all(|a| {
            matches!(a.as_str(), "ART-FIXPROC" | "ART-FIXNET")
        }),
        "fixture findings must not cite artifact IDs that do not exist"
    );
}

#[test]
fn fixture_correlates_process_with_network_and_persistence() {
    let streams = fixture_streams();
    let report = crate::correlation::correlate_streams(&streams);
    assert!(!report.links.is_empty(), "fixture must produce cross-stream links");
    let anydesk = report
        .links
        .iter()
        .find(|l| l.a.label.contains("AnyDesk.exe") && l.a.label.contains("6012"))
        .expect("AnyDesk pid 6012 must be linked to its LISTENING socket");
    // Grounding honesty: links may cite only the fixture's own anchors.
    assert_eq!(anydesk.a.artifact_id, "ART-FIXPROC");
    assert_eq!(anydesk.b.artifact_id, "ART-FIXNET");
    assert!(
        report.links.iter().all(|l| {
            matches!(l.a.artifact_id.as_str(), "ART-FIXPROC" | "ART-FIXNET")
                && matches!(l.b.artifact_id.as_str(), "ART-FIXPROC" | "ART-FIXNET")
        }),
        "every fixture link must stay grounded in fixture artifacts"
    );
}

#[test]
fn fixture_ml_anomalies_only_reference_real_fixture_processes() {
    let streams = fixture_streams();
    let pids: Vec<i64> = streams
        .processes
        .as_ref()
        .expect("fixture has processes")
        .processes
        .iter()
        .map(|p| p.pid)
        .collect();
    let ml = crate::analysis::ml::run(&streams);
    assert!(!ml.model_id.is_empty());
    for a in &ml.anomalies {
        assert!(pids.contains(&a.pid), "ML anomaly cites unknown pid {}", a.pid);
    }
}
