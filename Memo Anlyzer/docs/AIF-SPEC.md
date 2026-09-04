# AIF v1 Container Specification

**Acquisition Image Format — as written by MEMO Collector and read by
NEUROFORENSICS AI.** This document is the shared contract between the
collector (write side) and the analyzer (read side). The two must never
diverge; when the collector changes, this spec and `src/aifzip/` change
together.

## 1. Physical format

An AIF case file is a **ZIP archive (Deflate compression)** carrying the
extension `.AIF`. It is **not** a JSON file, not a raw image and not a
custom binary container.

- Detection: the analyzer reads the first bytes and requires the ZIP
  local-file-header signature `50 4B 03 04` (`PK\x03\x04`).
- A file that is JSON (or anything else) is rejected with a forensic
  error such as *“Not an AIF container — expected ZIP signature …”*. The
  analyzer never falls back to “maybe it is JSON”.
- Required root entries: `manifest.json`, `case.json`. `custody.json`
  is expected but its absence is tolerated with a warning.

## 2. Container layout

```
CASE-XXXX.AIF
├── manifest.json          ← evidence manifest (authoritative index)
├── case.json              ← case metadata document
├── custody.json           ← chain-of-custody record (inside copy)
├── system/                ← OS / host metadata (os.json, host.json, …)
├── cpu/                   ← CPU snapshot + metadata
├── gpu/                   ← GPU devices + GPU processes
├── processes/             ← process list, process tree, loaded modules
├── network/               ← connections, adapters, DNS, ARP, routes
├── windows_events/
│   ├── system/            ← events.json per channel
│   ├── application/
│   ├── security/
│   └── other/
│       ├── defender/
│       ├── powershell/
│       └── wmi/
├── persistence/           ← run keys, scheduled tasks, services, WMI subs
├── registry/artifacts/    ← registry artifact exports
├── hashes/                ← file/artifact hash lists
├── logs/                  ← collector diagnostic logs
└── reports/               ← collector-side summary reports
```

A module directory exists **only when the collector actually captured
it**. The analyzer derives the evidence tree from the entries that are
present; absent streams are displayed as *“Not present in evidence”*.

## 3. Root documents

### 3.1 `case.json`

| Field             | Type   | Notes                                          |
|-------------------|--------|------------------------------------------------|
| `format`          | string | Container format name (`"AIF"`).               |
| `format_version`  | u32    | Currently `1`.                                 |
| `case`            | object | Case identity entered by the investigator: `case_id`, `case_name`, `investigator_name`, `organization`, `evidence_description`, `acquisition_notes`, `reference_number`, `destination`, `demo_mode`, `created_at`. |
| `container_sha256`| string | **Always `null` inside the container** — a container cannot contain its own hash. The real hash lives externally (see §5). |

`demo_mode` is only true for clearly labelled synthetic demonstration
acquisitions. The analyzer surfaces such cases with a permanent
*DEMO / SYNTHETIC EVIDENCE* banner.

### 3.2 `manifest.json`

The authoritative evidence index.

| Field         | Type   | Notes                                             |
|---------------|--------|---------------------------------------------------|
| `case_id`     | string | Case identifier (matches `case.json`).            |
| `case_name`   | string |                                                   |
| `collector`   | object | `name`, `version`, `build`, `platform`.           |
| `host`        | object | `hostname`, `os`, `os_version`, `architecture`, `kernel_version`, `boot_time`, `username`, `domain`, `elevated`. |
| `acquisition` | object | `start_time`, `end_time`, `operator`, `method`, `status` (`COMPLETED`, `COMPLETED_WITH_FAILURES`, `PARTIAL`, `CANCELLED`, `FAILED`). |
| `modules[]`   | array  | Per-module execution summary (see below).           |
| `artifacts[]` | array  | One record per evidence artifact (see below).     |
| `warnings[]`  | array  | Collector-side caveats carried into the report.   |
| `errors[]`    | array  | Collector-side errors.                            |
| `integrity`   | object | `algorithm`, `artifact_hashes_in_manifest`, `aif_sha256` (**null inside the container** by design). |

**`modules[]` entry:** `module_id`, `module_name`, `status`, `reason`,
`artifacts`, `bytes`, `started_at`, `finished_at`, `warnings[]`.

**`artifacts[]` entry:**

| Field              | Type   | Notes                                        |
|--------------------|--------|----------------------------------------------|
| `artifact_id`      | string | Unique collector-assigned ID `ART-xxxxxx`.   |
| `relative_path`    | string | Path relative to the container root.         |
| `size`             | u64    | Declared artifact size in bytes.             |
| `sha256`           | string | Lowercase hex SHA-256 of the artifact body.  |
| `acquisition_time` | string | RFC 3339 timestamp.                          |
| `source`           | string | Human-readable data source description.      |
| `collector`        | string | Module id (`system`, `processes`, `network`, …). |
| `status`           | string | `ACQUIRED` \| `PARTIAL` \| `SKIPPED` \| `FAILED`. |
| `notes`            | string? | Optional collector notes.                   |
| `synthetic`        | bool   | True only for labelled demo data.            |

### 3.3 `custody.json`

Chain-of-custody record duplicated inside the container: `case_id`,
`collector_version`, `hostname`, `operator`, `start_time`, `end_time`,
`modules_requested[]`, `modules_successful[]`, `modules_failed[]`,
`modules_skipped[]`, `warning_count`, `artifact_count`, `aif_sha256`
(**empty inside the container** — the external custody copy carries the
hash), `status`, `notice`.

## 4. Evidence payload encoding

- JSON artifacts are UTF-8 JSON documents. **Any field the collector
  could not capture is written as `null`, never omitted silently and
  never invented.** The analyzer decodes every stream null-tolerantly.
- Examples of module payload shapes: `processes/process_list.json`
  (array of process records), `processes/modules.json` (`{"processes":
  { "<pid>": [module, …] }, …}` map form), `network/connections.json`,
  `windows_events/<channel>/events.json`, `hashes/hashes.json`
  (`{"records":[…]}`).

## 5. Integrity model

The container cannot hold its own hash, so trust is anchored externally:

1. **Sidecar** — `<CASE>.AIF.sha256` next to the evidence image,
   containing the container SHA-256.
2. **Custody copy** — `<CASE>.custody.json` next to the evidence image,
   whose `aif_sha256` field holds the container hash.

Analyzer verification pipeline:

1. Compute the SHA-256 of the whole `.AIF` file (streamed — multi-GB
   images are never loaded into RAM) and compare against the sidecar /
   custody expectation. No external hash ⇒ explicit warning, never a
   silent pass.
2. Deep verification: for every `artifacts[]` record, stream the
   container entry, re-compute SHA-256 and compare with the manifest
   value. Mismatches and missing entries are reported per artifact.

## 6. Analyzer access rules

- The original `.AIF` is **strictly read-only**; the analyzer never
  writes, moves or re-compresses it.
- Large entries are read through **streaming/chunked access**
  (`with_entry_reader`), with a 1 MiB cap for UI previews (hex/strings).
- Every artifact shown in the UI must resolve to a manifest record and
  a container entry; findings cite `ART-xxxxxx` IDs that are checked
  against the index before display.
- Evidence that is absent is reported as *“Not present in evidence”* —
  the analyzer never substitutes generated data.
