# NEUROFORENSICS AI

**AI-Powered CPU & GPU Forensic Analyzer**

NEUROFORENSICS AI is the **analysis component** of the MEMO Collector forensic
framework. It opens `.AIF` case files produced by MEMO Collector and analyzes
**only the evidence that actually exists** inside the case.

```
SUSPECT SYSTEM → MEMO COLLECTOR → FORENSIC AIF → NEUROFORENSICS AI
    → DETECT / VERIFY / INDEX → EVIDENCE TREE + EXPLORER
    → GROUNDED RULES + LOCAL ML → FINDINGS (ART-id cited)
    → TIMELINE / NETWORK / AI ASSISTANT → JSON / HTML / PDF REPORT
```

## Absolute forensic rules

- **Never fabricate evidence** — no invented processes, network activity,
  hashes, timestamps or findings. Missing evidence is displayed as
  *“Not present in evidence.”* When no evidence is loaded, the
  workstation stays empty.
- **No live collection** — the analyzer never scans the investigator's
  own system and never executes evidence of any kind.
- **Original AIF is read-only** — all investigator work (case database,
  notes, findings, reports) lives in the case folder, never inside the
  evidence image.
- **Every finding is traceable** — Finding → Rule/Model → Supporting
  Artifacts (`ART-xxxxxx`) → AIF entry → SHA-256 verification result.
- Evidence classes are kept distinct: OBSERVED FACT / INTEGRITY
  VERIFICATION / ANALYTICAL INDICATOR / ML ANOMALY / INVESTIGATOR
  INTERPRETATION.

## Workflow

1. **CREATE NEW CASE** — enter case number, case name, examiner,
   organization, description and case directory. A persistent SQLite
   case database (`case.db`) and case metadata are created.
2. **Add Evidence** — select a real `.AIF` image. The container is
   detected (ZIP signature), validated, SHA-256 verified against the
   external sidecar/custody record, deep-verified per artifact, indexed
   and decoded — streamed, never fully loaded into RAM.
3. **OPEN EXISTING CASE** — browse existing cases and restore the
   previously indexed evidence, artifacts, findings and examination
   state from the case database.
4. **Run Analysis** — grounded detection rules + a local isolation
   forest run over the decoded evidence only; every finding cites the
   artifacts it is based on. The AI assistant answers questions from
   the same indexed evidence.
5. **Export** — JSON / HTML / PDF forensic reports into `<case>/reports`.

## Technology

| Concern       | Choice                                    |
|---------------|-------------------------------------------|
| Language      | Rust                                      |
| GUI           | egui / eframe (native desktop)            |
| Database      | SQLite (`case.db` per case folder)        |
| Serialization | JSON / serde                              |
| Hashing       | SHA-256 (container + per-artifact)        |
| ML            | Local, offline isolation forest           |

Module layout: `casemgmt` (case manager + SQLite), `aifzip` (AIF v1
reader: detection, schema, integrity), `ingest` (index + typed stream
decoders), `analysis` (rules, ML, assistant), `reporting`
(JSON/HTML/PDF), `gui` (landing, workstation, tree, explorer, timeline,
network, findings, AI chat) and `ml` (model primitives).

## Build & run

Requires a Rust toolchain. On this workstation the project pins the
`stable-x86_64-pc-windows-gnu` toolchain via `rustup override` because no
MSVC linker is installed; the WinLibs GCC `mingw64\bin` directory must be
first on `PATH`:

```powershell
$env:PATH = "C:\Users\Jhon\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin;" + $env:PATH
cargo run              # development build
cargo test             # full test suite (41 tests)
cargo build --release  # Windows release binary
```

The release binary lands in `target/release/neuroforensics-ai.exe`.
Tests that exercise the real reference case activate automatically when
`E:\Desktop\thE rEAL\CASE-2026-1070.AIF` is present.

See [`docs/AIF-SPEC.md`](docs/AIF-SPEC.md) for the AIF v1 container
contract shared with MEMO Collector.

## Development status

- [x] **Case management** — CREATE/OPEN CASE, persistent SQLite case
  database, evidence registration, examination-state restore.
- [x] **AIF v1 reader** — ZIP container detection (never assumes JSON),
  manifest/case/custody parsing, schema validation, streaming access.
- [x] **Integrity** — streamed container SHA-256 vs external
  sidecar/custody, per-artifact deep verification, forensic errors.
- [x] **Evidence ingest** — typed decoders for system/CPU/GPU/process/
  network/events/persistence/registry/hash streams, null-tolerant,
  evidence tree with only streams actually present.
- [x] **Workstation GUI** — landing screen, evidence tree, artifact
  explorer with Hex/Strings/Metadata/AI tabs, timeline, network view,
  findings panel, AI assistant, dark/light themes.
- [x] **Grounded analysis** — deterministic rules + local isolation
  forest + assistant, every output linked to `ART-xxxxxx` evidence.
- [x] **Reporting** — JSON / HTML / PDF with evidence-class separation;
  absent evidence is reported as absent, never generated.
