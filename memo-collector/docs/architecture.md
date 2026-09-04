# MEMO Collector - Architecture

## Overview

MEMO Collector is a single Rust binary (`MEMOCollector.exe`) combining an
acquisition engine library and an egui/eframe GUI. There is no installer,
no service and no runtime dependency.

```
+---------------------------------------------------------------+
|                       MEMOCollector.exe                        |
|                                                               |
|  GUI (egui/eframe)            Engine (worker thread)          |
|  -------------------          ------------------------        |
|  Dashboard                    run_acquisition()               |
|  New Case   -- AppState -->   collectors x10                  |
|  Acquisition <-- progress--   manifest / custody              |
|  Evidence / Integrity         AIF packaging + SHA-256         |
|  Case Info / Settings / About reporting (HTML)               |
+---------------------------------------------------------------+
                 |                          |
                 v                          v
      Documented Win32 APIs        CASE-XXXX.AIF + sidecars
   (WMI, Toolhelp, PSAPI, registry,   (destination folder)
    event log, netstat)
```

## Crate layout

| Module | Responsibility |
| --- | --- |
| `app::engine` | Orchestrates one acquisition: staging dir, custody log bind, host snapshot, module loop, manifest finalize, AIF packaging, hashing, sidecar/custody/report emission, outcome. |
| `app::state` | `AppState` shared between GUI and engine: screen router, case form, settings, live progress (`Arc<Mutex<AcquisitionProgress>>`), control flags (`Arc<AcquisitionControl>`), last manifest, verification state. |
| `gui` | Dark SOC-style theme + 8 screens (Dashboard, New Case, Acquisition, Evidence, Integrity, Case Info, Settings, About). |
| `collectors` | `ICollector` trait, `CollectContext`, progress/warning/failure records, `build_collector(id, demo)` factory, 10 collectors + `DemoCollector`. |
| `evidence` | `ArtifactRecord`, `Manifest`, `ChainOfCustody`, AIF packaging/verification/manifest-read/extract. |
| `hashing::sha256` | Streaming SHA-256 (1 MiB buffer): hash bytes/files/readers, single-pass copy+hash. |
| `reporting::html` | Factual dark-themed HTML acquisition report (no conclusions). |
| `win` | Thin, documented Win32 helpers: privilege check/elevation, memory status, process modules/threads/handles/integrity, netstat/arp parsing, event log queries, GPU adapter enumeration, PowerShell JSON runner. |

## Threading model

- The GUI thread owns `AppState` and polls progress.
- Acquisition runs on a dedicated `std::thread` created by the New Case
  screen; it communicates only through:
  - `Arc<Mutex<AcquisitionProgress>>` (phase, modules, counters, warnings),
  - `Arc<AcquisitionControl>` (`cancel` / `pause` atomics),
- `ctx.check_cancel()` is called at every artifact boundary; `wait_if_paused()`
  blocks the worker while paused. Cancel never aborts silently: collected
  artifacts are packaged as a `PARTIAL ACQUISITION`.

## Collector contract (`ICollector`)

```rust
fn id(&self) -> CollectorId;
fn name(&self) -> &'static str;
fn initialize(&mut self, ctx) -> Result<(), CollectorError>;
fn check_availability(&self) -> Availability;      // Available | NotAvailable{reason}
fn collect(&mut self, ctx) -> Result<(), CollectorError>;
fn cleanup(&mut self);
```

Error policy: **one collector failing never terminates the acquisition.**
The engine maps every outcome to a module state
(`Completed / Skipped / Failed / Cancelled`), records a warning, and moves
to the next module.

`CollectContext` provides the only legal artifact registration paths:
`add_json`, `add_bytes`, `add_file_copy` — each writes to the staging
directory, computes SHA-256, assigns an artifact ID and registers the
record in the manifest. Collectors cannot inject un-hashed data.

## Error taxonomy

`CollectorError { module, code, description, recommended_action }` with
codes such as `CANCELLED`, `NOT_AVAILABLE`, `SERIALIZE`, `STAGING_IO`,
`WMI`, `SUBPROCESS`, `ACCESS_DENIED`. Every error carries a human-readable
recommended action and is mirrored to the acquisition log.

## Honesty guarantees (core product rules)

- No fake evidence: unavailable sources (RAM image, VRAM, CPU registers,
  SAM) produce explicit `NOT AVAILABLE` statements in their artifacts.
- No forensic conclusions anywhere in the UI or reports.
- Demo mode artifacts are always flagged `synthetic: true` with a visible
  banner; production paths never use synthetic data.
- Read-only acquisition: no host mutation, no process termination.

## Build configuration

- `[profile.release] opt-level = 3, lto = "thin", strip = true`
- Binary name fixed to `MEMOCollector` regardless of crate name.
- `windows` crate features limited to the API families actually used.
