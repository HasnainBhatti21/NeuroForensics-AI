# Acquisition Methods

How each MEMO Collector module acquires evidence, and what it honestly
declares as NOT AVAILABLE. All methods are read-only and use documented
Windows interfaces (Win32 APIs, WMI, event log, registry, standard
diagnostic commands).

## Common rules

- Every artifact is hashed with streaming SHA-256 at acquisition time.
- Every collector calls `check_cancel()` between artifacts; `wait_if_paused()`
  honors PAUSE.
- A collector failure logs a warning and the run continues.
- Subprocesses run with `CREATE_NO_WINDOW` and no interactive prompts.
- No forensic conclusions are drawn anywhere.

## 1. SystemMetadataCollector

| Artifact | Source |
| --- | --- |
| `system/os.json` | sysinfo host snapshot + environment + elevation flag |
| `system/wmi_operating_system.json` | WMI `Win32_OperatingSystem` |
| `system/wmi_computer_system.json` | WMI `Win32_ComputerSystem` |
| `system/wmi_baseboard.json` | WMI `Win32_BaseBoard` |
| `system/wmi_bios.json` | WMI `Win32_BIOS` |
| `system/disks.json` | sysinfo disks |
| `system/environment.json` | process environment + build lab (registry) |

WMI failure degrades gracefully to a warning.

## 2. CPUCollector

- `cpu/cpu_metadata.json`: sysinfo per-logical-processor snapshot +
  explicit note that CPU internal register state is NOT AVAILABLE to
  user-mode applications.
- `cpu/topology.json`: logical/physical counts, architecture.
- `cpu/wmi_processors.json`: WMI `Win32_Processor` rows.

## 3. MemoryCollector (artifact mode)

- `memory/memory_metadata.json`: declares ARTIFACT MODE and records the
  statement *"Full physical memory acquisition unavailable on this system."*
  Raw RAM imaging requires a signed acquisition driver and is never faked.
- `memory/memory_stats.json`: `GlobalMemoryStatusEx` statistics.
- `memory/process_memory.json`: working set / pagefile usage per process.
- `memory/memory_regions.json`: bounded `VirtualQueryEx` region maps for a
  limited number of processes (`REGION_SCAN_PROCESS_LIMIT`,
  `REGION_SCAN_MAX_REGIONS`). Inaccessible processes are counted, not hidden.

## 4. GPUCollector

- `gpu/gpu_metadata.json`: WMI `Win32_VideoController` rows with an explicit
  note that `AdapterRAM` is a 32-bit value (saturates at 4 GB) and that
  **VRAM raw acquisition is unavailable**.
- `gpu/gpu_processes.json`: `nvidia-smi` JSON when present; otherwise an
  honest NOT AVAILABLE note (no GPU process enumeration is assumed).
- `gpu/compute_metadata.json`: CUDA/OpenCL runtime detection only.
- `gpu/driver_files.json`: driver file facts from the registry.

## 5. ProcessCollector

- `processes/process_list.json`: sysinfo process refresh (user IDs enabled)
  + Toolhelp thread counts + PSAPI handle counts + token integrity level.
- `processes/process_tree.json`: parent/child reconstruction.
- `processes/modules.json`: `EnumProcessModulesEx` module lists for a
  bounded number of processes (`MODULE_ENUM_PROCESS_LIMIT`); protected
  processes are reported as inaccessible, never guessed.
- `processes/executable_paths.json`: unique executable paths.
- Processes are never labelled malicious; no process is terminated.

## 6. NetworkCollector (passive only)

- `network/adapters.json`: WMI `Win32_NetworkAdapterConfiguration`.
- `network/dns.json`: resolver configuration.
- `network/connections.json`: `netstat -ano` (TCP+UDP) with PID→name
  resolution.
- `network/routes.json`: `netstat -r`.
- `network/arp.json`: `arp -a`.
- `network/interfaces.json`: sysinfo interface counters.

No packet capture, no injection, no active probing.

## 7. WindowsEventCollector

Channels: System, Application, Security, Sysmon, PowerShell, and other
configured channels. **Sysmon is never assumed**: each channel is checked
with `wevtutil gli`; absent channels are SKIPPED with a reason.

- `windows_events/<channel>/events.json`: Get-WinEvent JSON export, capped
  by `events_per_channel` (newest first).
- `windows_events/<channel>/events_raw.xml`: `wevtutil qe /f:xml` raw copy.
- `windows_events/summary.json`: per-channel counts and statuses.

## 8. PersistenceCollector (read-only)

- `persistence/registry_runs.json`: Run/RunOnce keys (HKLM+HKCU, 9 keys).
- `persistence/startup.json`: startup folder listings.
- `persistence/services.json`: `Get-Service` JSON.
- `persistence/scheduled_tasks.json`: `Get-ScheduledTask` JSON.
- `persistence/wmi_subscriptions.json`: WMI `__EventFilter`,
  `__EventConsumer`, `__FilterToConsumerBinding`.
- `persistence/logon_and_other.json`: Winlogon, AppInit_DLLs, IFEO Debugger.

Nothing is created, modified or deleted.

## 9. RegistryCollector (targeted artifacts)

- `registry/artifacts/system_identity.json`: ComputerName,
  TimeZoneInformation.
- `registry/artifacts/installed_software.json`: Uninstall keys.
- `registry/artifacts/usb_history.json`: SYSTEM USBSTOR (access-denied is
  recorded, not treated as empty).
- `registry/artifacts/network_profiles.json`: NetworkList profiles.
- `registry/artifacts/sam_note.json`: explicit NOT AVAILABLE statement for
  the SAM hive (locked by the OS; never dumped).

## 10. HashCollector

- `hashes/hashes.json`: streaming SHA-256 of unique running-process
  executables, bounded by `max_executables_to_hash` and
  `max_hash_file_bytes`; skipped files are listed with the reason.

## DEMO MODE

`DemoCollector` replaces all collectors. Every artifact contains the
banner `SYNTHETIC DEMONSTRATION DATA - NOT REAL EVIDENCE` and the manifest
flags it `synthetic: true`. Demo mode never touches real evidence sources.

## Settings (acquisition limits)

| Setting | Default | Effect |
| --- | --- | --- |
| `events_per_channel` | 500 | cap per event log channel |
| `max_executables_to_hash` | 100 | cap for HashCollector |
| `max_hash_file_bytes` | 512 MB | files larger are skipped + noted |
