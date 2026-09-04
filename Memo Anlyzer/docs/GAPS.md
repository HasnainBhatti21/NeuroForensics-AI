# GAPS — evidence streams not yet decoded by NEUROFORENSICS AI

Tracks artifact types present in real collector output (MEMO Collector)
that the analyzer's ingestion layer (`src/ingest/mod.rs` →
`decode_streams`) does **not** yet parse into typed streams. They are
still listed in the evidence tree and fully viewable via the detail
panel (Parsed View / Raw-Hex / Strings / Metadata tabs) — nothing is
hidden, nothing is fabricated. This file exists so these gaps are never
silently forgotten or buried in later phases.

Verified against the real reference case
`E:\Desktop\thE rEAL\CASE-2026-1070.AIF` on 2026-08-29.

## Resolved in Phase 3 (2026-08-30)

All three original gaps now have shipped decoders, tested against the
real AIF (`cargo test`, 61 passed):

| # | Container path | Size in reference case | Observed shape | Decoder shipped | Proving test |
|---|----------------|------------------------|----------------|-----------------|--------------|
| 1 | `processes/executable_paths.json` | 2 bytes | Empty JSON array `[]` | `parse_executable_paths` (lenient: array, wrapper-object and pid→path-map shapes) → `ProcessStream.executable_paths` + `executable_paths_present` | `real_case_ingests_all_streams` (present, honestly empty), `executable_paths_array_shape`, `executable_paths_map_and_empty_shapes`, Parsed View shows "present but zero mappings" |
| 2 | `network/interfaces.json` | 611 bytes | `{ acquired_at, interfaces: [ { mac_address, name, total_packets_received, total_packets_transmitted, total_received_bytes, total_transmitted_bytes } ] }` | `InterfacesDoc`/`InterfaceStat` → `NetworkStream.interfaces` (+ field index) | `real_case_ingests_all_streams` (non-empty, MAC present), `decodes_interfaces_from_real_schema` |
| 3 | `windows_events/<channel>/events_raw.xml` (6 channels in reference case: application, security, system, other/defender, other/powershell, other/wmi) | 292 KB – 609 KB each | Raw Windows event XML export | `parse_raw_xml_events` (hand-rolled scanner: EventID, Provider, TimeCreated, Level→name, EventData pairs, entity decoding) attached to its channel as `EventChannel.raw_events` | `real_case_ingests_all_streams` (raw XML attached to ≥5 channels), `parses_raw_event_xml_with_entities_and_named_data`, `regression_real_case_selection_never_blank` |

## Open gaps

None currently — every artifact in the reference case decodes to a
non-empty Parsed View or an explicit honest message (enforced by
`gui::parsed::tests::regression_real_case_selection_never_blank`).

## Rules for this file

- Entries are added when a real collector artifact is found with no
  decoder. Never remove an entry until the decoder ships and is tested
  against the real AIF.
- Resolved entries stay in the table above as an audit trail.
- No fabricated samples here: sizes/shapes were read directly from
  `CASE-2026-1070.AIF`.
