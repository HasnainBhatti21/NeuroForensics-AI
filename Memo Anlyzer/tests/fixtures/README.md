# tests/fixtures — isolated synthetic test inputs (§39)

These files are synthetic, clearly-labeled test fixtures:

- NEVER loaded by production code. The only reader is the cfg(test)
  module src/fixture_tests.rs, resolved through env!("CARGO_MANIFEST_DIR")
  at compile time. The released binary contains no path to this directory.
- NOT real evidence. Every name, pid, address and hash in these files is
  invented for regression testing. They must never be cited in a report,
  copied into a case database, or treated as observed fact. Section 39
  (no fake data) applies to everything the tool reports; these fixtures
  exist solely to exercise the analysis pipeline in a controlled,
  reproducible way, complementing the real-AIF-first verification strategy.
- Shaped like the collector's decoded JSON schemas (process_list.json,
  connections.json, registry_runs.json) so the exact decoders used in
  production are the ones under test.

Files:
- process_list.json  -> processes list     -> MAL-001, MAL-002, ML baseline
- connections.json   -> network connections -> NET-001, process-network links
- registry_runs.json -> registry Run keys  -> PERSIST-001

Any future fixture must follow the same contract: synthetic, labeled,
test-only, and decoded through the production decoders.
- NOT real evidence. Every name, pid, address and hash in these files is
  invented for regression testing. They must never be cited in a report,
  copied into a case database, or treated as observed fact. Section 39
  (no fake data) applies to everything the tool reports; these fixtures
  exist solely to exercise the analysis pipeline in a controlled,
  reproducible way, complementing the real-AIF-first verification strategy.
- Shaped like the collector's decoded JSON schemas (process_list.json,
  connections.json, registry_runs.json) so the exact decoders used in
  production are the ones under test.

Files:
- process_list.json  -> processes list      -> MAL-001, MAL-002, ML baseline
- connections.json   -> network connections -> NET-001, process-network links
- registry_runs.json -> registry Run keys   -> PERSIST-001

Any future fixture must follow the same contract: synthetic, labeled,
test-only, and decoded through the production decoders.
