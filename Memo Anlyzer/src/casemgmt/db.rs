//! Persistent SQLite case database (`case.db`).
//!
//! Stores everything that must survive closing the application: case
//! metadata, registered evidence images, indexed artifact records,
//! findings mirror, notes, bookmarks and examination state. Opening an
//! existing case restores all of it without touching the original AIF.

use rusqlite::{params, Connection, OptionalExtension};

/// Case identity as entered by the examiner at CREATE NEW CASE time.
#[derive(Clone, Debug, Default)]
pub struct CaseMeta {
    pub case_number: String,
    pub case_name: String,
    pub examiner: String,
    pub organization: String,
    pub description: String,
    pub created_at: String,
    pub case_dir: String,
    /// RFC 3339 timestamp of the last time this case was opened.
    pub last_opened: String,
}

/// A registered .AIF evidence image (kept at its original location;
/// only the path, size and integrity values are stored here).
#[derive(Clone, Debug)]
pub struct EvidenceImageRecord {
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    /// SHA-256 of the whole .AIF container, computed by this tool.
    pub container_sha256: String,
    /// Expected hash from the `.AIF.sha256` sidecar / custody record.
    pub expected_sha256: Option<String>,
    /// Container hash comparison result (None = no sidecar found).
    pub container_verified: Option<bool>,
    pub case_id: Option<String>,
    pub format_version: Option<u32>,
    pub demo_mode: bool,
    pub added_at: String,
}

#[derive(Clone, Debug)]
pub struct StoredEvidenceImage {
    pub id: i64,
    pub record: EvidenceImageRecord,
}

/// One artifact record mirrored from the AIF `manifest.json`.
#[derive(Clone, Debug)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub acquisition_time: String,
    pub source: String,
    pub collector: String,
    pub status: String,
    pub synthetic: bool,
    /// Per-artifact SHA-256 re-hash result (None = not deep-verified).
    pub hash_verified: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct StoredArtifact {
    pub image_id: i64,
    pub reference: ArtifactRef,
}

#[derive(Clone, Debug)]
pub struct CaseNote {
    pub id: i64,
    pub artifact_id: Option<String>,
    pub text: String,
    pub created_at: String,
}

/// One immutable §41 chain-of-custody entry.
#[derive(Clone, Debug)]
pub struct CustodyEntry {
    pub ts: String,
    pub examiner: String,
    pub operation: String,
    pub detail: String,
}

/// One persisted §22 timeline event (mirrored from real evidence
/// timestamps at ingest time so the timeline survives restarts).
#[derive(Clone, Debug)]
pub struct TimelineEventRecord {
    /// RFC 3339 timestamp exactly as it appears in the evidence.
    pub ts: String,
    pub category: String,
    pub label: String,
    pub detail: String,
    pub artifact_id: Option<String>,
}

/// One persisted §21 field-index row (artifact field values, used by
/// global search so it works after restart without re-ingest).
#[derive(Clone, Debug)]
pub struct FieldIndexRow {
    pub artifact_id: String,
    pub field: String,
    pub value: String,
    /// Pre-lowercased `field + value` for case-insensitive search.
    pub haystack: String,
}

/// §35 finding workflow status. Findings are persisted NEW and only
/// ever change status through an explicit investigator action — the
/// tool never auto-confirms suspicious activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingStatus {
    New,
    Reviewed,
    Confirmed,
    Dismissed,
}

impl FindingStatus {
    pub const ALL: [FindingStatus; 4] = [
        FindingStatus::New,
        FindingStatus::Reviewed,
        FindingStatus::Confirmed,
        FindingStatus::Dismissed,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FindingStatus::New => "NEW",
            FindingStatus::Reviewed => "REVIEWED",
            FindingStatus::Confirmed => "CONFIRMED",
            FindingStatus::Dismissed => "DISMISSED",
        }
    }

    /// Strict parser: any unknown value is rejected rather than guessed.
    pub fn parse(value: &str) -> Result<FindingStatus, String> {
        match value {
            "NEW" => Ok(FindingStatus::New),
            "REVIEWED" => Ok(FindingStatus::Reviewed),
            "CONFIRMED" => Ok(FindingStatus::Confirmed),
            "DISMISSED" => Ok(FindingStatus::Dismissed),
            other => Err(format!("unknown finding status '{other}' — expected NEW/REVIEWED/CONFIRMED/DISMISSED")),
        }
    }
}

/// One §35 finding row (rule indicator or ML anomaly) persisted with
/// its grounding artifact IDs, status and investigator notes.
#[derive(Clone, Debug)]
pub struct FindingRow {
    /// Stable identifier: rule id (e.g. NET-001) or model id for anomalies.
    pub finding_id: String,
    /// Identity across re-runs: finding_id + evidence basis, so a
    /// re-analysis preserves the investigator's status and notes.
    pub finding_key: String,
    pub severity: String,
    pub category: String,
    pub confidence: Option<f64>,
    pub method: String,
    pub title: String,
    pub description: String,
    pub reasoning: String,
    pub supporting_artifacts: Vec<String>,
    /// RFC 3339 timestamp of the run that produced this finding.
    pub run_at: String,
    pub status: FindingStatus,
    pub investigator_note: String,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS case_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_images (
    id                  INTEGER PRIMARY KEY,
    path                TEXT NOT NULL,
    file_name           TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL,
    container_sha256    TEXT NOT NULL,
    expected_sha256     TEXT,
    container_verified  INTEGER,
    case_id             TEXT,
    format_version      INTEGER,
    demo_mode           INTEGER NOT NULL DEFAULT 0,
    added_at            TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    image_id          INTEGER NOT NULL REFERENCES evidence_images(id) ON DELETE CASCADE,
    artifact_id       TEXT NOT NULL,
    relative_path     TEXT NOT NULL,
    size              INTEGER NOT NULL,
    sha256            TEXT NOT NULL,
    acquisition_time  TEXT NOT NULL DEFAULT '',
    source            TEXT NOT NULL DEFAULT '',
    collector         TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'ACQUIRED',
    synthetic         INTEGER NOT NULL DEFAULT 0,
    hash_verified     INTEGER,
    PRIMARY KEY (image_id, artifact_id)
);
CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY,
    run_at   TEXT NOT NULL,
    payload  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY,
    artifact_id TEXT,
    text        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bookmarks (
    artifact_id TEXT PRIMARY KEY,
    note        TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exam_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"#;

/// Version recorded for the baseline `SCHEMA` alone.
const BASELINE_SCHEMA_VERSION: i64 = 1;

/// Target schema version of this build. Bump when a migration is added.
pub const CURRENT_SCHEMA_VERSION: i64 = BASELINE_SCHEMA_VERSION + MIGRATIONS.len() as i64;

/// Ordered migrations applied after the baseline `SCHEMA`. Entry *i*
/// upgrades the database from version *BASELINE_SCHEMA_VERSION + i* to
/// *BASELINE_SCHEMA_VERSION + i + 1*. Later phases append table
/// additions here, never editing `SCHEMA` in place for existing
/// deployments.
const MIGRATIONS: &[&str] = &[
    // v1 → v2 (Phase 4, spec §45 + §18 + §21 + §22): persistent
    // timeline events and persistent field index for global search.
    r#"
    CREATE TABLE IF NOT EXISTS timeline_events (
        id          INTEGER PRIMARY KEY,
        image_id    INTEGER NOT NULL REFERENCES evidence_images(id) ON DELETE CASCADE,
        ts          TEXT NOT NULL,
        category    TEXT NOT NULL,
        label       TEXT NOT NULL,
        detail      TEXT NOT NULL DEFAULT '',
        artifact_id TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_timeline_events_image_ts
        ON timeline_events(image_id, ts);
    CREATE TABLE IF NOT EXISTS field_index (
        image_id    INTEGER NOT NULL REFERENCES evidence_images(id) ON DELETE CASCADE,
        artifact_id TEXT NOT NULL,
        field       TEXT NOT NULL,
        value       TEXT NOT NULL,
        haystack    TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_field_index_image ON field_index(image_id);
    "#,
    // v2 → v3 (Phase 8.5, spec §35 + §36): row-level findings with a
    // status workflow (NEW/REVIEWED/CONFIRMED/DISMISSED), investigator
    // notes per finding, and the finding_artifacts join table. The
    // legacy `findings` payload table stays untouched for restore
    // compatibility; rows never carry automatic CONFIRMED status.
    r#"
    CREATE TABLE IF NOT EXISTS finding_rows (
        id                INTEGER PRIMARY KEY,
        image_id          INTEGER NOT NULL REFERENCES evidence_images(id) ON DELETE CASCADE,
        finding_id        TEXT NOT NULL,
        finding_key       TEXT NOT NULL,
        run_at            TEXT NOT NULL,
        severity          TEXT NOT NULL,
        category          TEXT NOT NULL,
        confidence        REAL,
        method            TEXT NOT NULL,
        title             TEXT NOT NULL,
        description       TEXT NOT NULL,
        reasoning         TEXT NOT NULL,
        status            TEXT NOT NULL DEFAULT 'NEW',
        investigator_note TEXT NOT NULL DEFAULT '',
        created_at        TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_rows_image_key
        ON finding_rows(image_id, finding_key);
    CREATE TABLE IF NOT EXISTS finding_artifacts (
        finding_row_id INTEGER NOT NULL REFERENCES finding_rows(id) ON DELETE CASCADE,
        artifact_id    TEXT NOT NULL,
        PRIMARY KEY (finding_row_id, artifact_id)
    );
    "#,
    // v3 → v4 (Phase 10, spec §41 + §47): append-only chain-of-custody
    // log — every processing/analysis operation the tool performs is
    // recorded with timestamp and examiner. Entries are never updated
    // or deleted through the public API.
    r#"
    CREATE TABLE IF NOT EXISTS custody_log (
        id        INTEGER PRIMARY KEY,
        ts        TEXT NOT NULL,
        examiner  TEXT NOT NULL DEFAULT '',
        operation TEXT NOT NULL,
        detail    TEXT NOT NULL DEFAULT ''
    );
    "#,
];

/// Apply pending migrations and record the resulting schema version.
fn apply_migrations(conn: &Connection) -> Result<i64, String> {
    let mut version: i64 = conn
        .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| r.get(0))
        .unwrap_or(0);
    if version == 0 {
        // Baseline-only database (just created, or pre-migration-era):
        // the baseline schema corresponds to the baseline version.
        conn.execute(
            "INSERT INTO schema_version(version) VALUES (?1)",
            params![BASELINE_SCHEMA_VERSION],
        )
        .map_err(|e| e.to_string())?;
        version = BASELINE_SCHEMA_VERSION;
    }
    for (idx, sql) in MIGRATIONS.iter().enumerate() {
        let target = BASELINE_SCHEMA_VERSION + idx as i64 + 1;
        if version < target {
            conn.execute_batch(sql).map_err(|e| format!("Migration to schema v{target} failed: {e}"))?;
            conn.execute("INSERT INTO schema_version(version) VALUES (?1)", params![target])
                .map_err(|e| e.to_string())?;
            version = target;
        }
    }
    Ok(version)
}

/// Open handle to one case database.
pub struct CaseDatabase {
    conn: Connection,
}

impl CaseDatabase {
    /// Create a new case database with schema + metadata.
    pub fn create(path: &std::path::Path, meta: &CaseMeta) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("SQLite error: {e}"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| format!("Schema error: {e}"))?;
        apply_migrations(&conn)?;
        let mut db = Self { conn };
        db.write_meta(meta)?;
        db.mark_opened();
        Ok(db)
    }

    /// Open an existing case database (validates that metadata exists).
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!("Case database not found: {}", path.display()));
        }
        let conn = Connection::open(path).map_err(|e| format!("SQLite error: {e}"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| e.to_string())?;
        // Ensure schema (idempotent) so older DBs gain new tables.
        conn.execute_batch(SCHEMA).map_err(|e| format!("Schema error: {e}"))?;
        apply_migrations(&conn)?;
        let db = Self { conn };
        // Must contain case metadata to count as a NeuroForensics case.
        if db.meta().case_number.is_empty() {
            return Err(format!(
                "{} is not a valid NeuroForensics case database (missing case metadata).",
                path.display()
            ));
        }
        Ok(db)
    }

    fn write_meta(&mut self, meta: &CaseMeta) -> Result<(), String> {
        let rows = [
            ("case_number", meta.case_number.as_str()),
            ("case_name", meta.case_name.as_str()),
            ("examiner", meta.examiner.as_str()),
            ("organization", meta.organization.as_str()),
            ("description", meta.description.as_str()),
            ("created_at", meta.created_at.as_str()),
            ("case_dir", meta.case_dir.as_str()),
        ];
        for (k, v) in rows {
            self.conn
                .execute(
                    "INSERT INTO case_meta(key, value) VALUES(?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![k, v],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn meta(&self) -> CaseMeta {
        let get = |key: &str| -> String {
            self.conn
                .query_row("SELECT value FROM case_meta WHERE key = ?1", params![key], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap_or_default()
        };
        CaseMeta {
            case_number: get("case_number"),
            case_name: get("case_name"),
            examiner: get("examiner"),
            organization: get("organization"),
            description: get("description"),
            created_at: get("created_at"),
            case_dir: get("case_dir"),
            last_opened: get("last_opened"),
        }
    }

    /// Record that the case was opened now (spec §5 RECENT CASES).
    pub fn mark_opened(&mut self) {
        let _ = self.conn.execute(
            "INSERT INTO case_meta(key, value) VALUES('last_opened', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![chrono::Local::now().to_rfc3339()],
        );
    }

    /// Schema version recorded in this database.
    pub fn schema_version(&self) -> i64 {
        self.conn
            .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| r.get(0))
            .unwrap_or(0)
    }

    // ---------------- evidence images ----------------

    pub fn add_evidence_image(&mut self, rec: &EvidenceImageRecord) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO evidence_images
                 (path, file_name, size_bytes, container_sha256, expected_sha256,
                  container_verified, case_id, format_version, demo_mode, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    rec.path,
                    rec.file_name,
                    rec.size_bytes,
                    rec.container_sha256,
                    rec.expected_sha256,
                    rec.container_verified.map(|v| if v { 1 } else { 0 }),
                    rec.case_id,
                    rec.format_version.map(|v| v as i64),
                    if rec.demo_mode { 1 } else { 0 },
                    rec.added_at,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn evidence_images(&self) -> Vec<StoredEvidenceImage> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, path, file_name, size_bytes, container_sha256, expected_sha256,
                    container_verified, case_id, format_version, demo_mode, added_at
             FROM evidence_images ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            let verified: Option<i64> = r.get(6)?;
            let fmt: Option<i64> = r.get(8)?;
            let demo: i64 = r.get(9)?;
            Ok(StoredEvidenceImage {
                id: r.get(0)?,
                record: EvidenceImageRecord {
                    path: r.get(1)?,
                    file_name: r.get(2)?,
                    size_bytes: r.get::<_, i64>(3)? as u64,
                    container_sha256: r.get(4)?,
                    expected_sha256: r.get(5)?,
                    container_verified: verified.map(|v| v != 0),
                    case_id: r.get(7)?,
                    format_version: fmt.map(|v| v as u32),
                    demo_mode: demo != 0,
                    added_at: r.get(10)?,
                },
            })
        });
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn update_image_verification(
        &mut self,
        image_id: i64,
        verified: Option<bool>,
        expected: Option<&str>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE evidence_images SET container_verified = ?2, expected_sha256 = COALESCE(?3, expected_sha256) WHERE id = ?1",
                params![image_id, verified.map(|v| if v { 1 } else { 0 }), expected],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Refresh the descriptive fields of an already-registered image
    /// (idempotent re-ingest of the same file reuses the row instead of
    /// duplicating it).
    pub fn update_image_record(&mut self, image_id: i64, rec: &EvidenceImageRecord) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE evidence_images
                 SET file_name = ?2, size_bytes = ?3, container_sha256 = ?4,
                     expected_sha256 = COALESCE(?5, expected_sha256),
                     container_verified = ?6, case_id = COALESCE(?7, case_id),
                     format_version = COALESCE(?8, format_version), demo_mode = ?9
                 WHERE id = ?1",
                params![
                    image_id,
                    rec.file_name,
                    rec.size_bytes as i64,
                    rec.container_sha256,
                    rec.expected_sha256,
                    rec.container_verified.map(|v| if v { 1 } else { 0 }),
                    rec.case_id,
                    rec.format_version.map(|v| v as i64),
                    if rec.demo_mode { 1 } else { 0 },
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Record a re-verification pass: the freshly computed container
    /// hash plus the sidecar comparison result.
    pub fn update_image_hash_and_verification(
        &mut self,
        image_id: i64,
        container_sha256: &str,
        verified: Option<bool>,
        expected: Option<&str>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE evidence_images
                 SET container_sha256 = ?2, container_verified = ?3,
                     expected_sha256 = COALESCE(?4, expected_sha256)
                 WHERE id = ?1",
                params![
                    image_id,
                    container_sha256,
                    verified.map(|v| if v { 1 } else { 0 }),
                    expected
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Remove a registered evidence image (and, via cascade, its
    /// indexed artifact rows). Returns the number of images deleted.
    pub fn remove_evidence_image(&mut self, image_id: i64) -> Result<usize, String> {
        self.conn
            .execute("DELETE FROM evidence_images WHERE id = ?1", params![image_id])
            .map_err(|e| e.to_string())
    }

    /// How many manifest artifacts are indexed for one image.
    pub fn artifact_count(&self, image_id: i64) -> usize {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM artifacts WHERE image_id = ?1",
                params![image_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
    }

    // ---------------- artifacts ----------------

    pub fn insert_artifacts(&mut self, image_id: i64, refs: &[ArtifactRef]) -> Result<(), String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for a in refs {
            tx.execute(
                "INSERT OR REPLACE INTO artifacts
                 (image_id, artifact_id, relative_path, size, sha256, acquisition_time,
                  source, collector, status, synthetic, hash_verified)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    image_id,
                    a.artifact_id,
                    a.relative_path,
                    a.size as i64,
                    a.sha256,
                    a.acquisition_time,
                    a.source,
                    a.collector,
                    a.status,
                    if a.synthetic { 1 } else { 0 },
                    a.hash_verified.map(|v| if v { 1 } else { 0 }),
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist one per-artifact re-hash result (VERIFY EVIDENCE).
    pub fn set_artifact_verification(
        &mut self,
        image_id: i64,
        artifact_id: &str,
        verified: bool,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE artifacts SET hash_verified = ?3 WHERE image_id = ?1 AND artifact_id = ?2",
                params![image_id, artifact_id, if verified { 1 } else { 0 }],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn all_artifacts(&self) -> Vec<StoredArtifact> {
        let mut stmt = match self.conn.prepare(
            "SELECT image_id, artifact_id, relative_path, size, sha256, acquisition_time,
                    source, collector, status, synthetic, hash_verified
             FROM artifacts ORDER BY image_id, artifact_id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            let synthetic: i64 = r.get(9)?;
            let hv: Option<i64> = r.get(10)?;
            Ok(StoredArtifact {
                image_id: r.get(0)?,
                reference: ArtifactRef {
                    artifact_id: r.get(1)?,
                    relative_path: r.get(2)?,
                    size: r.get::<_, i64>(3)? as u64,
                    sha256: r.get(4)?,
                    acquisition_time: r.get(5)?,
                    source: r.get(6)?,
                    collector: r.get(7)?,
                    status: r.get(8)?,
                    synthetic: synthetic != 0,
                    hash_verified: hv.map(|v| v != 0),
                },
            })
        });
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    // ---------------- findings / notes / bookmarks / state ----------------

    pub fn save_findings(&mut self, payload: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO findings(run_at, payload) VALUES (?1, ?2)",
                params![chrono::Local::now().to_rfc3339(), payload],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn latest_findings(&self) -> Option<String> {
        self.conn
            .query_row(
                "SELECT payload FROM findings ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .unwrap_or(None)
    }

    // ---------------- §35 row-level findings + status workflow ----------------

    /// Persist the findings of one analysis run. Re-running the
    /// analysis for the same image replaces the rows but PRESERVES the
    /// investigator's status and notes for every finding whose
    /// `finding_key` survived (same identity, same evidence basis).
    /// New rows always enter as NEW — §35 forbids auto-confirmation.
    pub fn upsert_finding_rows(
        &mut self,
        image_id: i64,
        rows: &[FindingRow],
    ) -> Result<(), String> {
        // Prior workflow state keyed by finding identity.
        let prior: std::collections::HashMap<String, (String, String)> = self
            .finding_rows(image_id)
            .into_iter()
            .map(|r| (r.finding_key.clone(), (r.status.label().to_string(), r.investigator_note)))
            .collect();
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM finding_rows WHERE image_id = ?1", params![image_id])
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (status, note) = prior
                .get(&row.finding_key)
                .map(|(s, n)| (s.as_str(), n.as_str()))
                // §35: findings enter NEW; never auto-confirmed.
                .unwrap_or(("NEW", ""));
            tx.execute(
                "INSERT INTO finding_rows
                 (image_id, finding_id, finding_key, run_at, severity, category, confidence,
                  method, title, description, reasoning, status, investigator_note, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    image_id,
                    row.finding_id,
                    row.finding_key,
                    row.run_at,
                    row.severity,
                    row.category,
                    row.confidence,
                    row.method,
                    row.title,
                    row.description,
                    row.reasoning,
                    status,
                    note,
                    chrono::Local::now().to_rfc3339(),
                ],
            )
            .map_err(|e| e.to_string())?;
            let row_id = tx.last_insert_rowid();
            for artifact_id in &row.supporting_artifacts {
                tx.execute(
                    "INSERT OR IGNORE INTO finding_artifacts(finding_row_id, artifact_id) VALUES (?1, ?2)",
                    params![row_id, artifact_id],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persisted §35 finding rows of one image (join table resolved
    /// into `supporting_artifacts`), in stored order.
    pub fn finding_rows(&self, image_id: i64) -> Vec<FindingRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, finding_id, finding_key, run_at, severity, category, confidence,
                    method, title, description, reasoning, status, investigator_note
             FROM finding_rows WHERE image_id = ?1 ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![image_id], |r| {
            let confidence: Option<f64> = r.get(6)?;
            Ok((
                r.get::<_, i64>(0)?,
                FindingRow {
                    finding_id: r.get(1)?,
                    finding_key: r.get(2)?,
                    run_at: r.get(3)?,
                    severity: r.get(4)?,
                    category: r.get(5)?,
                    confidence,
                    method: r.get(7)?,
                    title: r.get(8)?,
                    description: r.get(9)?,
                    reasoning: r.get(10)?,
                    supporting_artifacts: Vec::new(),
                    status: FindingStatus::parse(&r.get::<_, String>(11)?)
                        .unwrap_or(FindingStatus::New),
                    investigator_note: r.get(12)?,
                },
            ))
        });
        let pairs: Vec<(i64, FindingRow)> = match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => return Vec::new(),
        };
        pairs
            .into_iter()
            .map(|(row_id, mut record)| {
                record.supporting_artifacts = self.finding_artifacts(row_id);
                record
            })
            .collect()
    }

    /// Artifact IDs grounded in the finding_artifacts join table.
    fn finding_artifacts(&self, finding_row_id: i64) -> Vec<String> {
        let mut stmt = match self.conn.prepare(
            "SELECT artifact_id FROM finding_artifacts WHERE finding_row_id = ?1 ORDER BY artifact_id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![finding_row_id], |r| r.get::<_, String>(0));
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Number of join-table rows (test hook: proves cascade leaves no
    /// orphan artifact links after REMOVE EVIDENCE).
    #[cfg(test)]
    pub fn finding_artifacts_orphan_count(&self) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM finding_artifacts", [], |r| r.get::<_, i64>(0))
            .unwrap_or(-1)
    }

    /// §36: set one finding's workflow status. Only the four §35
    /// values are accepted — anything else is rejected, and nothing in
    /// this module ever writes CONFIRMED on its own.
    pub fn set_finding_status(
        &mut self,
        image_id: i64,
        finding_key: &str,
        status: FindingStatus,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE finding_rows SET status = ?3 WHERE image_id = ?1 AND finding_key = ?2",
                params![image_id, finding_key, status.label()],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// §36: record the investigator's note on one finding.
    pub fn set_finding_note(
        &mut self,
        image_id: i64,
        finding_key: &str,
        note: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE finding_rows SET investigator_note = ?3 WHERE image_id = ?1 AND finding_key = ?2",
                params![image_id, finding_key, note.trim()],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------------- §41 chain of custody ----------------

    /// Append one immutable custody entry (§41/§47). The examiner is
    /// taken from the case metadata; secrets are never passed here.
    pub fn log_custody(&mut self, operation: &str, detail: &str) -> Result<(), String> {
        let examiner = self.meta().examiner;
        self.conn
            .execute(
                "INSERT INTO custody_log(ts, examiner, operation, detail) VALUES (?1, ?2, ?3, ?4)",
                params![chrono::Local::now().to_rfc3339(), examiner, operation, detail],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Full custody trail, oldest first (§41 report input).
    pub fn custody_log(&self) -> Vec<CustodyEntry> {
        let mut stmt = match self.conn.prepare(
            "SELECT ts, examiner, operation, detail FROM custody_log ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            Ok(CustodyEntry { ts: r.get(0)?, examiner: r.get(1)?, operation: r.get(2)?, detail: r.get(3)? })
        });
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn add_note(&mut self, artifact_id: Option<&str>, text: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO notes(artifact_id, text, created_at) VALUES (?1, ?2, ?3)",
                params![artifact_id, text.trim(), chrono::Local::now().to_rfc3339()],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn notes(&self) -> Vec<CaseNote> {
        let mut stmt = match self
            .conn
            .prepare("SELECT id, artifact_id, text, created_at FROM notes ORDER BY id")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            Ok(CaseNote { id: r.get(0)?, artifact_id: r.get(1)?, text: r.get(2)?, created_at: r.get(3)? })
        });
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn toggle_bookmark(&mut self, artifact_id: &str, note: Option<&str>) -> Result<bool, String> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM bookmarks WHERE artifact_id = ?1",
                params![artifact_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .is_some();
        if exists {
            self.conn
                .execute("DELETE FROM bookmarks WHERE artifact_id = ?1", params![artifact_id])
                .map_err(|e| e.to_string())?;
            Ok(false)
        } else {
            self.conn
                .execute(
                    "INSERT INTO bookmarks(artifact_id, note, created_at) VALUES (?1, ?2, ?3)",
                    params![artifact_id, note, chrono::Local::now().to_rfc3339()],
                )
                .map_err(|e| e.to_string())?;
            Ok(true)
        }
    }

    pub fn is_bookmarked(&self, artifact_id: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM bookmarks WHERE artifact_id = ?1",
                params![artifact_id],
                |_| Ok(()),
            )
            .optional()
            .unwrap_or(None)
            .is_some()
    }

    pub fn set_state(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO exam_state(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_state(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM exam_state WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .unwrap_or(None)
    }

    // ---------------- §22 persistent timeline ----------------

    /// Most recently registered evidence image, if any (used to restore
    /// the persistent index/timeline when opening a case).
    pub fn latest_image_id(&self) -> Option<i64> {
        self.conn
            .query_row("SELECT id FROM evidence_images ORDER BY id DESC LIMIT 1", [], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
            .unwrap_or(None)
    }

    /// Replace all persisted timeline events of one image (idempotent
    /// re-ingest: delete then insert in a single transaction).
    pub fn replace_timeline_events(
        &mut self,
        image_id: i64,
        events: &[TimelineEventRecord],
    ) -> Result<(), String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM timeline_events WHERE image_id = ?1", params![image_id])
            .map_err(|e| e.to_string())?;
        for ev in events {
            tx.execute(
                "INSERT INTO timeline_events (image_id, ts, category, label, detail, artifact_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![image_id, ev.ts, ev.category, ev.label, ev.detail, ev.artifact_id],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persisted timeline events of one image, newest first (string
    /// order on the RFC 3339 column is a coarse pre-sort; the UI sorts
    /// by parsed timestamp).
    pub fn timeline_events(&self, image_id: i64) -> Vec<TimelineEventRecord> {
        let mut stmt = match self.conn.prepare(
            "SELECT ts, category, label, detail, artifact_id
             FROM timeline_events WHERE image_id = ?1 ORDER BY ts DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![image_id], |r| {
            Ok(TimelineEventRecord {
                ts: r.get(0)?,
                category: r.get(1)?,
                label: r.get(2)?,
                detail: r.get(3)?,
                artifact_id: r.get(4)?,
            })
        });
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    // ---------------- §21 persistent field index ----------------

    /// Replace all persisted field-index rows of one image.
    pub fn replace_field_index(
        &mut self,
        image_id: i64,
        rows: &[FieldIndexRow],
    ) -> Result<(), String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM field_index WHERE image_id = ?1", params![image_id])
            .map_err(|e| e.to_string())?;
        for row in rows {
            tx.execute(
                "INSERT INTO field_index (image_id, artifact_id, field, value, haystack)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![image_id, row.artifact_id, row.field, row.value, row.haystack],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persisted field-index rows of one image (global search source
    /// when no image is currently open).
    pub fn field_index_rows(&self, image_id: i64) -> Vec<FieldIndexRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT artifact_id, field, value, haystack
             FROM field_index WHERE image_id = ?1 ORDER BY rowid",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![image_id], |r| {
            Ok(FieldIndexRow {
                artifact_id: r.get(0)?,
                field: r.get(1)?,
                value: r.get(2)?,
                haystack: r.get(3)?,
            })
        });
        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One throwaway case database in the system temp directory.
    fn temp_db(tag: &str) -> (std::path::PathBuf, CaseDatabase) {
        let path = std::env::temp_dir().join(format!(
            "nf-db-test-{tag}-{}-{}.db",
            std::process::id(),
            chrono::Local::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let meta = CaseMeta {
            case_number: "TEST-1".into(),
            case_dir: path.to_string_lossy().to_string(),
            ..Default::default()
        };
        let db = CaseDatabase::create(&path, &meta).expect("create temp case db");
        (path, db)
    }

    #[test]
    fn migration_v2_creates_timeline_and_field_index_tables() {
        let (path, mut db) = temp_db("v2");
        assert_eq!(db.schema_version(), CURRENT_SCHEMA_VERSION);

        let image_id = db
            .add_evidence_image(&EvidenceImageRecord {
                path: "x.aif".into(),
                file_name: "x.aif".into(),
                size_bytes: 1,
                container_sha256: "aa".into(),
                expected_sha256: None,
                container_verified: None,
                case_id: None,
                format_version: None,
                demo_mode: false,
                added_at: chrono::Local::now().to_rfc3339(),
            })
            .expect("add image");

        db.replace_timeline_events(
            image_id,
            &[
                TimelineEventRecord {
                    ts: "2026-08-26T16:00:00Z".into(),
                    category: "windows_events".into(),
                    label: "Event 4625 (Information) — Security".into(),
                    detail: "record 1 · provider 'Security'".into(),
                    artifact_id: Some("ART-000030".into()),
                },
                TimelineEventRecord {
                    ts: "2026-08-26T17:30:00+02:00".into(),
                    category: "system".into(),
                    label: "Evidence acquisition finished (SUCCESS)".into(),
                    detail: String::new(),
                    artifact_id: None,
                },
            ],
        )
        .expect("persist timeline");

        db.replace_field_index(
            image_id,
            &[FieldIndexRow {
                artifact_id: "ART-000005".into(),
                field: "processes[0].name".into(),
                value: "xmrig.exe".into(),
                haystack: "processes[0].name xmrig.exe".into(),
            }],
        )
        .expect("persist field index");

        // Restart: reopen the same file — data must survive untouched.
        drop(db);
        let db2 = CaseDatabase::open(&path).expect("reopen case db");
        let events = db2.timeline_events(image_id);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].ts, "2026-08-26T17:30:00+02:00"); // DESC string order
        assert!(events[1].artifact_id.as_deref() == Some("ART-000030"));
        let rows = db2.field_index_rows(image_id);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, "xmrig.exe");

        // Idempotent re-ingest: replace does not duplicate.
        drop(db2);
        let mut db3 = CaseDatabase::open(&path).expect("reopen again");
        db3.replace_timeline_events(image_id, &[]).expect("clear timeline");
        assert!(db3.timeline_events(image_id).is_empty());

        std::fs::remove_file(&path).ok();
    }

    fn sample_row(key: &str, id: &str) -> FindingRow {
        FindingRow {
            finding_id: id.into(),
            finding_key: key.into(),
            severity: "MEDIUM".into(),
            category: "NETWORK".into(),
            confidence: Some(0.9),
            method: "RULE-BASED".into(),
            title: format!("POTENTIAL INDICATOR — {id}"),
            description: "desc".into(),
            reasoning: "reason".into(),
            supporting_artifacts: vec!["ART-000015".into(), "ART-000020".into()],
            run_at: chrono::Local::now().to_rfc3339(),
            status: FindingStatus::New,
            investigator_note: String::new(),
        }
    }

    #[test]
    fn migration_v3_creates_finding_workflow_tables() {
        let (path, db) = temp_db("v3");
        assert_eq!(db.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(CURRENT_SCHEMA_VERSION >= 3);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn finding_status_parsing_is_strict() {
        assert_eq!(FindingStatus::parse("NEW"), Ok(FindingStatus::New));
        assert_eq!(FindingStatus::parse("CONFIRMED"), Ok(FindingStatus::Confirmed));
        assert!(FindingStatus::parse("SUSPICIOUS").is_err());
        assert!(FindingStatus::parse("new").is_err());
        assert_eq!(FindingStatus::ALL.len(), 4);
    }

    #[test]
    fn finding_workflow_survives_rerun_and_restart() {
        let (path, mut db) = temp_db("v3workflow");
        let image_id = db
            .add_evidence_image(&EvidenceImageRecord {
                path: "x.aif".into(),
                file_name: "x.aif".into(),
                size_bytes: 1,
                container_sha256: "aa".into(),
                expected_sha256: None,
                container_verified: None,
                case_id: None,
                format_version: None,
                demo_mode: false,
                added_at: chrono::Local::now().to_rfc3339(),
            })
            .expect("add image");

        // First run: two findings enter NEW with joined artifact ids.
        db.upsert_finding_rows(image_id, &[sample_row("NET-001|ART-000015", "NET-001"), sample_row("PRC-002|ART-000030", "PRC-002")])
            .expect("first run persist");
        let rows = db.finding_rows(image_id);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].status, FindingStatus::New);
        assert_eq!(rows[0].supporting_artifacts, vec!["ART-000015", "ART-000020"]);
        assert!((rows[0].confidence.unwrap() - 0.9).abs() < 1e-9);

        // Investigator workflow: status + note on one finding.
        db.set_finding_status(image_id, "NET-001|ART-000015", FindingStatus::Reviewed).expect("set status");
        db.set_finding_note(image_id, "NET-001|ART-000015", "Confirmed listening socket matches AnyDesk.").expect("set note");

        // Re-run: same keys replace rows but preserve the workflow state.
        db.upsert_finding_rows(image_id, &[sample_row("NET-001|ART-000015", "NET-001"), sample_row("GPU-001|ART-000040", "GPU-001")])
            .expect("second run persist");
        let rows = db.finding_rows(image_id);
        assert_eq!(rows.len(), 2, "re-run replaces, never duplicates");
        let net = rows.iter().find(|r| r.finding_id == "NET-001").expect("NET-001");
        assert_eq!(net.status, FindingStatus::Reviewed, "status preserved across re-run");
        assert_eq!(net.investigator_note, "Confirmed listening socket matches AnyDesk.");
        assert!(rows.iter().all(|r| r.status != FindingStatus::Confirmed),
            "nothing is ever auto-confirmed");

        // Restart: workflow state survives closing the database.
        drop(db);
        let db2 = CaseDatabase::open(&path).expect("reopen");
        let rows = db2.finding_rows(image_id);
        assert_eq!(rows.len(), 2);
        let net = rows.iter().find(|r| r.finding_id == "NET-001").expect("NET-001");
        assert_eq!(net.status, FindingStatus::Reviewed);
        assert!(!net.investigator_note.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn custody_log_is_append_only_and_survives_restart() {
        let (path, mut db) = temp_db("v4custody");
        assert_eq!(db.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(CURRENT_SCHEMA_VERSION >= 4);

        db.log_custody("CASE CREATED", "case folder initialized").expect("log");
        db.log_custody("EVIDENCE ADDED", "CASE-1.AIF · sha256=ab12 · 1024 bytes").expect("log");
        db.log_custody("ANALYSIS RUN", "3 indicator(s), 4 ML anomalies").expect("log");

        let trail = db.custody_log();
        assert_eq!(trail.len(), 3);
        assert_eq!(trail[0].operation, "CASE CREATED");
        assert_eq!(trail[2].operation, "ANALYSIS RUN");

        // Restart: the trail persists, ordering intact.
        drop(db);
        let db2 = CaseDatabase::open(&path).expect("reopen");
        let trail = db2.custody_log();
        assert_eq!(trail.len(), 3);
        assert_eq!(trail[1].operation, "EVIDENCE ADDED");
        assert!(trail[1].detail.contains("sha256=ab12"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_evidence_image_cascades_all_derived_rows() {
        let (path, mut db) = temp_db("v4cascade");
        let image_id = db
            .add_evidence_image(&EvidenceImageRecord {
                path: "x.aif".into(),
                file_name: "x.aif".into(),
                size_bytes: 1,
                container_sha256: "aa".into(),
                expected_sha256: None,
                container_verified: None,
                case_id: None,
                format_version: None,
                demo_mode: false,
                added_at: chrono::Local::now().to_rfc3339(),
            })
            .expect("add image");
        db.insert_artifacts(
            image_id,
            &[ArtifactRef {
                artifact_id: "ART-000001".into(),
                relative_path: "system/os.json".into(),
                size: 10,
                sha256: "bb".into(),
                acquisition_time: String::new(),
                source: String::new(),
                collector: String::new(),
                status: "SUCCESS".into(),
                synthetic: false,
                hash_verified: None,
            }],
        )
        .expect("insert artifacts");
        db.upsert_finding_rows(image_id, &[sample_row("NET-001|ART-000001|seq-0", "NET-001")])
            .expect("persist findings");
        db.replace_timeline_events(
            image_id,
            &[TimelineEventRecord {
                ts: "2026-08-30T10:00:00Z".into(),
                category: "system".into(),
                label: "event".into(),
                detail: String::new(),
                artifact_id: None,
            }],
        )
        .expect("persist timeline");

        // §6 REMOVE EVIDENCE: one call removes the image and everything
        // derived from it (artifacts, finding rows + join, timeline).
        let removed = db.remove_evidence_image(image_id).expect("remove");
        assert_eq!(removed, 1);
        assert!(db.evidence_images().is_empty());
        assert_eq!(db.artifact_count(image_id), 0);
        assert!(db.finding_rows(image_id).is_empty());
        assert!(db.timeline_events(image_id).is_empty());
        // The join table is empty too (no orphan artifact links).
        assert!(db.finding_artifacts_orphan_count() == 0);

        std::fs::remove_file(&path).ok();
    }
}
