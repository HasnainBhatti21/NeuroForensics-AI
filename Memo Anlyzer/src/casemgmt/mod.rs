//! Case management: CREATE NEW CASE / OPEN EXISTING CASE workflow.
//!
//! A NeuroForensics case is a folder containing a persistent SQLite
//! case database (`case.db`) that stores case metadata, registered
//! evidence images (.AIF), indexed artifact records, findings, notes,
//! bookmarks and examination state. The original .AIF files are only
//! ever referenced read-only from their original location â€” they are
//! never copied, moved or modified.

pub mod db;

use std::path::{Path, PathBuf};

pub use db::{CaseDatabase, CaseMeta};

/// File name of the persistent case database inside a case folder.
pub const CASE_DB_FILE: &str = "case.db";

/// Working sub-folders of every case (spec §4). The original evidence
/// is never copied in — `evidence/` only holds sidecars/exports the
/// examiner deliberately places there.
pub const CASE_SUBFOLDERS: &[&str] = &["evidence", "indexes", "reports", "logs", "exports"];

/// Everything the examiner enters when creating a new case.
#[derive(Clone, Debug, Default)]
pub struct NewCaseForm {
    pub case_number: String,
    pub case_name: String,
    pub examiner: String,
    pub organization: String,
    pub description: String,
    /// Parent directory chosen by the examiner; the case folder
    /// `<directory>/<case_number>/` is created inside it.
    pub directory: PathBuf,
}

/// A case located on disk (folder + its case.db path).
#[derive(Clone, Debug)]
pub struct CaseFolder {
    pub dir: PathBuf,
    pub db_path: PathBuf,
}

/// Sanitize a case number into a safe directory name.
pub fn sanitize_case_dir_name(case_number: &str) -> String {
    let trimmed = case_number.trim();
    let mut out: String = trimmed
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if out.is_empty() {
        out.push_str("CASE");
    }
    out
}

/// Validate the CREATE NEW CASE form; returns a human-readable error
/// listing every missing required field.
pub fn validate_form(form: &NewCaseForm) -> Result<(), String> {
    let mut missing = Vec::new();
    if form.case_number.trim().is_empty() {
        missing.push("Case number");
    }
    if form.case_name.trim().is_empty() {
        missing.push("Case name");
    }
    if form.examiner.trim().is_empty() {
        missing.push("Examiner");
    }
    if form.directory.as_os_str().is_empty() {
        missing.push("Case directory");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("Required field(s) missing: {}", missing.join(", ")))
    }
}

/// CREATE NEW CASE: create the case folder and its persistent database.
pub fn create_case(form: &NewCaseForm) -> Result<CaseFolder, String> {
    validate_form(form)?;

    let dir_name = sanitize_case_dir_name(&form.case_number);
    let dir = form.directory.join(&dir_name);
    let db_path = dir.join(CASE_DB_FILE);
    if db_path.exists() {
        return Err(format!(
            "A case database already exists at {} â€” open it with OPEN EXISTING CASE instead.",
            db_path.display()
        ));
    }

    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Case directory could not be created: {e}"))?;
    for sub in CASE_SUBFOLDERS {
        std::fs::create_dir_all(dir.join(sub))
            .map_err(|e| format!("Case '{sub}' directory could not be created: {e}"))?;
    }

    CaseDatabase::create(
        &db_path,
        &CaseMeta {
            case_number: form.case_number.trim().to_string(),
            case_name: form.case_name.trim().to_string(),
            examiner: form.examiner.trim().to_string(),
            organization: form.organization.trim().to_string(),
            description: form.description.trim().to_string(),
            created_at: chrono::Local::now().to_rfc3339(),
            case_dir: dir.to_string_lossy().to_string(),
            last_opened: String::new(), // set by CaseDatabase::create (mark_opened)
        },
    )?;

    // §41: the very first custody entry — the case came into existence.
    if let Ok(mut db) = CaseDatabase::open(&db_path) {
        let _ = db.log_custody(
            "CASE CREATED",
            &format!("case folder initialized at {}", dir.display()),
        );
    }

    Ok(CaseFolder { dir, db_path })
}

/// OPEN EXISTING CASE: locate the case database from a path chosen by
/// the examiner. Accepts either the `case.db` file itself or any
/// directory that contains one.
pub fn locate_case(path: &Path) -> Result<CaseFolder, String> {
    let db_path = if path.is_dir() {
        let candidate = path.join(CASE_DB_FILE);
        if candidate.is_file() {
            candidate
        } else {
            return Err(format!(
                "{} is not a NeuroForensics case folder (no {} inside).",
                path.display(),
                CASE_DB_FILE
            ));
        }
    } else if path.is_file() {
        if path.file_name().and_then(|n| n.to_str()) == Some(CASE_DB_FILE) {
            path.to_path_buf()
        } else {
            return Err(format!(
                "{} is not a NeuroForensics case database ({CASE_DB_FILE}).",
                path.display()
            ));
        }
    } else {
        return Err(format!("{} does not exist.", path.display()));
    };

    let dir = db_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(CaseFolder { dir, db_path })
}

/// Browse a root directory for existing cases (one level deep).
pub fn list_cases(root: &Path) -> Vec<CaseFolder> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join(CASE_DB_FILE).is_file() {
            found.push(CaseFolder {
                db_path: path.join(CASE_DB_FILE),
                dir: path,
            });
        }
    }
    found.sort_by(|a, b| a.dir.cmp(&b.dir));
    found
}

/// Display summary of one located case (spec §5: number, name,
/// examiner, created, last opened). Reads the case database briefly;
/// unreadable databases yield `None` and are skipped by the caller.
#[derive(Clone, Debug)]
pub struct CaseSummary {
    pub folder: CaseFolder,
    pub case_number: String,
    pub case_name: String,
    pub examiner: String,
    pub created_at: String,
    pub last_opened: String,
    pub evidence_count: usize,
}

pub fn summarize_case(folder: &CaseFolder) -> Option<CaseSummary> {
    let db = db::CaseDatabase::open(&folder.db_path).ok()?;
    let meta = db.meta();
    let evidence_count = db.evidence_images().len();
    Some(CaseSummary {
        folder: folder.clone(),
        case_number: meta.case_number,
        case_name: meta.case_name,
        examiner: meta.examiner,
        created_at: meta.created_at,
        last_opened: meta.last_opened,
        evidence_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use db::{ArtifactRef, EvidenceImageRecord};

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join("neuroforensics_casemgmt_tests").join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn form(dir: PathBuf) -> NewCaseForm {
        NewCaseForm {
            case_number: "CASE-2026-0001".into(),
            case_name: "Test Case".into(),
            examiner: "A. Examiner".into(),
            organization: "DFIR Lab".into(),
            description: "unit test".into(),
            directory: dir,
        }
    }

    #[test]
    fn create_builds_the_full_case_folder_layout() {
        let root = temp_root("layout");
        let folder = create_case(&form(root)).expect("case created");
        for sub in CASE_SUBFOLDERS {
            assert!(folder.dir.join(sub).is_dir(), "missing subfolder {sub}");
        }
        let db = CaseDatabase::open(&folder.db_path).expect("db opens");
        assert_eq!(db.schema_version(), db::CURRENT_SCHEMA_VERSION);
        assert!(!db.meta().last_opened.is_empty(), "last_opened recorded on create");
    }

    #[test]
    fn create_then_open_restores_metadata() {
        let root = temp_root("create_open");
        let folder = create_case(&form(root.clone())).expect("case created");
        assert!(folder.db_path.is_file());

        let located = locate_case(&folder.dir).expect("case located");
        let db = CaseDatabase::open(&located.db_path).expect("db opens");
        let meta = db.meta();
        assert_eq!(meta.case_number, "CASE-2026-0001");
        assert_eq!(meta.case_name, "Test Case");
        assert_eq!(meta.examiner, "A. Examiner");
    }

    #[test]
    fn create_requires_mandatory_fields() {
        let root = temp_root("validation");
        let mut f = form(root);
        f.examiner = String::new();
        let err = create_case(&f).unwrap_err();
        assert!(err.contains("Examiner"), "error was: {err}");
    }

    #[test]
    fn duplicate_case_is_refused() {
        let root = temp_root("duplicate");
        create_case(&form(root.clone())).unwrap();
        let err = create_case(&form(root)).unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn locate_rejects_non_case_paths() {
        let root = temp_root("locate");
        std::fs::write(root.join("not-a-case.db"), b"x").unwrap();
        assert!(locate_case(&root.join("not-a-case.db")).is_err());
        assert!(locate_case(&root).is_err()); // empty dir: no case.db
    }

    #[test]
    fn list_cases_finds_created_case() {
        let root = temp_root("list");
        create_case(&form(root.clone())).unwrap();
        let cases = list_cases(&root);
        assert_eq!(cases.len(), 1);
        assert!(cases[0].db_path.ends_with(CASE_DB_FILE));
    }

    #[test]
    fn evidence_images_and_artifacts_roundtrip() {
        let root = temp_root("evidence");
        let folder = create_case(&form(root)).unwrap();
        let mut db = CaseDatabase::open(&folder.db_path).unwrap();

        let image_id = db
            .add_evidence_image(&EvidenceImageRecord {
                path: "E:/cases/CASE-2026-0001.AIF".into(),
                file_name: "CASE-2026-0001.AIF".into(),
                size_bytes: 412_953,
                container_sha256: "abc123".into(),
                expected_sha256: Some("abc123".into()),
                container_verified: Some(true),
                case_id: Some("CASE-2026-0001".into()),
                format_version: Some(1),
                demo_mode: false,
                added_at: chrono::Local::now().to_rfc3339(),
            })
            .unwrap();
        assert!(image_id > 0);

        db.insert_artifacts(
            image_id,
            &[
                ArtifactRef {
                    artifact_id: "ART-000001".into(),
                    relative_path: "system/os.json".into(),
                    size: 386,
                    sha256: "b07cff99".into(),
                    acquisition_time: "2026-08-29T04:51:37+05:00".into(),
                    source: "sysinfo + environment".into(),
                    collector: "system".into(),
                    status: "ACQUIRED".into(),
                    synthetic: false,
                    hash_verified: Some(true),
                },
                ArtifactRef {
                    artifact_id: "ART-000002".into(),
                    relative_path: "processes/process_list.json".into(),
                    size: 159_724,
                    sha256: "deadbeef".into(),
                    acquisition_time: "2026-08-29T04:51:38+05:00".into(),
                    source: "process snapshot".into(),
                    collector: "processes".into(),
                    status: "ACQUIRED".into(),
                    synthetic: false,
                    hash_verified: Some(true),
                },
            ],
        )
        .unwrap();

        // Reopen: everything must be restored from the persistent DB.
        drop(db);
        let db = CaseDatabase::open(&folder.db_path).unwrap();
        let images = db.evidence_images();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].record.file_name, "CASE-2026-0001.AIF");
        assert_eq!(images[0].record.container_verified, Some(true));
        let arts = db.all_artifacts();
        assert_eq!(arts.len(), 2);
        assert!(arts.iter().any(|a| a.reference.artifact_id == "ART-000002"));
    }

    #[test]
    fn notes_bookmarks_and_state_persist() {
        let root = temp_root("notes");
        let folder = create_case(&form(root)).unwrap();
        let mut db = CaseDatabase::open(&folder.db_path).unwrap();
        db.add_note(Some("ART-000001"), "Suspicious run key entry").unwrap();
        db.toggle_bookmark("ART-000001", Some("flagged")).unwrap();
        db.set_state("last_view", "explorer").unwrap();

        drop(db);
        let db = CaseDatabase::open(&folder.db_path).unwrap();
        assert_eq!(db.notes().len(), 1);
        assert!(db.is_bookmarked("ART-000001"));
        assert_eq!(db.get_state("last_view"), Some("explorer".into()));
    }
}
