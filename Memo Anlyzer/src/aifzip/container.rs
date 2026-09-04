//! AIF container open/detect/stream layer.
//!
//! An AIF case is detected by its actual container signature (ZIP
//! local-file-header magic), NOT by file extension and NOT by assuming
//! JSON. All evidence access is streamed entry-by-entry from disk —
//! multi-GB containers are never loaded into RAM wholesale.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use super::integrity::{hash_stream, SidecarInfo};
use super::schema::{CaseDocument, Custody, Manifest};

/// ZIP local file header signature — the physical signature of every
/// AIF v1 container.
pub const ZIP_LOCAL_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
/// Hard cap on the whole container file (forensic sanity, spec §49).
pub const MAX_CONTAINER_BYTES: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
/// Hard cap on a single in-memory artifact read (hex viewer etc.).
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Forensic-format errors surfaced verbatim to the examiner.
#[derive(Debug)]
pub enum AifOpenError {
    Io(String),
    NotAContainer,
    LooksLikeJson,
    NotZipArchive(String),
    MissingEntry(&'static str),
    InvalidManifest(String),
    InvalidCase(String),
    InvalidCustody(String),
    TooLarge { size: u64, cap: u64 },
}

impl std::fmt::Display for AifOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AifOpenError::Io(e) => write!(f, "Unable to read the evidence image: {e}"),
            AifOpenError::NotAContainer => write!(
                f,
                "Not an AIF evidence container: the file does not begin with the ZIP \
                 local-file-header signature (PK\\x03\\x04). Only AIF v1 containers \
                 produced by MEMO Collector are supported."
            ),
            AifOpenError::LooksLikeJson => write!(
                f,
                "Not an AIF evidence container: the file appears to be plain JSON. \
                 Legacy JSON exports are not supported — re-acquire the evidence with \
                 MEMO Collector v1, which writes AIF v1 ZIP containers."
            ),
            AifOpenError::NotZipArchive(e) => write!(
                f,
                "The file begins with the ZIP signature but is not a readable ZIP archive: {e}. \
                 The evidence image may be truncated or corrupted."
            ),
            AifOpenError::MissingEntry(name) => write!(
                f,
                "Invalid AIF container: required entry '{name}' is missing. \
                 A valid AIF v1 case must contain manifest.json and case.json at the root."
            ),
            AifOpenError::InvalidManifest(e) => write!(
                f,
                "Invalid AIF container: manifest.json could not be parsed ({e})."
            ),
            AifOpenError::InvalidCase(e) => write!(
                f,
                "Invalid AIF container: case.json could not be parsed ({e})."
            ),
            AifOpenError::InvalidCustody(e) => write!(
                f,
                "Invalid AIF container: custody.json could not be parsed ({e})."
            ),
            AifOpenError::TooLarge { size, cap } => write!(
                f,
                "Evidence image refused: {size} bytes exceeds the {cap}-byte container cap."
            ),
        }
    }
}

/// A validated, open AIF container ready for streamed evidence access.
pub struct OpenedAif {
    pub path: PathBuf,
    pub size_bytes: u64,
    /// Streaming SHA-256 of the whole container file.
    pub container_sha256: String,
    archive: ZipArchive<File>,
    pub manifest: Manifest,
    pub case_doc: CaseDocument,
    pub custody: Option<Custody>,
    /// Every entry actually present in the archive (forward slashes).
    pub entry_names: Vec<String>,
    /// Expected container hash from the external sidecar/custody, if
    /// companion files sit next to the .AIF.
    pub sidecar: Option<SidecarInfo>,
}

impl OpenedAif {
    /// Streamed read of one evidence entry into memory (size-capped).
    /// Use only for entries that must be fully materialized (JSON
    /// decoding, hex view); large binary streams should use
    /// [`Self::with_entry_reader`] instead.
    pub fn read_entry(&mut self, relative_path: &str) -> Result<Vec<u8>, String> {
        let size = {
            let entry = self
                .archive
                .by_name(relative_path)
                .map_err(|e| format!("Entry '{relative_path}' cannot be opened: {e}"))?;
            entry.size()
        };
        if size > MAX_ARTIFACT_BYTES {
            return Err(format!(
                "Entry '{relative_path}' is {size} bytes — exceeds the {MAX_ARTIFACT_BYTES}-byte in-memory cap."
            ));
        }
        let mut buf = Vec::with_capacity(size.min(16 * 1024 * 1024) as usize);
        let mut reader = self
            .archive
            .by_name(relative_path)
            .map_err(|e| format!("Entry '{relative_path}' cannot be opened: {e}"))?;
        reader
            .read_to_end(&mut buf)
            .map_err(|e| format!("Entry '{relative_path}' could not be read: {e}"))?;
        Ok(buf)
    }

    /// Run a closure over a streamed entry reader (no full buffering).
    pub fn with_entry_reader<R>(
        &mut self,
        relative_path: &str,
        f: impl FnOnce(&mut dyn Read) -> Result<R, String>,
    ) -> Result<R, String> {
        let mut reader = self
            .archive
            .by_name(relative_path)
            .map_err(|e| format!("Entry '{relative_path}' cannot be opened: {e}"))?;
        f(&mut reader)
    }

    /// True when the manifest lists an entry that the archive contains.
    pub fn has_entry(&self, relative_path: &str) -> bool {
        self.entry_names.iter().any(|n| n == relative_path)
    }
}

/// Detect, validate and open an AIF evidence image.
pub fn open_aif(path: &Path) -> Result<OpenedAif, AifOpenError> {
    let meta = std::fs::metadata(path).map_err(|e| AifOpenError::Io(e.to_string()))?;
    if meta.len() > MAX_CONTAINER_BYTES {
        return Err(AifOpenError::TooLarge { size: meta.len(), cap: MAX_CONTAINER_BYTES });
    }

    // 1. Header detection — never assume JSON or trust the extension.
    let mut head = [0u8; 4];
    {
        let mut f = File::open(path).map_err(|e| AifOpenError::Io(e.to_string()))?;
        let mut taken = 0;
        while taken < 4 {
            let n = f.read(&mut head[taken..]).map_err(|e| AifOpenError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            taken += n;
        }
        if taken < 4 {
            return Err(AifOpenError::NotAContainer);
        }
    }
    if head == ZIP_LOCAL_MAGIC {
        // ZIP container — proceed below.
    } else if head[0] == b'{' || head[0] == b'[' {
        return Err(AifOpenError::LooksLikeJson);
    } else {
        return Err(AifOpenError::NotAContainer);
    }

    // 2. Streaming SHA-256 of the whole container (never buffered).
    let file = File::open(path).map_err(|e| AifOpenError::Io(e.to_string()))?;
    let mut buf_reader = BufReader::new(file);
    let (container_sha256, _) =
        hash_stream(&mut buf_reader).map_err(|e| AifOpenError::Io(e.to_string()))?;

    // 3. Open the archive and discover evidence streams.
    let file = File::open(path).map_err(|e| AifOpenError::Io(e.to_string()))?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| AifOpenError::NotZipArchive(e.to_string()))?;
    let entry_names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    // 4. Required root documents (schema validation).
    let manifest: Manifest = {
        let mut entry = archive
            .by_name("manifest.json")
            .map_err(|_| AifOpenError::MissingEntry("manifest.json"))?;
        let mut s = String::new();
        entry
            .read_to_string(&mut s)
            .map_err(|e| AifOpenError::InvalidManifest(e.to_string()))?;
        serde_json::from_str(&s).map_err(|e| AifOpenError::InvalidManifest(e.to_string()))?
    };
    let case_doc: CaseDocument = {
        let mut entry = archive
            .by_name("case.json")
            .map_err(|_| AifOpenError::MissingEntry("case.json"))?;
        let mut s = String::new();
        entry
            .read_to_string(&mut s)
            .map_err(|e| AifOpenError::InvalidCase(e.to_string()))?;
        serde_json::from_str(&s).map_err(|e| AifOpenError::InvalidCase(e.to_string()))?
    };
    let custody: Option<Custody> = if entry_names.iter().any(|n| n == "custody.json") {
        let mut entry = archive
            .by_name("custody.json")
            .map_err(|_| AifOpenError::MissingEntry("custody.json"))?;
        let mut s = String::new();
        entry
            .read_to_string(&mut s)
            .map_err(|e| AifOpenError::InvalidCustody(e.to_string()))?;
        Some(serde_json::from_str(&s).map_err(|e| AifOpenError::InvalidCustody(e.to_string()))?)
    } else {
        None
    };

    // 5. External integrity sidecars next to the container, if any.
    let sidecar = SidecarInfo::discover(path);

    Ok(OpenedAif {
        path: path.to_path_buf(),
        size_bytes: meta.len(),
        container_sha256,
        archive,
        manifest,
        case_doc,
        custody,
        entry_names,
        sidecar,
    })
}
