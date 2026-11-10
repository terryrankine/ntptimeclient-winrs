//! The learned clock drift, kept on disk so it survives a restart.
//!
//! File: `drift.txt` in the state directory. One line, a version marker and
//! the value in parts per million, for example `v1 12.345`. The marker lets
//! the format change later. A reader rejects any marker it does not know.
//!
//! The file is only a hint. Anything wrong with it means "no saved drift",
//! never a failure. [`DriftStore::load`] returns `None` and the reason is
//! kept for [`FileDriftStore::last_load_note`], so the host can log it.
//!
//! The directory ACL is not set here. The platform crate (Task 11) applies
//! it, and this type only creates the directory if it is missing. `save`
//! trusts the directory. The caller must have secured it first, including a
//! directory that already existed, because anyone who can write there can
//! plant files next to the drift file.
//!
//! Saves are serial only. Two concurrent saves share one temp name and can
//! fail or clobber each other. The host has a single writer.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use ntpc_core::{DriftStore, Ppm, StoreError};

use crate::safe_open;
use thiserror::Error;

/// Largest accepted drift, either sign. Same as the discipline's slew cap.
pub const MAX_PPM: f64 = 500.0;

/// Largest file read. A real file is under 30 bytes. Bounded so a swapped
/// or corrupted file cannot be read into memory.
pub const MAX_FILE_BYTES: u64 = 256;

/// Name of the drift file inside the state directory.
pub const FILE_NAME: &str = "drift.txt";

/// Same directory as the drift file, so the final rename never crosses a
/// volume and stays atomic.
const TEMP_NAME: &str = "drift.txt.tmp";

/// Format marker written and required on the first token.
const VERSION: &str = "v1";

/// Why a load gave no value. Never holds any file text.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum LoadNote {
    /// There is no drift file. Normal on first start.
    #[error("no drift file")]
    Missing,
    /// The file exists and could not be read.
    #[error("drift file unreadable: {0}")]
    Unreadable(io::ErrorKind),
    /// The file is larger than [`MAX_FILE_BYTES`].
    #[error("drift file is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    /// The file is not valid UTF-8.
    #[error("drift file is not valid UTF-8")]
    NotUtf8,
    /// The text is not a known version marker followed by one number.
    #[error("drift file is not in the expected format")]
    BadFormat,
    /// The number is NaN or infinite.
    #[error("drift value is not a finite number")]
    NotFinite,
    /// The number is outside plus or minus [`MAX_PPM`].
    #[error("drift value {0} ppm is outside plus or minus 500 ppm")]
    OutOfRange(f64),
}

/// Drift kept in one file in a directory.
#[derive(Debug)]
pub struct FileDriftStore {
    dir: PathBuf,
    note: Mutex<Option<LoadNote>>,
}

impl FileDriftStore {
    /// A store in `dir`. Nothing is touched until a load or save.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            note: Mutex::new(None),
        }
    }

    /// The state directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The drift file.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    /// The temp file a save writes first. A crash can leave it behind. A
    /// load ignores it and the next save overwrites it.
    #[must_use]
    pub fn temp_path(&self) -> PathBuf {
        self.dir.join(TEMP_NAME)
    }

    /// Loads the value or says why not. Does not touch the stored note.
    ///
    /// # Errors
    /// A [`LoadNote`] naming the first thing wrong with the file.
    pub fn load_checked(&self) -> Result<Ppm, LoadNote> {
        let file = safe_open::open_read(&self.path()).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LoadNote::Missing,
            kind => LoadNote::Unreadable(kind),
        })?;
        // One byte over the limit is enough to know the file is too big.
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| LoadNote::Unreadable(e.kind()))?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(LoadNote::TooLarge);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| LoadNote::NotUtf8)?;
        parse(text)
    }

    /// Why the latest [`DriftStore::load`] returned `None`. `None` after a
    /// load that worked, and before any load.
    #[must_use]
    pub fn last_load_note(&self) -> Option<LoadNote> {
        self.note
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_note(&self, note: Option<LoadNote>) {
        *self.note.lock().unwrap_or_else(PoisonError::into_inner) = note;
    }
}

fn parse(text: &str) -> Result<Ppm, LoadNote> {
    let mut tokens = text.split_whitespace();
    let (Some(marker), Some(value), None) = (tokens.next(), tokens.next(), tokens.next()) else {
        return Err(LoadNote::BadFormat);
    };
    if marker != VERSION {
        return Err(LoadNote::BadFormat);
    }
    let value: f64 = value.parse().map_err(|_| LoadNote::BadFormat)?;
    if !value.is_finite() {
        return Err(LoadNote::NotFinite);
    }
    if value.abs() > MAX_PPM {
        return Err(LoadNote::OutOfRange(value));
    }
    Ok(Ppm::new(value))
}

/// Keeps the full OS error (code and text). Neither holds a path or file text.
fn io_error(step: &str, e: &io::Error) -> StoreError {
    StoreError::Io(format!("{step}: {e}"))
}

/// Adds a failed cleanup to the error, so neither is lost.
fn with_cleanup(step: &str, e: &io::Error, temp: &Path) -> StoreError {
    match fs::remove_file(temp) {
        Ok(()) => io_error(step, e),
        Err(c) if c.kind() == io::ErrorKind::NotFound => io_error(step, e),
        Err(c) => StoreError::Io(format!(
            "{step}: {e}. Removing the temp file also failed: {c}"
        )),
    }
}

impl DriftStore for FileDriftStore {
    fn load(&self) -> Option<Ppm> {
        match self.load_checked() {
            Ok(ppm) => {
                self.set_note(None);
                Some(ppm)
            }
            Err(note) => {
                self.set_note(Some(note));
                None
            }
        }
    }

    /// Writes a temp file, flushes it to disk and renames it over the
    /// target. A crash leaves the old file or the new one, never half of
    /// either. On Windows `std::fs::rename` replaces an existing target
    /// (the `save_replaces_an_existing_file` test runs that path).
    /// The directory itself cannot be flushed through std on Windows, so a
    /// power cut right after a save may still lose the newest value. The
    /// old value stays intact.
    fn save(&self, ppm: Ppm) -> Result<(), StoreError> {
        let value = ppm.value();
        // Refuse what a load would refuse. The discipline clamps, so this
        // only fires on a bug upstream.
        if !value.is_finite() || value.abs() > MAX_PPM {
            return Err(StoreError::Io(format!(
                "drift {value} ppm is not within plus or minus {MAX_PPM} ppm, not saved"
            )));
        }
        fs::create_dir_all(&self.dir).map_err(|e| io_error("create state directory", &e))?;
        let temp = self.temp_path();
        // A temp file from a crash is ours to remove. Anything that cannot be
        // removed (a directory, a locked or read-only file) is an error.
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error("remove old drift temp file", &e)),
        }
        let mut f =
            safe_open::create_new(&temp).map_err(|e| io_error("create drift temp file", &e))?;
        // `{:?}` is the shortest text that reads back exactly. `{}` writes
        // 5e-324 as 0.000...5 with over 300 digits.
        if let Err(e) = f
            .write_all(format!("{VERSION} {value:?}\n").as_bytes())
            .and_then(|()| f.sync_all())
        {
            drop(f);
            return Err(with_cleanup("write drift temp file", &e, &temp));
        }
        drop(f);
        fs::rename(&temp, self.path()).map_err(|e| with_cleanup("replace drift file", &e, &temp))
    }
}

#[cfg(test)]
mod tests;
