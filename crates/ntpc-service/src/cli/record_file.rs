//! The restore record as a file in the state directory.
//!
//! Reads go through `safe_open` (no reparse follow, symlinks refused) and,
//! on Windows, refuse a file with more than one hard link. Writes go to a
//! temp file, are flushed, then renamed over the target with
//! `MOVEFILE_WRITE_THROUGH`, so the record survives a power cut right after
//! the `w32time` stop that follows it.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use ntpc_platform::w32time::Restore;

use super::{LoadError, RecordStore};
use crate::safe_open;

/// Name of the restore record in the state directory.
pub const RECORD_FILE_NAME: &str = "restore.json";
/// Temp name for the atomic write. Same directory, so the rename stays on
/// one volume.
pub const RECORD_TEMP_NAME: &str = "restore.json.tmp";

/// The restore record as a file in one directory.
#[derive(Debug)]
pub struct FileRecordStore {
    dir: PathBuf,
}

impl FileRecordStore {
    /// A store in `dir`. Nothing is touched until a call.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(RECORD_FILE_NAME)
    }

    fn temp_path(&self) -> PathBuf {
        self.dir.join(RECORD_TEMP_NAME)
    }
}

/// OS error text without a path. `std` does not add paths to `io::Error`.
fn io_text(step: &str, e: &io::Error) -> String {
    format!("{step}: {e}")
}

/// Renames `from` over `to`. On Windows with write-through. Elsewhere plain
/// `rename`: the crate builds there only for the fuzz job and never writes a
/// record.
fn replace(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        ntpc_platform::replace_file_write_through(from, to)
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}

/// Refuses a file with more than one hard link. Another name for the same
/// data could be changed behind the record's back.
fn check_single_link(file: &fs::File) -> Result<(), LoadError> {
    #[cfg(windows)]
    {
        match ntpc_platform::file_link_count(file) {
            Ok(1) => Ok(()),
            Ok(_) => Err(LoadError::Linked),
            Err(e) => Err(LoadError::Io(e.kind())),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(())
    }
}

impl RecordStore for FileRecordStore {
    #[cfg(windows)]
    fn secure(&mut self) -> Result<(), String> {
        // A dropped restore record means the previous directory held a record we
        // could not trust. Install must refuse then: recording the current
        // (stopped and disabled) state as the original would lose the real one.
        // Task 12 part 2 refines this with a distinct exit code (R86).
        match ntpc_platform::secure_state_dir(&self.dir).map_err(|e| e.to_string())? {
            ntpc_platform::Secured {
                restore_record: ntpc_platform::RestoreRecord::Dropped,
                ..
            } => Err("the previous restore record could not be trusted and was dropped".to_owned()),
            _ => Ok(()),
        }
    }

    #[cfg(not(windows))]
    fn secure(&mut self) -> Result<(), String> {
        Err("the state directory can be secured on Windows only".to_owned())
    }

    fn load(&self) -> Result<Option<Restore>, LoadError> {
        let file = match safe_open::open_read(&self.path()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(LoadError::Io(e.kind())),
        };
        check_single_link(&file)?;
        let mut bytes = Vec::new();
        // One byte over the limit is enough to know it is too large.
        file.take(Restore::MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| LoadError::Io(e.kind()))?;
        Restore::decode(&bytes)
            .map(Some)
            .map_err(LoadError::Invalid)
    }

    /// Temp file, flush, write-through rename over the target. A crash
    /// leaves the old record or the new one, never half of either.
    fn save(&mut self, r: &Restore) -> Result<(), String> {
        let temp = self.temp_path();
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_text("remove old record temp file", &e)),
        }
        let mut f =
            safe_open::create_new(&temp).map_err(|e| io_text("create record temp file", &e))?;
        if let Err(e) = f
            .write_all(r.encode().as_bytes())
            .and_then(|()| f.sync_all())
        {
            drop(f);
            let _ = fs::remove_file(&temp);
            return Err(io_text("write record temp file", &e));
        }
        drop(f);
        replace(&temp, &self.path()).map_err(|e| {
            let _ = fs::remove_file(&temp);
            io_text("replace record file", &e)
        })
    }

    fn remove(&mut self) -> Result<(), String> {
        match fs::remove_file(self.path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_text("remove record file", &e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntpc_platform::w32time::{RestoreFormatError, StartType};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "ntpc-restore-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_store_round_trips() {
        let d = TempDir::new("rt");
        let mut s = FileRecordStore::new(&d.0);
        assert_eq!(s.load(), Ok(None));
        let r = Restore::new(StartType::AutomaticDelayed, true);
        s.save(&r).unwrap();
        assert_eq!(s.load(), Ok(Some(r)));
        // A second save replaces the first.
        let r2 = Restore::new(StartType::Manual, false);
        s.save(&r2).unwrap();
        assert_eq!(s.load(), Ok(Some(r2)));
        assert!(!d.0.join(RECORD_TEMP_NAME).exists());
        s.remove().unwrap();
        assert_eq!(s.load(), Ok(None));
        s.remove().unwrap();
    }

    #[test]
    fn file_store_refuses_a_tampered_file() {
        let d = TempDir::new("bad");
        let text = Restore::new(StartType::Manual, true)
            .encode()
            .replace("w32time", "WinDefend");
        fs::write(d.0.join(RECORD_FILE_NAME), text).unwrap();
        assert_eq!(
            FileRecordStore::new(&d.0).load(),
            Err(LoadError::Invalid(RestoreFormatError::NotCanonical))
        );
    }

    #[test]
    fn file_store_refuses_a_huge_file() {
        let d = TempDir::new("huge");
        fs::write(d.0.join(RECORD_FILE_NAME), vec![b' '; 1 << 20]).unwrap();
        assert_eq!(
            FileRecordStore::new(&d.0).load(),
            Err(LoadError::Invalid(RestoreFormatError::TooLarge))
        );
    }

    #[test]
    fn file_store_overwrites_a_stale_temp_file() {
        let d = TempDir::new("tmp");
        fs::write(d.0.join(RECORD_TEMP_NAME), b"junk").unwrap();
        let mut s = FileRecordStore::new(&d.0);
        let r = Restore::new(StartType::Disabled, false);
        s.save(&r).unwrap();
        assert_eq!(s.load(), Ok(Some(r)));
    }

    #[test]
    fn file_store_errors_name_no_path() {
        let d = TempDir::new("err");
        // A directory where the record should be: reads fail.
        fs::create_dir(d.0.join(RECORD_FILE_NAME)).unwrap();
        let e = FileRecordStore::new(&d.0).load().unwrap_err();
        let t = e.to_string();
        assert!(!t.contains('\\') && !t.contains("ntpc-restore"), "{t}");
    }

    // ---- Links (M10). Each test skips when the link cannot be made. ----

    #[cfg(windows)]
    fn junction(link: &std::path::Path, target: &std::path::Path) -> bool {
        std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[cfg(windows)]
    #[test]
    fn a_symlinked_record_is_refused_and_the_target_not_read() {
        let d = TempDir::new("sym");
        let victim = d.0.join("victim.json");
        fs::write(&victim, Restore::new(StartType::Manual, true).encode()).unwrap();
        if let Err(e) = std::os::windows::fs::symlink_file(&victim, d.0.join(RECORD_FILE_NAME)) {
            eprintln!("skipped: cannot create a symlink here: {e}");
            return;
        }
        assert!(FileRecordStore::new(&d.0).load().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_hard_linked_record_is_refused() {
        let d = TempDir::new("hard");
        let other = d.0.join("other.json");
        fs::write(&other, Restore::new(StartType::Manual, true).encode()).unwrap();
        if let Err(e) = fs::hard_link(&other, d.0.join(RECORD_FILE_NAME)) {
            eprintln!("skipped: cannot create a hard link here: {e}");
            return;
        }
        assert_eq!(FileRecordStore::new(&d.0).load(), Err(LoadError::Linked));
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_at_the_record_is_refused_for_read_and_write() {
        let d = TempDir::new("junc");
        let target = d.0.join("target");
        fs::create_dir(&target).unwrap();
        if !junction(&d.0.join(RECORD_FILE_NAME), &target) {
            eprintln!("skipped: mklink /J failed");
            return;
        }
        let mut s = FileRecordStore::new(&d.0);
        assert!(s.load().is_err());
        assert!(s.save(&Restore::new(StartType::Manual, true)).is_err());
        // Nothing was written through the junction.
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        assert!(!d.0.join(RECORD_TEMP_NAME).exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_at_the_temp_path_gives_an_error_and_no_write_through() {
        let d = TempDir::new("junctmp");
        let target = d.0.join("target");
        fs::create_dir(&target).unwrap();
        if !junction(&d.0.join(RECORD_TEMP_NAME), &target) {
            eprintln!("skipped: mklink /J failed");
            return;
        }
        let mut s = FileRecordStore::new(&d.0);
        assert!(s.save(&Restore::new(StartType::Manual, true)).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        assert!(!d.0.join(RECORD_FILE_NAME).exists());
    }
}
