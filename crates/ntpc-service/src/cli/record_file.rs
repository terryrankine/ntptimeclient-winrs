//! The restore record as a file in the state directory.
//!
//! Reads go through `safe_open` (no reparse follow, symlinks refused). Before
//! any byte is read, the open file must be a plain file, not a reparse
//! point, with one hard link, at most [`Restore::MAX_BYTES`] long and owned
//! by SYSTEM or Administrators (R86). Writes go to a
//! temp file, are flushed, then renamed over the target with
//! `MOVEFILE_WRITE_THROUGH`, so the record survives a power cut right after
//! the `w32time` stop that follows it.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use ntpc_platform::w32time::Restore;

use super::{DirState, LoadError, RecordStore, SecureRefusal, TrustFailure};
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
    /// The owner check on read. Off only in this module's tests, whose temp
    /// files belong to the test user.
    check_owner: bool,
}

impl FileRecordStore {
    /// A store in `dir`. Nothing is touched until a call.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            check_owner: true,
        }
    }

    #[cfg(test)]
    fn without_owner_check(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            check_owner: false,
        }
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

/// Provenance of the open file, checked before reading it (R86).
fn check_provenance(file: &fs::File, check_owner: bool) -> Result<(), LoadError> {
    #[cfg(windows)]
    {
        let f =
            ntpc_platform::w32time::record_file_facts(file).map_err(|e| LoadError::Io(e.kind()))?;
        let failure = if f.directory {
            Some(TrustFailure::NotAFile)
        } else if f.reparse {
            Some(TrustFailure::Reparse)
        } else if f.links != 1 {
            Some(TrustFailure::Links)
        } else if f.size > Restore::MAX_BYTES as u64 {
            Some(TrustFailure::TooLarge)
        } else if check_owner && !f.owner_trusted {
            Some(TrustFailure::Owner)
        } else {
            None
        };
        failure.map_or(Ok(()), |t| Err(LoadError::NotTrusted(t)))
    }
    #[cfg(not(windows))]
    {
        // Never reached in use: records are written and read on Windows only.
        let _ = check_owner;
        let len = file.metadata().map_err(|e| LoadError::Io(e.kind()))?.len();
        if len > Restore::MAX_BYTES as u64 {
            return Err(LoadError::NotTrusted(TrustFailure::TooLarge));
        }
        Ok(())
    }
}

/// The fate of the restore record after securing (N2). A record existed and
/// failed the provenance checks: it sits in the quarantine, and nobody may
/// act as if there were no record (R86).
///
/// # Errors
/// [`SecureRefusal::RecordDropped`] for [`ntpc_platform::RestoreRecord::Dropped`].
#[cfg(windows)]
pub fn check_secured(r: ntpc_platform::RestoreRecord) -> Result<(), SecureRefusal> {
    use ntpc_platform::RestoreRecord;
    match r {
        RestoreRecord::Dropped => Err(SecureRefusal::RecordDropped),
        RestoreRecord::Kept | RestoreRecord::Absent => Ok(()),
    }
}

impl RecordStore for FileRecordStore {
    /// No create, no follow: `symlink_metadata` on the path and its parent.
    /// Any answer but "not found" is `Present`, so `secure` decides.
    fn dir_state(&self) -> DirState {
        match fs::symlink_metadata(&self.dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => match self.dir.parent() {
                Some(parent) if fs::symlink_metadata(parent).is_err() => DirState::ParentMissing,
                _ => DirState::Missing,
            },
            _ => DirState::Present,
        }
    }

    #[cfg(windows)]
    fn secure(&mut self) -> Result<(), SecureRefusal> {
        let secured = ntpc_platform::secure_state_dir(&self.dir)
            .map_err(|e| super::classify_acl_error(&e))?;
        check_secured(secured.restore_record)
    }

    #[cfg(not(windows))]
    fn secure(&mut self) -> Result<(), SecureRefusal> {
        Err(SecureRefusal::Directory(
            "the state directory can be secured on Windows only".to_owned(),
        ))
    }

    fn load(&self) -> Result<Option<Restore>, LoadError> {
        let file = match safe_open::open_read(&self.path()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(LoadError::Io(e.kind())),
        };
        check_provenance(&file, self.check_owner)?;
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
    use crate::cli::TrustFailure;
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
        let mut s = FileRecordStore::without_owner_check(&d.0);
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
            FileRecordStore::without_owner_check(&d.0).load(),
            Err(LoadError::Invalid(RestoreFormatError::NotCanonical))
        );
    }

    #[test]
    fn file_store_refuses_a_huge_file() {
        let d = TempDir::new("huge");
        fs::write(d.0.join(RECORD_FILE_NAME), vec![b' '; 1 << 20]).unwrap();
        // Refused on the size from the handle, before any byte is read.
        assert_eq!(
            FileRecordStore::without_owner_check(&d.0).load(),
            Err(LoadError::NotTrusted(TrustFailure::TooLarge))
        );
    }

    #[test]
    fn file_store_overwrites_a_stale_temp_file() {
        let d = TempDir::new("tmp");
        fs::write(d.0.join(RECORD_TEMP_NAME), b"junk").unwrap();
        let mut s = FileRecordStore::without_owner_check(&d.0);
        let r = Restore::new(StartType::Disabled, false);
        s.save(&r).unwrap();
        assert_eq!(s.load(), Ok(Some(r)));
    }

    #[test]
    fn file_store_errors_name_no_path() {
        let d = TempDir::new("err");
        // A directory where the record should be: reads fail.
        fs::create_dir(d.0.join(RECORD_FILE_NAME)).unwrap();
        let e = FileRecordStore::without_owner_check(&d.0)
            .load()
            .unwrap_err();
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
        assert!(FileRecordStore::without_owner_check(&d.0).load().is_err());
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
        assert_eq!(
            FileRecordStore::without_owner_check(&d.0).load(),
            Err(LoadError::NotTrusted(TrustFailure::Links))
        );
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
        let mut s = FileRecordStore::without_owner_check(&d.0);
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
        let mut s = FileRecordStore::without_owner_check(&d.0);
        assert!(s.save(&Restore::new(StartType::Manual, true)).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        assert!(!d.0.join(RECORD_FILE_NAME).exists());
    }

    /// The real owner check. A temp file made by a non-elevated test run is
    /// owned by the test user, so it must be refused. Elevated, the default
    /// owner is Administrators and the check cannot tell: skip then.
    #[cfg(windows)]
    #[test]
    fn a_record_owned_by_a_plain_user_is_refused() {
        if ntpc_platform::is_elevated().unwrap_or(true) {
            eprintln!("skipped: elevated, new files are owned by Administrators");
            return;
        }
        let d = TempDir::new("owner");
        fs::write(
            d.0.join(RECORD_FILE_NAME),
            Restore::new(StartType::Manual, true).encode(),
        )
        .unwrap();
        assert_eq!(
            FileRecordStore::new(&d.0).load(),
            Err(LoadError::NotTrusted(TrustFailure::Owner))
        );
    }

    #[test]
    fn exactly_the_cap_is_read_and_one_more_byte_is_refused() {
        let d = TempDir::new("cap");
        let mut at_cap = Restore::new(StartType::Manual, true).encode().into_bytes();
        at_cap.resize(Restore::MAX_BYTES, b' ');
        fs::write(d.0.join(RECORD_FILE_NAME), &at_cap).unwrap();
        // At the cap the content check decides (padding is not canonical).
        assert_eq!(
            FileRecordStore::without_owner_check(&d.0).load(),
            Err(LoadError::Invalid(RestoreFormatError::NotCanonical))
        );
        at_cap.push(b' ');
        fs::write(d.0.join(RECORD_FILE_NAME), &at_cap).unwrap();
        assert_eq!(
            FileRecordStore::without_owner_check(&d.0).load(),
            Err(LoadError::NotTrusted(TrustFailure::TooLarge))
        );
    }

    #[cfg(windows)]
    #[test]
    fn check_secured_refuses_only_a_dropped_record() {
        use ntpc_platform::RestoreRecord;
        assert_eq!(check_secured(RestoreRecord::Kept), Ok(()));
        assert_eq!(check_secured(RestoreRecord::Absent), Ok(()));
        assert_eq!(
            check_secured(RestoreRecord::Dropped),
            Err(SecureRefusal::RecordDropped)
        );
    }

    #[test]
    fn dir_state_tells_present_missing_and_parent_missing_apart() {
        let d = TempDir::new("dirstate");
        assert_eq!(FileRecordStore::new(&d.0).dir_state(), DirState::Present);
        let missing = d.0.join("state");
        assert_eq!(
            FileRecordStore::new(&missing).dir_state(),
            DirState::Missing
        );
        let deep = d.0.join("no-parent").join("state");
        assert_eq!(
            FileRecordStore::new(&deep).dir_state(),
            DirState::ParentMissing
        );
        // Looking created nothing.
        assert!(!missing.exists());
        assert!(!d.0.join("no-parent").exists());
    }
}
