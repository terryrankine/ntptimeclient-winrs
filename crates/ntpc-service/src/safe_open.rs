//! Opens for the config and drift files, with the link-following switches
//! turned off where the platform has them.
//!
//! This is defence in depth. The main control is a secured state directory
//! (Task 11, `ntpc-platform`). If the directory is secure, nobody unprivileged
//! can plant a link in it. These flags only narrow what a planted link can do.
//!
//! On Windows the flags are:
//! - `FILE_FLAG_OPEN_REPARSE_POINT`: open a symlink or junction itself, not
//!   its target.
//! - `SECURITY_IDENTIFICATION` through `security_qos_flags`: a server end of a
//!   named pipe cannot impersonate the service at more than identification
//!   level if the path is redirected there.
//!
//! On other hosts neither flag exists. The project targets Windows. The gate
//! only keeps the crate compiling elsewhere, where reads are plain and
//! `create_new` uses `O_EXCL`.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Windows `FILE_FLAG_OPEN_REPARSE_POINT`. Written out here because the
/// constant lives in a crate we do not depend on.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Windows `SECURITY_IDENTIFICATION`, the `SECURITY_SQOS_PRESENT` level that
/// lets a server identify the caller but not act as it.
#[cfg(windows)]
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

fn harden(options: &mut OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .security_qos_flags(SECURITY_IDENTIFICATION);
    }
    #[cfg(not(windows))]
    {
        let _ = options;
    }
}

/// Opens an existing file for reading.
pub(crate) fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    harden(&mut options);
    let file = options.open(path)?;
    // With the reparse flag a link opens as itself and reads as empty. An
    // empty config would silently mean defaults, so refuse the link.
    #[cfg(windows)]
    if file.metadata()?.file_type().is_symlink() {
        return Err(io::Error::other("path is a symbolic link or junction"));
    }
    // R75, R105: a second hard link means someone else can name, and maybe
    // write, the same file from outside the secured directory. Refused for
    // every reader: drift, config, status and the restore record. On other
    // targets there is no check: the project runs on Windows only and the
    // gate only keeps the crate compiling there.
    #[cfg(windows)]
    if ntpc_platform::file_link_count(&file)? > 1 {
        return Err(io::Error::other(ExtraLinks));
    }
    Ok(file)
}

/// The refusal for a file with more than one hard link. A type, so a
/// caller that classifies refusals (the restore record reader) can tell it
/// from an I/O failure. The text names no path.
#[derive(Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct ExtraLinks;

impl std::fmt::Display for ExtraLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("file has more than one hard link")
    }
}

impl std::error::Error for ExtraLinks {}

/// True if `e` is the [`ExtraLinks`] refusal of [`open_read`].
pub(crate) fn is_extra_links(e: &io::Error) -> bool {
    matches!(e.get_ref(), Some(inner) if inner.is::<ExtraLinks>())
}

/// Creates a new file for writing. Fails if anything is at the path already.
///
/// What was observed on Windows 11 (the reviewer's probe, and the link tests
/// in `drift_store`), not a documented guarantee: `save` removes the old temp
/// path first. A symlink or hard link there was removed itself and its target
/// stayed untouched. A junction made that removal fail, so `save` returned an
/// error and wrote nothing through. `create_new` plus the reparse flag stay as
/// a second guard whatever the platform does.
pub(crate) fn create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    harden(&mut options);
    options.open(path)
}

/// R105. Only files in fresh temp directories. A hard link is made to a
/// file outside the reader's directory, as a planting attacker would.
#[cfg(all(test, windows))]
mod link_tests {
    use std::fs;
    use std::path::PathBuf;

    use ntpc_core::{DriftStore, Ppm};

    use crate::config::{Config, ConfigError};
    use crate::drift_store::{FILE_NAME, FileDriftStore, LoadNote};
    use crate::status::{StatusError, read_status};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("ntpc-links-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("state")).expect("temp dir");
            Self(p)
        }

        fn state(&self) -> PathBuf {
            self.0.join("state")
        }

        /// `name` in the state directory, hard-linked to a file outside it.
        fn planted(&self, name: &str, body: &[u8]) -> PathBuf {
            let outside = self.0.join(format!("outside-{name}"));
            fs::write(&outside, body).expect("write");
            let inside = self.state().join(name);
            fs::hard_link(&outside, &inside).expect("hard link");
            inside
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_plain_file_still_opens() {
        let s = Scratch::new("plain");
        let p = s.state().join("plain.txt");
        fs::write(&p, b"x").expect("write");
        assert!(super::open_read(&p).is_ok());
    }

    #[test]
    fn a_hard_linked_file_is_refused_without_a_path_in_the_text() {
        let s = Scratch::new("raw");
        let p = s.planted("any.txt", b"x");
        let e = super::open_read(&p).expect_err("refused");
        assert_eq!(e.kind(), std::io::ErrorKind::Other);
        assert!(super::is_extra_links(&e));
        assert_eq!(e.to_string(), "file has more than one hard link");
    }

    #[test]
    fn a_hard_linked_drift_file_loads_as_none_with_a_note() {
        let s = Scratch::new("drift");
        let plain = FileDriftStore::new(s.state());
        plain.save(Ppm::new(1.5)).expect("save");
        assert!(plain.load_checked().is_ok(), "plain drift loads");
        fs::remove_file(s.state().join(FILE_NAME)).expect("remove");
        let _ = s.planted(FILE_NAME, b"v1 12.5\n");
        let store = FileDriftStore::new(s.state());
        assert_eq!(
            store.load_checked(),
            Err(LoadNote::Unreadable(std::io::ErrorKind::Other))
        );
        assert_eq!(store.load(), None);
    }

    #[test]
    fn a_hard_linked_config_is_a_read_error() {
        let s = Scratch::new("config");
        let plain = s.state().join("plain.toml");
        fs::write(&plain, b"").expect("write");
        assert!(Config::load(&plain).is_ok(), "plain config loads");
        let p = s.planted("config.toml", b"");
        assert!(matches!(
            Config::load(&p),
            Err(ConfigError::Read {
                kind: std::io::ErrorKind::Other,
                ..
            })
        ));
    }

    #[test]
    fn a_hard_linked_status_file_is_refused_by_the_reader() {
        let s = Scratch::new("status");
        let p = s.planted("status.json", b"{}");
        assert_eq!(
            read_status(&p),
            Err(StatusError::Io(std::io::ErrorKind::Other))
        );
    }
}
