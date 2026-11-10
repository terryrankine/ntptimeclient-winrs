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
    Ok(file)
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
