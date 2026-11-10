//! Platform adapters. All `unsafe` code lives in `win32` and nowhere else.

/// Raw Win32 calls. This is the only module allowed to use `unsafe`.
/// Every `unsafe` block needs a `// SAFETY:` comment.
/// Windows only, so the crate still builds where the fuzz job runs.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod win32;

pub mod clock;
pub mod domain;
pub mod w32time;

/// DHCP option 42 servers and the lease watcher.
pub mod dhcp;

/// This machine's own unicast addresses.
pub mod net;

/// The calling thread's priority, for the timing path.
pub mod thread;

/// State directory security. Windows only.
#[cfg(windows)]
pub mod acl;

#[cfg(windows)]
pub use acl::{AclError, KNOWN_CHILDREN, RestoreRecord, Secured, secure_state_dir};
#[cfg(windows)]
pub use clock::WindowsClock;
pub use clock::{AdjustmentState, MAX_ADJUSTMENT_PPM, ppm_to_adjustment, quantise};
#[cfg(windows)]
pub use domain::join_state;
pub use domain::{JoinState, map_join_status};
#[cfg(windows)]
pub use w32time::ScmControl;

/// Whether this process runs elevated. Read only. Install and uninstall
/// refuse without it.
///
/// # Errors
/// The OS error if the token cannot be read.
#[cfg(windows)]
pub fn is_elevated() -> std::io::Result<bool> {
    win32::token_is_elevated()
}

/// Renames `from` over `to` and returns only once the move is on disk
/// (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`).
///
/// # Errors
/// The OS error.
#[cfg(windows)]
pub fn replace_file_write_through(
    from: &std::path::Path,
    to: &std::path::Path,
) -> std::io::Result<()> {
    win32::scm::replace_file_write_through(from, to)
}

/// Whether this process's token gives new objects a trusted owner: SYSTEM
/// or Administrators. Every file the service writes in the state directory
/// gets that owner, and any other owner makes the next start replace the
/// directory (R106). Read only.
///
/// # Errors
/// The OS error if the token cannot be read.
#[cfg(windows)]
pub fn default_owner_is_trusted() -> std::io::Result<bool> {
    Ok(matches!(
        win32::token_default_owner()?,
        win32::Principal::System | win32::Principal::Administrators
    ))
}

/// The hard link count of an open file. Read only, through the handle, so
/// a rename after the open cannot change the answer. Stable `std` has no
/// way to read it on Windows. The host's log file sink refuses a file with
/// more than one link (R75): a planted hard link would point our writes at
/// a file someone else chose.
///
/// # Errors
/// The OS error.
#[cfg(windows)]
pub fn file_link_count(file: &std::fs::File) -> std::io::Result<u32> {
    // A duplicate of the handle, so the wrapper can take an OwnedHandle.
    let h = std::os::windows::io::OwnedHandle::from(file.try_clone()?);
    Ok(win32::link_info(&h)?.links)
}

/// Crate name, used by the smoke test.
pub const CRATE_NAME: &str = "ntpc-platform";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn depends_on_core() {
        assert_eq!(ntpc_core::CRATE_NAME, "ntpc-core");
    }

    /// Read only: `GetTokenInformation(TokenOwner)` on this process.
    #[cfg(windows)]
    #[test]
    fn default_owner_reads() {
        let _trusted: bool = default_owner_is_trusted().expect("token owner");
    }

    /// Only files in a fresh directory under the system temp folder. The
    /// directory is removed at the end.
    #[cfg(windows)]
    #[test]
    fn link_count_sees_a_hard_link_on_read_and_append_handles() {
        use std::fs::{self, OpenOptions};
        let dir = std::env::temp_dir().join(format!("ntpc-links-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("temp dir");
        let one = dir.join("one.log");
        fs::write(&one, b"x").expect("write");
        let read = fs::File::open(&one).expect("open");
        assert_eq!(file_link_count(&read).expect("count"), 1);
        let append = OpenOptions::new().append(true).open(&one).expect("append");
        assert_eq!(file_link_count(&append).expect("count on append"), 1);
        fs::hard_link(&one, dir.join("two.log")).expect("hard link");
        assert_eq!(file_link_count(&read).expect("count"), 2);
        assert_eq!(file_link_count(&append).expect("count on append"), 2);
        drop((read, append));
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
