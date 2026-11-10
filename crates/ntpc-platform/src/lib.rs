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
}
