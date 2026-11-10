//! Platform adapters. All `unsafe` code lives in `win32` and nowhere else.

/// Raw Win32 calls. This is the only module allowed to use `unsafe`.
/// Every `unsafe` block needs a `// SAFETY:` comment.
/// Windows only, so the crate still builds where the fuzz job runs.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod win32;

pub mod clock;
pub mod domain;

/// State directory security. Windows only.
#[cfg(windows)]
pub mod acl;

#[cfg(windows)]
pub use acl::{AclError, secure_state_dir};
#[cfg(windows)]
pub use clock::WindowsClock;
pub use clock::{AdjustmentState, MAX_ADJUSTMENT_PPM, ppm_to_adjustment, quantise};
#[cfg(windows)]
pub use domain::join_state;
pub use domain::{JoinState, map_join_status};

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
