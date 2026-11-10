//! The state directory: `ntpc_platform::secure_state_dir` mapped to the
//! host's [`SecureOutcome`].

use std::path::Path;

use ntpc_platform::{AclError, RestoreRecord, Secured};

use crate::host::{SecureOutcome, StateDir};

/// Maps the platform result. `Kept` and `Absent` are a plain secured
/// directory. `Dropped` is secured with an untrusted restore record left in
/// quarantine. Any error refuses: the host then runs with persistence off
/// and timekeeping on.
#[must_use]
pub fn secure_outcome(result: Result<Secured, AclError>) -> SecureOutcome {
    match result {
        Ok(Secured {
            restore_record: RestoreRecord::Kept | RestoreRecord::Absent,
        }) => SecureOutcome::Ok,
        Ok(Secured {
            restore_record: RestoreRecord::Dropped,
        }) => SecureOutcome::RestoreDropped,
        Err(e) => SecureOutcome::Refused {
            reason: refusal_reason(&e),
        },
    }
}

/// The reason class for the log. Never a path, never OS text: the host
/// logs it as is.
#[must_use]
pub fn refusal_reason(e: &AclError) -> &'static str {
    match e {
        AclError::BadPath => "the path is not an absolute local drive path",
        AclError::TrailingDotOrSpace => "a path component ends in a dot or a space",
        AclError::NotFixedDrive => "the drive is not a fixed local drive",
        AclError::PathChanged => "the directory changed while it was being secured",
        AclError::ReservedName => "the path holds a device name or a colon",
        AclError::RestoreCarryFailed { .. } => {
            "the restore record could not be carried into a fresh directory"
        }
        AclError::RollbackFailed { .. } => {
            "replacing the directory failed and so did moving it back. The previous \
             directory, which may hold the restore record, was left under a sibling name \
             with .old- in it"
        }
        AclError::Link => "the directory is a link or junction",
        AclError::ParentLink => "a parent is a link or junction",
        AclError::NotADirectory => "the path or a parent is not a directory",
        AclError::UntrustedOwner => "the owner is not SYSTEM or Administrators",
        AclError::UntrustedParent => {
            "a parent has an owner other than SYSTEM, Administrators \
                                      or TrustedInstaller"
        }
        AclError::UnexpectedChild => "the directory holds an entry the service never writes",
        AclError::DaclNotApplied => "the access list was still wrong after setting it",
        AclError::Os { .. } => "an OS call failed",
        // AclError is non_exhaustive.
        _ => "an unlisted refusal",
    }
}

/// The real state directory. Secured once when built, before any file in
/// it is opened, so the log can be put there only when that worked. The
/// host's [`StateDir::secure`] returns the outcome of that one call. A
/// second `secure_state_dir` would only repeat the fast path.
#[derive(Debug, Clone, Copy)]
pub struct WinStateDir {
    outcome: SecureOutcome,
}

impl WinStateDir {
    /// Calls `ntpc_platform::secure_state_dir` on `dir` now. It may create
    /// the directory, or replace a weak one (R78). It touches nothing else.
    #[must_use]
    pub fn secure_now(dir: &Path) -> Self {
        Self::from_outcome(secure_outcome(ntpc_platform::secure_state_dir(dir)))
    }

    /// A state directory with a known outcome. For tests.
    #[must_use]
    pub fn from_outcome(outcome: SecureOutcome) -> Self {
        Self { outcome }
    }
}

impl StateDir for WinStateDir {
    fn secure(&self) -> SecureOutcome {
        self.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_error() -> Vec<AclError> {
        vec![
            AclError::BadPath,
            AclError::TrailingDotOrSpace,
            AclError::NotFixedDrive,
            AclError::PathChanged,
            AclError::ReservedName,
            AclError::RestoreCarryFailed {
                detail: r"C:\Users\someone\secret".into(),
            },
            AclError::RollbackFailed {
                cause: r"C:\ProgramData\x".into(),
                rollback: r"C:\ProgramData\y".into(),
            },
            AclError::Link,
            AclError::ParentLink,
            AclError::NotADirectory,
            AclError::UntrustedOwner,
            AclError::UntrustedParent,
            AclError::UnexpectedChild,
            AclError::DaclNotApplied,
            AclError::Os {
                op: "list",
                detail: r"\\?\C:\ProgramData\z".into(),
            },
        ]
    }

    #[test]
    fn secured_maps_by_restore_record() {
        let ok = |r| secure_outcome(Ok(Secured { restore_record: r }));
        assert_eq!(ok(RestoreRecord::Kept), SecureOutcome::Ok);
        assert_eq!(ok(RestoreRecord::Absent), SecureOutcome::Ok);
        assert_eq!(ok(RestoreRecord::Dropped), SecureOutcome::RestoreDropped);
    }

    #[test]
    fn every_error_refuses_with_its_own_reason_and_no_path() {
        let mut seen = Vec::new();
        for e in every_error() {
            let SecureOutcome::Refused { reason } = secure_outcome(Err(e.clone())) else {
                panic!("{e:?} did not refuse");
            };
            assert_ne!(reason, "");
            assert!(
                !reason.contains('\\') && !reason.contains(":\\"),
                "{reason}"
            );
            assert!(!reason.contains("secret") && !reason.contains("ProgramData"));
            assert!(!seen.contains(&reason), "reason repeated: {reason}");
            seen.push(reason);
        }
        assert_eq!(seen.len(), 15);
    }

    #[test]
    fn rollback_reason_says_the_record_may_be_in_quarantine() {
        let r = refusal_reason(&AclError::RollbackFailed {
            cause: String::new(),
            rollback: String::new(),
        });
        assert!(r.contains("restore record") && r.contains(".old-"), "{r}");
    }

    #[test]
    fn the_host_sees_the_outcome_of_the_one_call() {
        for o in [
            SecureOutcome::Ok,
            SecureOutcome::RestoreDropped,
            SecureOutcome::Refused { reason: "x" },
        ] {
            let d = WinStateDir::from_outcome(o);
            assert_eq!(d.secure(), o);
            assert_eq!(d.secure(), o, "same on a second call");
        }
    }
}
