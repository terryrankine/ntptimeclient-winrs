//! One clock-adjusting instance per machine (R111).
//!
//! `run` and the service both hold the named mutex [`INSTANCE_MUTEX`] for
//! their whole life. A second one finds it and refuses. The SCM query in
//! `run` stays as a courtesy check.
//!
//! Squatting (Learn, `CreateMutexW`: "a malicious user can create this
//! mutex before you do"): only a mutex owned by SYSTEM or Administrators
//! counts as another instance. One owned by anyone else, or one whose DACL
//! refuses us, is a squat. A squat must not stop time sync, so the caller
//! goes on without the lock and logs a warning. Our own mutex grants only
//! SYSTEM and Administrators any access.

/// The mutex name. "Global\" puts it in the namespace every session sees
/// (Learn, Kernel object namespaces, case sensitive). The rest holds no
/// backslash (Learn, `CreateMutexW`).
pub const INSTANCE_MUTEX: &str = r"Global\ntptimeclient-winrs-clock";

/// What the open found, without the handle. Pure, so the policy is tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// This call created it.
    Created,
    /// It existed, owned by SYSTEM or Administrators.
    ExistedTrusted,
    /// It existed, owned by anyone else.
    ExistedUntrusted,
    /// It exists and its DACL refuses us (`ERROR_ACCESS_DENIED`).
    Denied,
    /// Another OS error.
    Failed(i32),
}

/// The decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// We hold the lock.
    Held,
    /// Another instance runs. Refuse.
    OtherInstance,
    /// The name is squatted or the lock could not be taken. Go on without
    /// it and log the reason.
    Unguarded(String),
}

/// The policy.
#[must_use]
pub fn decide(f: Found) -> Decision {
    match f {
        Found::Created => Decision::Held,
        Found::ExistedTrusted => Decision::OtherInstance,
        Found::ExistedUntrusted => Decision::Unguarded(
            "the instance lock name is held by an account other than SYSTEM or Administrators"
                .to_owned(),
        ),
        Found::Denied => {
            Decision::Unguarded("the instance lock name exists and refuses this account".to_owned())
        }
        Found::Failed(code) => Decision::Unguarded(format!(
            "the instance lock could not be taken: OS error {code}"
        )),
    }
}

/// Another instance holds the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtherInstance;

impl std::fmt::Display for OtherInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("another instance of ntptimeclient-winrs is adjusting the clock")
    }
}

impl std::error::Error for OtherInstance {}

/// Holds the lock until dropped.
#[cfg(windows)]
#[derive(Debug)]
pub struct InstanceGuard {
    _mutex: Option<crate::win32::mutex::NamedMutex>,
}

/// Takes the instance lock. `Ok(guard)` to go on (held, or unguarded with
/// the reason in the second field).
///
/// # Errors
/// [`OtherInstance`] when another instance holds the lock.
#[cfg(windows)]
pub fn acquire() -> Result<(InstanceGuard, Option<String>), OtherInstance> {
    acquire_named(INSTANCE_MUTEX)
}

#[cfg(windows)]
fn acquire_named(name: &str) -> Result<(InstanceGuard, Option<String>), OtherInstance> {
    use crate::win32::Principal;
    use crate::win32::mutex::{Opened, open};
    let (found, handle) = match open(name) {
        Ok(Opened::Created(m)) => (Found::Created, Some(m)),
        Ok(Opened::Existed(m, Principal::System | Principal::Administrators)) => {
            (Found::ExistedTrusted, Some(m))
        }
        Ok(Opened::Existed(m, _)) => (Found::ExistedUntrusted, Some(m)),
        Err(e) if e.raw_os_error() == Some(5) => (Found::Denied, None),
        Err(e) => (Found::Failed(e.raw_os_error().unwrap_or(-1)), None),
    };
    match decide(found) {
        Decision::Held => Ok((InstanceGuard { _mutex: handle }, None)),
        Decision::OtherInstance => Err(OtherInstance),
        // A squatted handle is not kept: it guards nothing.
        Decision::Unguarded(why) => Ok((InstanceGuard { _mutex: None }, Some(why))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_trusted_existing_lock_refuses() {
        assert_eq!(decide(Found::Created), Decision::Held);
        assert_eq!(decide(Found::ExistedTrusted), Decision::OtherInstance);
        assert!(matches!(
            decide(Found::ExistedUntrusted),
            Decision::Unguarded(_)
        ));
        assert!(matches!(decide(Found::Denied), Decision::Unguarded(_)));
        assert!(matches!(decide(Found::Failed(6)), Decision::Unguarded(_)));
    }

    #[test]
    fn the_name_is_global_with_no_inner_backslash() {
        let rest = INSTANCE_MUTEX.strip_prefix("Global\\").unwrap();
        assert!(!rest.contains('\\'));
        assert!(INSTANCE_MUTEX.len() < 260, "MAX_PATH");
    }

    #[cfg(windows)]
    #[test]
    fn a_second_acquire_in_one_process_does_not_get_a_second_lock() {
        // A Local name, so a test never meets a real instance. Elevated, the
        // second acquire sees a trusted lock and refuses. Not elevated, our
        // own DACL refuses this token and the second acquire is unguarded.
        let n = format!("Local\\ntpc-test-instance-{}", std::process::id());
        let first = acquire_named(&n).unwrap();
        assert!(first.1.is_none(), "{:?}", first.1);
        let second = acquire_named(&n);
        assert!(
            matches!(second, Err(OtherInstance) | Ok((_, Some(_)))),
            "two holders of one lock"
        );
        drop(first);
    }
}
