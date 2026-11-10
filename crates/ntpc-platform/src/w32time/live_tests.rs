//! Tests against the real service control manager.
//!
//! The plain tests are read only: `query` opens `w32time` with
//! `SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG` and nothing else. They
//! print nothing, so no machine detail reaches the test log.
//!
//! The ignored tests stop, disable and restore the real `w32time`. Run them
//! only on a throwaway VM, elevated, with `NTPC_ALLOW_SERVICE_TESTS=1` and
//! `NTPC_I_AM_ON_A_VM=1`. A drop guard puts the original start type and run
//! state back, also when a test panics.

use super::*;

#[test]
fn live_query_of_w32time_is_sane_or_a_clean_error() {
    match ScmControl.query(W32TIME) {
        Ok(s) => {
            // Any decoded state is sane by construction. Check the start
            // type is one a restore record can hold.
            assert!(StartType::ALL.contains(&s.start));
        }
        Err(e) => {
            // A clean error, never a panic. Its text names no path.
            assert!(!e.to_string().contains('\\'));
        }
    }
}

#[test]
fn live_query_of_a_missing_service_is_not_found() {
    let e = ScmControl
        .query("ntpc-no-such-service-for-tests")
        .unwrap_err();
    assert_eq!(e, SvcError::NotFound);
}

#[test]
fn live_query_refuses_a_name_with_a_nul() {
    let e = ScmControl.query("w32\0time").unwrap_err();
    assert!(matches!(e, SvcError::Os { op: "open", .. }), "{e:?}");
}

#[test]
fn live_is_running_does_not_panic() {
    let _ = is_running(&ScmControl);
}

/// Both switches must be set. There is no WMI in this crate, so the VM
/// check is the operator's word: `NTPC_I_AM_ON_A_VM=1`.
fn require_vm_and_admin() {
    let on = |k: &str| std::env::var(k).as_deref() == Ok("1");
    assert!(
        on("NTPC_ALLOW_SERVICE_TESTS") && on("NTPC_I_AM_ON_A_VM"),
        "set NTPC_ALLOW_SERVICE_TESTS=1 and NTPC_I_AM_ON_A_VM=1 on a throwaway VM"
    );
    assert!(crate::is_elevated().unwrap(), "run elevated");
}

/// Puts `w32time` back to the state read before the test, also on panic.
struct Guard(SvcState);

impl Drop for Guard {
    fn drop(&mut self) {
        let mut ctl = ScmControl;
        if let Err(e) = ctl.set_start_type(W32TIME, self.0.start) {
            eprintln!("guard: setting the start type back failed: {e}");
        }
        if self.0.run != RunState::Stopped
            && let Err(e) = ctl.start(W32TIME)
            && e != SvcError::AlreadyRunning
        {
            eprintln!("guard: starting w32time again failed: {e}");
        }
    }
}

/// Stops and disables the real `w32time`, then restores it and checks the
/// start type and run state match. MUTATES THE SYSTEM. Not run by the
/// builder.
#[test]
#[ignore = "stops and disables the real w32time: throwaway VM only"]
fn admin_take_over_and_restore_round_trip() {
    require_vm_and_admin();
    let mut ctl = ScmControl;
    let before = ctl.query(W32TIME).unwrap();
    let _guard = Guard(before);
    let file = std::env::temp_dir().join(format!("ntpc-admin-restore-{}.json", std::process::id()));
    let record = take_over(&mut ctl, None, |r| {
        std::fs::write(&file, r.encode()).map_err(|e| e.to_string())
    })
    .unwrap();
    assert_eq!(record, Restore::from_state(before));
    let on_disk = Restore::decode(&std::fs::read(&file).unwrap()).unwrap();
    let _ = std::fs::remove_file(&file);
    assert_eq!(on_disk, record);
    let mid = ctl.query(W32TIME).unwrap();
    assert_eq!(mid.run, RunState::Stopped);
    assert_eq!(mid.start, StartType::Disabled);
    restore(&mut ctl, &on_disk).unwrap();
    // The start returns at start pending. Give it a moment.
    std::thread::sleep(Duration::from_secs(3));
    let after = ctl.query(W32TIME).unwrap();
    assert_eq!(after.start, before.start);
    assert_eq!(
        after.run == RunState::Stopped,
        before.run == RunState::Stopped
    );
}

/// Each start type survives a set and a query. MUTATES THE SYSTEM.
#[test]
#[ignore = "changes the real w32time start type: throwaway VM only"]
fn admin_every_start_type_round_trips() {
    require_vm_and_admin();
    let mut ctl = ScmControl;
    let before = ctl.query(W32TIME).unwrap();
    let _guard = Guard(before);
    for t in StartType::ALL {
        ctl.set_start_type(W32TIME, t).unwrap();
        assert_eq!(ctl.query(W32TIME).unwrap().start, t);
    }
}
