//! Tests against the real service control manager.
//!
//! The plain tests are read only: `query` opens `w32time` with
//! `SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG` and nothing else. They
//! print nothing, so no machine detail reaches the test log.
//!
//! The ignored tests stop, disable and restore the real `w32time`. Run them
//! only on a throwaway VM, elevated, with `NTPC_ALLOW_SERVICE_TESTS=1`.

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

fn allowed() -> bool {
    std::env::var("NTPC_ALLOW_SERVICE_TESTS").as_deref() == Ok("1")
}

/// Stops and disables the real `w32time`, then restores it and checks the
/// start type and run state match. MUTATES THE SYSTEM. Not run by the
/// builder.
#[test]
#[ignore = "stops and disables the real w32time: throwaway VM only"]
fn admin_take_over_and_restore_round_trip() {
    assert!(
        allowed(),
        "set NTPC_ALLOW_SERVICE_TESTS=1 on a throwaway VM"
    );
    assert!(crate::is_elevated().unwrap(), "run elevated");
    let mut ctl = ScmControl;
    let before = ctl.query(W32TIME).unwrap();
    let record = take_over(&mut ctl, None, |_| Ok(())).unwrap();
    assert_eq!(record, Restore::from_state(before));
    let mid = ctl.query(W32TIME).unwrap();
    assert_eq!(mid.run, RunState::Stopped);
    assert_eq!(mid.start, StartType::Disabled);
    restore(&mut ctl, &record).unwrap();
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
    assert!(
        allowed(),
        "set NTPC_ALLOW_SERVICE_TESTS=1 on a throwaway VM"
    );
    let mut ctl = ScmControl;
    let before = ctl.query(W32TIME).unwrap();
    for t in StartType::ALL {
        ctl.set_start_type(W32TIME, t).unwrap();
        assert_eq!(ctl.query(W32TIME).unwrap().start, t);
    }
    ctl.set_start_type(W32TIME, before.start).unwrap();
}
