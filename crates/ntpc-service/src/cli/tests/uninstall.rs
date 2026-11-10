//! Uninstall tests over the fakes in `cli/tests.rs`.

use super::*;

#[test]
fn uninstall_restores_w32time_even_if_service_missing() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = false;
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(
        w.w32time(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::Manual
        })
    );
    assert_eq!(w.store.saved(), None, "record removed after restore");
}

// ---- Uninstall ----

#[test]
fn uninstall_refuses_when_not_elevated() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Ok(false);
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    assert_eq!(w.uninstall(), exit::NOT_ELEVATED);
    assert!(!w.scm.mutated());
    assert!(!w.reg.stopped);
}

#[test]
fn uninstall_without_a_record_leaves_w32time_alone() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Manual));
    assert_eq!(w.uninstall(), exit::OK);
    assert!(!w.scm.mutated());
    assert!(w.host.text().contains("no restore record"));
}

#[test]
fn uninstall_without_a_record_while_disabled_is_exit_18_not_0() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.uninstall(), exit::NO_RECORD_DISABLED);
    assert!(!w.scm.mutated());
    let t = w.host.text();
    assert!(t.contains("still disabled"), "{t}");
    assert!(t.contains("services.msc"), "{t}");
    // w32time not back: our registration is kept (R94).
    assert_eq!(w.reg.unregister_calls, 0);
}

#[test]
fn uninstall_with_a_tampered_record_leaves_w32time_alone() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::invalid();
    // Disabled and no usable record: 18 wins over 7, the text says both.
    assert_eq!(w.uninstall(), exit::NO_RECORD_DISABLED);
    assert!(w.host.text().contains("not valid"));
    assert!(!w.scm.mutated());
    // The file stays for the administrator to inspect.
    assert!(matches!(w.store.record, Some(Err(_))));
}

#[test]
fn uninstall_keeps_the_record_when_restore_fails() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::missing());
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    assert_eq!(w.uninstall(), exit::RESTORE);
    assert_eq!(w.store.saved(), Some(Restore::new(StartType::Manual, true)));
}

#[test]
fn uninstall_restores_even_when_unregister_fails() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Automatic, false));
    w.reg.present = true;
    w.reg.unregister_error = Some("delete failed".to_owned());
    assert_eq!(w.uninstall(), exit::UNREGISTER);
    assert_eq!(w.w32time().unwrap().start, StartType::Automatic);
}

#[test]
fn uninstall_reports_a_record_that_cannot_be_removed() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, false));
    w.store.remove_error = Some("locked".to_owned());
    assert_eq!(w.uninstall(), exit::STATE_DIR);
    assert_eq!(w.w32time().unwrap().start, StartType::Manual);
}

#[test]
fn uninstall_stops_our_service_before_restoring() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::OK);
    assert!(w.reg.stopped);
}

// ---- R86: uninstall trusts only a secured directory and a checked file ----

fn disabled_world_with_record() -> World {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w
}

#[test]
fn uninstall_leaves_w32time_alone_when_the_directory_is_not_trusted() {
    for r in refusals() {
        let mut w = disabled_world_with_record();
        w.store.secure_error = Some(r.clone());
        assert_eq!(w.uninstall(), exit::NO_RECORD_DISABLED, "{r:?}");
        // Only the read-only query that found w32time disabled.
        assert_eq!(
            w.scm.calls(),
            vec![Call::Query("w32time".to_owned())],
            "{r:?}"
        );
        let t = w.host.text();
        assert!(t.contains("services.msc"), "{t}");
        // The record is kept for the administrator.
        assert!(w.store.saved().is_some());
    }
}

#[test]
fn uninstall_leaves_w32time_alone_when_the_record_file_is_not_trusted() {
    for f in [
        TrustFailure::Owner,
        TrustFailure::Links,
        TrustFailure::TooLarge,
        TrustFailure::Reparse,
        TrustFailure::NotAFile,
    ] {
        let mut w = disabled_world_with_record();
        w.store.record = Some(Err(LoadError::NotTrusted(f)));
        assert_eq!(w.uninstall(), exit::NO_RECORD_DISABLED, "{f:?}");
        assert!(!w.scm.mutated(), "{f:?}");
        assert!(w.host.text().contains("services.msc"));
    }
}

#[test]
fn uninstall_secures_before_it_reads_and_restores_a_trusted_record() {
    let mut w = disabled_world_with_record();
    assert_eq!(w.uninstall(), exit::OK);
    assert!(w.store.secured);
    assert_eq!(
        w.w32time(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::Manual
        })
    );
}

#[test]
fn manual_restore_hint_guesses_no_start_type() {
    for t in ["automatic", "manual", "disabled", "delayed"] {
        assert!(!MANUAL_RESTORE.to_lowercase().contains(t), "{t}");
    }
}

fn manual_world_with_record() -> World {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Manual));
    w.store = MemStore::with(Restore::new(StartType::Automatic, true));
    w
}

#[test]
fn untrusted_directory_with_w32time_not_disabled_is_exit_17() {
    for r in refusals() {
        let mut w = manual_world_with_record();
        w.store.secure_error = Some(r.clone());
        assert_eq!(w.uninstall(), exit::RECORD_NOT_TRUSTED, "{r:?}");
        assert!(!w.scm.mutated(), "{r:?}");
    }
}

#[test]
fn untrusted_record_file_with_w32time_not_disabled_is_exit_17() {
    let mut w = manual_world_with_record();
    w.store.record = Some(Err(LoadError::NotTrusted(TrustFailure::Owner)));
    assert_eq!(w.uninstall(), exit::RECORD_NOT_TRUSTED);
    assert!(!w.scm.mutated());
}

// ---- N3: uninstall words for a dropped record ----

#[test]
fn a_dropped_record_on_uninstall_points_at_the_sibling_and_never_says_install() {
    let mut w = disabled_world_with_record();
    w.store.secure_error = Some(SecureRefusal::RecordDropped);
    w.uninstall();
    let t = w.host.text();
    assert!(t.contains(".old-"), "{t}");
    assert!(t.contains("services.msc"), "{t}");
    assert!(!t.contains("run install"), "{t}");
    // The manual hint is printed once, not repeated.
    assert_eq!(t.matches("services.msc").count(), 1, "{t}");
    assert!(!t.contains('\\'), "{t}");
}

// ---- R94: restore before unregister, keep the registration on failure ----

#[test]
fn restore_failure_keeps_our_registration() {
    let mut w = disabled_world_with_record();
    let mut s = Script::with(RunState::Stopped, StartType::Disabled);
    s.refuse_set_start = Some(SvcError::AccessDenied);
    w.scm = FakeScm::new(s);
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::RESTORE);
    assert_eq!(w.reg.unregister_calls, 0);
    assert!(w.host.text().contains("registration is kept"));
}

#[test]
fn restore_ok_then_unregister_runs_after_it() {
    let mut w = disabled_world_with_record();
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(w.reg.unregister_calls, 1);
    let t = w.host.text();
    let restored = t.find("start type set back").unwrap();
    let removed = t.find("registration removed").unwrap();
    assert!(restored < removed, "{t}");
}

#[test]
fn missing_service_still_restores_and_unregister_is_harmless() {
    let mut w = disabled_world_with_record();
    w.reg.present = false;
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(w.w32time().unwrap().start, StartType::Manual);
    assert_eq!(w.reg.unregister_calls, 1);
}

// ---- N5: no state directory, or no parent folder ----

#[test]
fn a_missing_state_dir_is_not_created_and_means_no_record() {
    for (state, text) in [
        (DirState::Missing, "no state directory"),
        (DirState::ParentMissing, "State directory unavailable"),
    ] {
        let mut w = World::new(JoinState::Workgroup);
        w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Manual));
        w.store.dir = Some(state);
        assert_eq!(w.uninstall(), exit::OK, "{state:?}");
        assert!(!w.store.secured, "secure would create it");
        assert!(w.host.text().contains(text), "{}", w.host.text());
        // The same with w32time disabled is R92's exit 18.
        let mut w = World::new(JoinState::Workgroup);
        w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
        w.store.dir = Some(state);
        assert_eq!(w.uninstall(), exit::NO_RECORD_DISABLED, "{state:?}");
    }
}

// ---- R94 concern (Task 14c-B): start our service again ----

#[test]
fn restore_failure_starts_our_stopped_service_again() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::missing());
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::RESTORE);
    assert_eq!(w.reg.unregister_calls, 0);
    assert_eq!(w.reg.start_calls, 1);
    assert!(w.host.text().contains("started again"), "{}", w.host.text());
}

#[test]
fn no_record_while_disabled_starts_our_stopped_service_again() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::NO_RECORD_DISABLED);
    assert_eq!(w.reg.start_calls, 1);
}

#[test]
fn a_failed_restart_is_reported_with_the_manual_step() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::missing());
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = true;
    w.reg.start_error = Some("access denied".to_owned());
    assert_eq!(w.uninstall(), exit::RESTORE);
    let t = w.host.text();
    assert!(t.contains("could not be started again"), "{t}");
    assert!(t.contains("no time sync"), "{t}");
}

#[test]
fn an_absent_service_is_not_started_again() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::missing());
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = false;
    assert_eq!(w.uninstall(), exit::RESTORE);
    assert_eq!(w.reg.start_calls, 0);
}

#[test]
fn a_successful_uninstall_never_starts_our_service() {
    let mut w = World::new(JoinState::Workgroup);
    w.store = MemStore::with(Restore::new(StartType::AutomaticDelayed, true));
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(w.reg.start_calls, 0);
}

#[test]
fn uninstall_refuses_a_foreign_service_and_changes_nothing() {
    let mut w = World::new(JoinState::Workgroup);
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.foreign = true;
    assert_eq!(w.uninstall(), exit::FOREIGN_SERVICE);
    assert!(!w.reg.stopped);
    assert_eq!(w.reg.unregister_calls, 0);
    assert!(!w.scm.mutated());
}
