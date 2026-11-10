//! Install tests over the fakes in `cli/tests.rs`.

use super::*;

// ---- The three from the brief ----

#[test]
fn install_aborts_on_domain_joined_silent_without_flag() {
    let mut w = World::new(JoinState::Domain);
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert!(w.untouched());
    assert!(!w.store.secured, "the state directory is not touched");
    assert_eq!(w.w32time(), original());
    assert!(w.host.text().contains("--confirm-domain-joined"));
    assert!(w.host.text().contains("-ConfirmDomainJoined"));
}

#[test]
fn install_proceeds_on_domain_joined_with_flag() {
    let mut w = World::new(JoinState::Domain);
    assert_eq!(w.install(SILENT_CONFIRMED), exit::OK);
    assert_eq!(w.w32time(), taken_over());
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::AutomaticDelayed, true))
    );
    assert!(w.reg.registered);
    assert!(w.host.text().contains("domain"));
}

// ---- Domain rule ----

#[test]
fn non_terminal_stdin_counts_as_silent() {
    let mut w = World::new(JoinState::Domain);
    w.host.stdin_console = false;
    w.host.stderr_console = true;
    assert_eq!(w.install(PLAIN), exit::DOMAIN_JOINED);
    assert_eq!(w.host.asked, 0);
    assert!(w.untouched());
}

#[test]
fn unknown_join_state_aborts_a_silent_install() {
    let mut w = World::new(JoinState::Unknown);
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert!(w.untouched());
}

#[test]
fn interactive_decline_aborts_without_change() {
    let mut w = World::new(JoinState::Domain);
    w.host.consoles(true);
    w.host.answer = false;
    assert_eq!(w.install(PLAIN), exit::DECLINED);
    assert_eq!(w.host.asked, 1);
    assert!(w.untouched());
    assert!(!w.store.secured);
}

#[test]
fn interactive_yes_proceeds() {
    let mut w = World::new(JoinState::Unknown);
    w.host.consoles(true);
    w.host.answer = true;
    assert_eq!(w.install(PLAIN), exit::OK);
    assert_eq!(w.w32time(), taken_over());
}

#[test]
fn silent_flag_wins_over_a_terminal() {
    let mut w = World::new(JoinState::Domain);
    w.host.consoles(true);
    w.host.answer = true;
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert_eq!(w.host.asked, 0);
}

#[test]
fn workgroup_installs_without_asking() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.consoles(true);
    assert_eq!(w.install(PLAIN), exit::OK);
    assert_eq!(w.host.asked, 0);
}

// ---- Install refusals ----

#[test]
fn install_refuses_when_not_elevated() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Ok(false);
    assert_eq!(w.install(SILENT), exit::NOT_ELEVATED);
    assert!(w.untouched());
}

#[test]
fn install_refuses_when_elevation_cannot_be_read() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Err("token unreadable".to_owned());
    assert_eq!(w.install(SILENT), exit::NOT_ELEVATED);
    assert!(w.untouched());
}

#[test]
fn install_refuses_before_any_change_when_registration_is_not_built() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.not_ready = true;
    assert_eq!(w.install(SILENT), exit::REGISTER);
    assert!(w.untouched());
    assert!(!w.store.secured);
    assert_eq!(w.scm.calls(), Vec::<Call>::new());
}

#[test]
fn install_refuses_when_the_state_dir_cannot_be_secured() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.secure_error = Some(SecureRefusal::Directory("unexpected entry".to_owned()));
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert!(w.untouched());
}

#[test]
fn install_refuses_when_the_record_cannot_be_saved() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.save_error = Some("disk full".to_owned());
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert!(!w.scm.mutated());
    assert_eq!(w.w32time(), original());
}

#[test]
fn install_refuses_on_a_tampered_record_and_changes_nothing() {
    let mut w = World::new(JoinState::Workgroup);
    w.store = MemStore::invalid();
    assert_eq!(w.install(SILENT), exit::RECORD_INVALID);
    assert!(!w.scm.mutated());
    assert_eq!(w.w32time(), original());
}

#[test]
fn install_refuses_on_an_unreadable_record() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.record = Some(Err(LoadError::Io(io::ErrorKind::PermissionDenied)));
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert!(!w.scm.mutated());
}

#[test]
fn install_reports_a_refused_stop() {
    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::running(StartType::Automatic);
    s.refuse_stop = Some(SvcError::DependentsRunning);
    w.scm = FakeScm::new(s);
    assert_eq!(w.install(SILENT), exit::TAKEOVER);
    assert!(!w.reg.registered);
    // M8: nothing changed, so the record this run wrote is gone again.
    assert_eq!(w.store.saved(), None);
    assert!(w.host.text().contains("new restore record was removed"));
}

#[test]
fn a_refused_stop_keeps_a_pre_existing_record() {
    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::with(RunState::Running, StartType::Manual);
    s.refuse_stop = Some(SvcError::DependentsRunning);
    w.scm = FakeScm::new(s);
    w.store = MemStore::with(Restore::new(StartType::Automatic, true));
    assert_eq!(w.install(SILENT), exit::TAKEOVER);
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Automatic, true))
    );
    assert!(w.host.text().contains("earlier restore record is kept"));
}

#[test]
fn a_failure_after_a_change_keeps_the_new_record() {
    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::running(StartType::Automatic);
    s.stop_pending_polls = u32::MAX;
    w.scm = FakeScm::new(s);
    // The default timing would poll for 30 s of fake pauses, which cost
    // nothing in the fake.
    assert_eq!(w.install(SILENT), exit::TAKEOVER);
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Automatic, true))
    );
    assert!(w.host.text().contains("Run uninstall"));
}

// ---- R84: already disabled, no record ----

#[test]
fn already_disabled_without_a_record_is_refused() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.install(SILENT), exit::DISABLED_ORIGINAL);
    assert!(w.untouched());
    assert_eq!(w.store.saved(), None);
    // Documented: the check runs after the state directory was secured.
    assert!(w.store.secured);
    assert_eq!(
        w.w32time(),
        Some(SvcState {
            run: RunState::Stopped,
            start: StartType::Disabled
        })
    );
    assert!(w.host.text().contains("--accept-disabled-original"));
}

#[test]
fn already_disabled_with_the_flag_records_disabled() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.install(ACCEPT_DISABLED), exit::OK);
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Disabled, false))
    );
}

#[test]
fn already_disabled_with_a_record_is_not_affected() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    assert_eq!(w.install(SILENT), exit::OK);
    assert_eq!(w.store.saved(), Some(Restore::new(StartType::Manual, true)));
}

#[test]
fn disabled_original_code_is_outside_the_other_ranges() {
    assert!(!(2..=11).contains(&exit::DISABLED_ORIGINAL));
    assert!(!(40..=47).contains(&exit::DISABLED_ORIGINAL));
    assert_ne!(exit::DISABLED_ORIGINAL, exit::OK);
    for c in exit::ALL {
        assert!(!(40..=47).contains(&c), "{c}");
    }
}

// ---- R83: every console and flag combination ----

#[test]
fn console_flag_and_join_matrix() {
    for join in [JoinState::Workgroup, JoinState::Domain, JoinState::Unknown] {
        for stdin_console in [false, true] {
            for stderr_console in [false, true] {
                for flag in [false, true] {
                    let mut w = World::new(join);
                    w.host.stdin_console = stdin_console;
                    w.host.stderr_console = stderr_console;
                    // The user would say no if asked.
                    w.host.answer = false;
                    let opts = if flag { PLAIN_CONFIRMED } else { PLAIN };
                    let code = w.install(opts);
                    let interactive = stdin_console && stderr_console;
                    let case =
                        format!("{join:?} in={stdin_console} err={stderr_console} flag={flag}");
                    let (want, asked) = match (join, flag, interactive) {
                        (JoinState::Workgroup, _, _) | (_, true, _) => (exit::OK, 0),
                        (_, false, true) => (exit::DECLINED, 1),
                        (_, false, false) => (exit::DOMAIN_JOINED, 0),
                    };
                    assert_eq!(code, want, "{case}");
                    assert_eq!(w.host.asked, asked, "{case}");
                }
            }
        }
    }
}

#[test]
fn register_failure_rolls_w32time_back_and_removes_the_record() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.register_error = Some("create failed".to_owned());
    assert_eq!(w.install(SILENT), exit::REGISTER_FAILED);
    assert_eq!(w.w32time(), original());
    assert_eq!(w.store.saved(), None);
    assert!(w.host.text().contains("w32time was put back"));
}

#[test]
fn rerun_install_keeps_the_true_original_record() {
    let mut w = World::new(JoinState::Workgroup);
    assert_eq!(w.install(SILENT), exit::OK);
    assert_eq!(w.install(SILENT), exit::OK);
    assert_eq!(w.store.saves, 1, "second install must not overwrite");
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::AutomaticDelayed, true))
    );
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(w.w32time(), original());
}

#[test]
fn only_w32time_is_touched_by_install_and_uninstall() {
    let mut w = World::new(JoinState::Workgroup);
    w.install(SILENT);
    w.uninstall();
    for c in w.scm.calls() {
        if let Call::Query(n) | Call::Stop(n) | Call::Start(n) | Call::SetStartType(n, _) = c {
            assert_eq!(n, "w32time");
        }
    }
}

#[test]
fn every_secure_refusal_class_has_its_own_install_code_and_changes_nothing() {
    let want = [
        exit::STATE_DIR,
        exit::BAD_STATE_PATH,
        exit::ROLLBACK_FAILED,
        exit::CARRY_FAILED,
        exit::RECORD_DROPPED,
    ];
    for (r, code) in refusals().into_iter().zip(want) {
        let mut w = World::new(JoinState::Workgroup);
        w.store.secure_error = Some(r.clone());
        assert_eq!(w.install(SILENT), code, "{r:?}");
        assert_eq!(w.scm.calls(), Vec::<Call>::new(), "{r:?}");
        assert_eq!(w.store.saves, 0);
        assert!(!w.reg.registered);
        assert_eq!(w.w32time(), original());
        assert!(!w.host.text().contains('\\'), "{}", w.host.text());
    }
    let codes: BTreeSet<u8> = want.into_iter().collect();
    assert_eq!(codes.len(), want.len());
}

#[test]
fn a_dropped_record_says_to_restore_by_hand_first() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.secure_error = Some(SecureRefusal::RecordDropped);
    assert_eq!(w.install(SILENT), exit::RECORD_DROPPED);
    let t = w.host.text();
    assert!(t.contains("Restore w32time by hand first"), "{t}");
    assert!(t.contains("quarantine"), "{t}");
}

#[test]
fn rollback_failed_points_at_the_quarantine_and_the_docs() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.secure_error = Some(SecureRefusal::RollbackFailed("x".to_owned()));
    assert_eq!(w.install(SILENT), exit::ROLLBACK_FAILED);
    let t = w.host.text();
    assert!(t.contains("sibling quarantine directory"), "{t}");
    assert!(t.contains("documentation"), "{t}");
}

#[test]
fn install_refuses_an_untrusted_record_file() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.record = Some(Err(LoadError::NotTrusted(TrustFailure::Owner)));
    assert_eq!(w.install(SILENT), exit::RECORD_NOT_TRUSTED);
    assert!(!w.scm.mutated());
    assert_eq!(w.store.saves, 0);
}

/// The mapping from every `AclError` variant that exists today. The enum
/// is non-exhaustive: the wildcard arm cannot be reached from a test,
/// because no variant outside this list can be built.
#[cfg(windows)]
#[test]
fn acl_errors_map_to_classes() {
    use ntpc_platform::AclError as A;
    let cases = [
        (A::BadPath, exit::BAD_STATE_PATH),
        (A::TrailingDotOrSpace, exit::BAD_STATE_PATH),
        (A::ReservedName, exit::BAD_STATE_PATH),
        (A::NotFixedDrive, exit::BAD_STATE_PATH),
        (
            A::RollbackFailed {
                cause: "a".to_owned(),
                rollback: "b".to_owned(),
            },
            exit::ROLLBACK_FAILED,
        ),
        (
            A::RestoreCarryFailed {
                detail: "c".to_owned(),
            },
            exit::CARRY_FAILED,
        ),
        (A::PathChanged, exit::STATE_DIR),
        (A::Link, exit::STATE_DIR),
        (A::ParentLink, exit::STATE_DIR),
        (A::NotADirectory, exit::STATE_DIR),
        (A::UntrustedOwner, exit::STATE_DIR),
        (A::UntrustedParent, exit::STATE_DIR),
        (A::UnexpectedChild, exit::STATE_DIR),
        (A::DaclNotApplied, exit::STATE_DIR),
        (
            A::Os {
                op: "open",
                detail: "d".to_owned(),
            },
            exit::STATE_DIR,
        ),
    ];
    for (e, code) in cases {
        let c = classify_acl_error(&e);
        assert_eq!(c.install_code(), code, "{e:?}");
        // The class keeps the platform text, which holds no path.
        assert!(!c.to_string().contains('\\'), "{c}");
    }
}

// ---- R95: register failed after the takeover ----

#[test]
fn register_failure_with_a_failed_put_back_says_so() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.register_error = Some("create failed".to_owned());
    // The takeover works, then every start fails.
    let mut s = Script::running(StartType::Manual);
    s.refuse_start = Some(SvcError::AccessDenied);
    w.scm = FakeScm::new(s);
    assert_eq!(w.install(SILENT), exit::REGISTER_FAILED);
    let t = w.host.text();
    assert!(t.contains("w32time was NOT put back"), "{t}");
    // The record stays for uninstall.
    assert_eq!(w.store.saved(), Some(Restore::new(StartType::Manual, true)));
}

#[test]
fn not_ready_and_register_failed_are_different_codes() {
    assert_ne!(exit::REGISTER, exit::REGISTER_FAILED);
}

#[test]
fn disabled_original_text_names_the_exe_flag_and_the_script_switch() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.install(SILENT), exit::DISABLED_ORIGINAL);
    let t = w.host.text();
    assert!(t.contains("--accept-disabled-original"), "{t}");
    assert!(t.contains("-AcceptDisabledOriginal"), "{t}");
}

// ---- N5: a missing parent folder ----

#[test]
fn install_refuses_when_the_state_dir_parent_is_missing() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.dir = Some(DirState::ParentMissing);
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert_eq!(w.scm.calls(), Vec::<Call>::new());
    assert!(!w.store.secured);
    assert!(w.host.text().contains("state directory unavailable"));
}

// ---- N6: the warning goes to the question's stream ----

#[test]
fn domain_warnings_use_the_warning_stream() {
    for (opts, interactive) in [(PLAIN, true), (SILENT, false), (SILENT_CONFIRMED, false)] {
        let mut w = World::new(JoinState::Domain);
        w.host.consoles(interactive);
        w.install(opts);
        assert!(
            w.host
                .warnings
                .iter()
                .any(|l| l.contains("joined to a domain")),
            "{opts:?}"
        );
    }
}

// ---- Task 14c-B: exe location and start after register ----

#[test]
fn install_refuses_an_unsafe_exe_location_before_any_change() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.unsafe_location = true;
    assert_eq!(w.install(SILENT), exit::EXE_LOCATION);
    assert!(w.untouched());
    assert!(
        w.host.text().contains("only administrators"),
        "{}",
        w.host.text()
    );
}

#[test]
fn install_starts_our_service_after_registering() {
    let mut w = World::new(JoinState::Workgroup);
    assert_eq!(w.install(SILENT), exit::OK);
    assert!(w.reg.registered);
    assert_eq!(w.reg.start_calls, 1);
}

#[test]
fn a_failed_start_keeps_the_install_and_says_so() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.start_error = Some("access denied".to_owned());
    assert_eq!(w.install(SILENT), exit::START_FAILED);
    // Installed: registration kept, w32time stays taken over.
    assert!(w.reg.registered);
    assert_eq!(w.w32time(), taken_over());
    assert!(w.host.text().contains("next boot"), "{}", w.host.text());
}

#[test]
fn a_register_failure_never_starts_anything() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.register_error = Some("create failed".to_owned());
    assert_eq!(w.install(SILENT), exit::REGISTER_FAILED);
    assert_eq!(w.reg.start_calls, 0);
}
