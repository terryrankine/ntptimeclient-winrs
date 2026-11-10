use super::fake::{Call, FakeScm, Script};
use super::*;

fn w(name: &str) -> String {
    name.to_owned()
}

// The signature must match the persist closure that `take_over` takes.
#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn persist_ok(_: &Restore) -> Result<(), String> {
    Ok(())
}

fn rec(start: StartType, was_running: bool) -> Restore {
    Restore::new(start, was_running)
}

fn quick() -> Timing {
    Timing {
        polls: 4,
        interval: Duration::from_millis(1),
    }
}

// ---- The seven from the brief ----

#[test]
fn take_over_records_previous_state() {
    let mut ctl = FakeScm::new(Script::running(StartType::AutomaticDelayed));
    let r = take_over(&mut ctl, None, persist_ok).unwrap();
    assert_eq!(r, rec(StartType::AutomaticDelayed, true));
    assert_eq!(
        ctl.state(),
        Some(SvcState {
            run: RunState::Stopped,
            start: StartType::Disabled
        })
    );
}

#[test]
fn restore_returns_previous_state() {
    let mut ctl = FakeScm::new(Script::running(StartType::Manual));
    let r = take_over(&mut ctl, None, persist_ok).unwrap();
    let out = restore(&mut ctl, &r).unwrap();
    assert!(out.started);
    assert_eq!(
        ctl.state(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::Manual
        })
    );
}

#[test]
fn take_over_fails_cleanly_when_stop_refused() {
    let mut script = Script::running(StartType::Automatic);
    script.refuse_stop = Some(SvcError::DependentsRunning);
    let mut ctl = FakeScm::new(script);
    let e = take_over(&mut ctl, None, persist_ok).unwrap_err();
    assert_eq!(e, TakeoverError::Stop(SvcError::DependentsRunning));
    // Nothing changed: still running, still automatic, no start type call.
    assert_eq!(
        ctl.state(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::Automatic
        })
    );
    assert!(
        !ctl.calls()
            .iter()
            .any(|c| matches!(c, Call::SetStartType(_, _)))
    );
}

#[test]
fn restart_after_takeover_is_detected() {
    let mut ctl = FakeScm::new(Script::running(StartType::Manual));
    take_over(&mut ctl, None, persist_ok).unwrap();
    assert!(!is_running(&ctl));
    // Policy or a trigger brings it back.
    ctl.script_mut().state = Some(SvcState {
        run: RunState::Running,
        start: StartType::Automatic,
    });
    assert!(is_running(&ctl));
    let d = monitor_decision(Some(false), is_running(&ctl));
    assert!(!d.adjustment_allowed);
    assert!(d.changed);
}

// ---- Order and crash safety ----

#[test]
fn record_is_persisted_before_any_change() {
    let mut ctl = FakeScm::new(Script::running(StartType::Automatic));
    let log = ctl.log();
    take_over(&mut ctl, None, |_| {
        log.borrow_mut().push(Call::Mark("persist"));
        Ok(())
    })
    .unwrap();
    let calls = ctl.calls();
    let persist = calls
        .iter()
        .position(|c| *c == Call::Mark("persist"))
        .unwrap();
    let first_change = calls
        .iter()
        .position(|c| matches!(c, Call::Stop(_) | Call::SetStartType(_, _)))
        .unwrap();
    assert!(persist < first_change, "{calls:?}");
    assert_eq!(calls[0], Call::Query(w("w32time")));
}

#[test]
fn persist_failure_changes_nothing() {
    let mut ctl = FakeScm::new(Script::running(StartType::Automatic));
    let e = take_over(&mut ctl, None, |_| Err("disk full".to_owned())).unwrap_err();
    assert_eq!(e, TakeoverError::Persist("disk full".to_owned()));
    assert!(!ctl.mutated());
}

#[test]
fn crash_between_record_and_stop_restores_to_the_true_original() {
    // The record was written, then the process died before the stop.
    let mut ctl = FakeScm::new(Script::running(StartType::AutomaticDelayed));
    let mut saved = None;
    let _ = take_over(&mut ctl, None, |r| {
        saved = Some(*r);
        Err("crash".to_owned())
    });
    let saved = saved.unwrap();
    let out = restore(&mut ctl, &saved).unwrap();
    // Already running counts as success.
    assert!(out.started);
    assert_eq!(
        ctl.state(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::AutomaticDelayed
        })
    );
}

#[test]
fn rerun_keeps_the_true_original_record() {
    // First install took over. Second install sees stopped and disabled.
    let mut ctl = FakeScm::new(Script::running(StartType::Automatic));
    let first = take_over(&mut ctl, None, persist_ok).unwrap();
    let mut persisted = false;
    let second = take_over(&mut ctl, Some(first), |_| {
        persisted = true;
        Ok(())
    })
    .unwrap();
    assert_eq!(second, rec(StartType::Automatic, true));
    assert!(!persisted, "an existing record must not be overwritten");
}

#[test]
fn take_over_is_idempotent_when_already_stopped_and_disabled() {
    let mut ctl = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    let r = take_over(&mut ctl, None, persist_ok).unwrap();
    assert_eq!(r, rec(StartType::Disabled, false));
    assert!(!ctl.calls().iter().any(|c| matches!(c, Call::Stop(_))));
}

// ---- Stop and disable failures ----

#[test]
fn stop_timeout_is_reported() {
    let mut script = Script::running(StartType::Manual);
    script.stop_pending_polls = u32::MAX;
    let mut ctl = FakeScm::new(script);
    let e = take_over_with(&mut ctl, None, persist_ok, quick()).unwrap_err();
    assert_eq!(e, TakeoverError::StopTimeout);
    // The start type was not touched.
    assert_eq!(ctl.state().unwrap().start, StartType::Manual);
}

#[test]
fn stop_that_takes_a_few_polls_succeeds() {
    let mut script = Script::running(StartType::Manual);
    script.stop_pending_polls = 2;
    let mut ctl = FakeScm::new(script);
    take_over_with(&mut ctl, None, persist_ok, quick()).unwrap();
    assert!(ctl.calls().contains(&Call::Pause));
}

#[test]
fn stop_refused_then_nothing_was_changed() {
    let mut script = Script::running(StartType::AutomaticDelayed);
    script.refuse_stop = Some(SvcError::AccessDenied);
    let mut ctl = FakeScm::new(script);
    assert!(take_over(&mut ctl, None, persist_ok).is_err());
    let calls = ctl.calls();
    assert!(
        calls
            .iter()
            .all(|c| matches!(c, Call::Query(_) | Call::Stop(_))),
        "{calls:?}"
    );
}

#[test]
fn disable_failure_after_stop_rolls_back_and_reports_both() {
    let mut script = Script::running(StartType::Automatic);
    script.refuse_set_start = Some(SvcError::AccessDenied);
    script.refuse_start = Some(SvcError::Os {
        op: "start",
        code: 1053,
    });
    let mut ctl = FakeScm::new(script);
    let e = take_over(&mut ctl, None, persist_ok).unwrap_err();
    assert_eq!(
        e,
        TakeoverError::Disable {
            error: SvcError::AccessDenied,
            rollback: Some(SvcError::Os {
                op: "start",
                code: 1053
            }),
        }
    );
    assert!(ctl.calls().contains(&Call::Start(w("w32time"))));
}

#[test]
fn disable_failure_rollback_restarts_a_running_service() {
    let mut script = Script::running(StartType::Automatic);
    script.refuse_set_start = Some(SvcError::AccessDenied);
    let mut ctl = FakeScm::new(script);
    let e = take_over(&mut ctl, None, persist_ok).unwrap_err();
    assert_eq!(
        e,
        TakeoverError::Disable {
            error: SvcError::AccessDenied,
            rollback: None
        }
    );
    assert_eq!(ctl.state().unwrap().run, RunState::Running);
}

#[test]
fn disable_failure_does_not_start_a_service_that_was_stopped() {
    let mut script = Script::with(RunState::Stopped, StartType::Manual);
    script.refuse_set_start = Some(SvcError::AccessDenied);
    let mut ctl = FakeScm::new(script);
    assert!(take_over(&mut ctl, None, persist_ok).is_err());
    assert!(!ctl.calls().iter().any(|c| matches!(c, Call::Start(_))));
}

#[test]
fn restart_during_takeover_fails_verification() {
    let mut script = Script::running(StartType::Automatic);
    script.restart_after_disable = true;
    let mut ctl = FakeScm::new(script);
    let e = take_over(&mut ctl, None, persist_ok).unwrap_err();
    assert!(matches!(e, TakeoverError::VerifyMismatch(_)), "{e:?}");
}

#[test]
fn take_over_of_a_missing_service_is_an_error_without_change() {
    let mut ctl = FakeScm::new(Script::missing());
    let e = take_over(&mut ctl, None, persist_ok).unwrap_err();
    assert_eq!(e, TakeoverError::Query(SvcError::NotFound));
    assert!(!ctl.mutated());
}

#[test]
fn only_w32time_is_ever_touched() {
    let mut ctl = FakeScm::new(Script::running(StartType::Automatic));
    let r = take_over(&mut ctl, None, persist_ok).unwrap();
    restore(&mut ctl, &r).unwrap();
    for c in ctl.calls() {
        match c {
            Call::Query(n) | Call::Stop(n) | Call::Start(n) | Call::SetStartType(n, _) => {
                assert_eq!(n, "w32time");
            }
            Call::Pause | Call::Mark(_) => {}
        }
    }
}

// ---- Restore ----

#[test]
fn restore_when_w32time_is_missing_reports_not_found() {
    let mut ctl = FakeScm::new(Script::missing());
    let e = restore(&mut ctl, &rec(StartType::Automatic, true)).unwrap_err();
    assert_eq!(e, RestoreError::SetStartType(SvcError::NotFound));
}

#[test]
fn restore_when_original_was_disabled_does_not_start() {
    let mut ctl = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    // Disabled but running at install time is possible. It cannot start.
    let out = restore(&mut ctl, &rec(StartType::Disabled, true)).unwrap();
    assert!(!out.started);
    assert!(out.start_skipped_disabled);
    assert!(!ctl.calls().iter().any(|c| matches!(c, Call::Start(_))));
    assert_eq!(ctl.state().unwrap().start, StartType::Disabled);
}

#[test]
fn restore_of_a_stopped_original_does_not_start() {
    let mut ctl = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    let out = restore(&mut ctl, &rec(StartType::Manual, false)).unwrap();
    assert!(!out.started);
    assert_eq!(
        ctl.state(),
        Some(SvcState {
            run: RunState::Stopped,
            start: StartType::Manual
        })
    );
}

#[test]
fn restore_is_idempotent() {
    let mut ctl = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    let r = rec(StartType::Automatic, true);
    restore(&mut ctl, &r).unwrap();
    restore(&mut ctl, &r).unwrap();
    assert_eq!(
        ctl.state(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::Automatic
        })
    );
}

#[test]
fn restore_start_failure_is_reported() {
    let mut script = Script::with(RunState::Stopped, StartType::Disabled);
    script.refuse_start = Some(SvcError::AccessDenied);
    let mut ctl = FakeScm::new(script);
    let e = restore(&mut ctl, &rec(StartType::Manual, true)).unwrap_err();
    assert_eq!(e, RestoreError::Start(SvcError::AccessDenied));
    // The start type was put back before the start failed.
    assert_eq!(ctl.state().unwrap().start, StartType::Manual);
}

// ---- is_running and the monitor ----

#[test]
fn is_running_is_true_on_query_error() {
    let mut script = Script::with(RunState::Stopped, StartType::Disabled);
    script.query_error = Some(SvcError::AccessDenied);
    assert!(is_running(&FakeScm::new(script)));
}

#[test]
fn is_running_is_true_when_missing() {
    // A missing w32time cannot fight, but "cannot tell" is the rule.
    assert!(is_running(&FakeScm::new(Script::missing())));
}

#[test]
fn is_running_counts_every_state_but_stopped() {
    for run in [
        RunState::StartPending,
        RunState::StopPending,
        RunState::Running,
        RunState::ContinuePending,
        RunState::PausePending,
        RunState::Paused,
    ] {
        let ctl = FakeScm::new(Script::with(run, StartType::Manual));
        assert!(is_running(&ctl), "{run:?}");
    }
    let ctl = FakeScm::new(Script::with(RunState::Stopped, StartType::Manual));
    assert!(!is_running(&ctl));
}

#[test]
fn monitor_over_all_transitions() {
    // First check at start: always "changed" so the host logs it.
    let d = monitor_decision(None, false);
    assert_eq!((d.adjustment_allowed, d.changed), (true, true));
    let d = monitor_decision(None, true);
    assert_eq!((d.adjustment_allowed, d.changed), (false, true));
    // Stopped stays stopped: level re-sent, nothing to log.
    let d = monitor_decision(Some(false), false);
    assert_eq!((d.adjustment_allowed, d.changed), (true, false));
    // Stopped to running: stop adjusting, log.
    let d = monitor_decision(Some(false), true);
    assert_eq!((d.adjustment_allowed, d.changed), (false, true));
    // Running to stopped: adjust again, log.
    let d = monitor_decision(Some(true), false);
    assert_eq!((d.adjustment_allowed, d.changed), (true, true));
    // Running stays running.
    let d = monitor_decision(Some(true), true);
    assert_eq!((d.adjustment_allowed, d.changed), (false, false));
}

#[test]
fn monitor_period_is_thirty_seconds() {
    assert_eq!(MONITOR_PERIOD, Duration::from_secs(30));
}

// ---- Raw mapping ----

#[test]
fn run_state_maps_documented_values() {
    assert_eq!(RunState::from_raw(1), Some(RunState::Stopped));
    assert_eq!(RunState::from_raw(2), Some(RunState::StartPending));
    assert_eq!(RunState::from_raw(3), Some(RunState::StopPending));
    assert_eq!(RunState::from_raw(4), Some(RunState::Running));
    assert_eq!(RunState::from_raw(5), Some(RunState::ContinuePending));
    assert_eq!(RunState::from_raw(6), Some(RunState::PausePending));
    assert_eq!(RunState::from_raw(7), Some(RunState::Paused));
    assert_eq!(RunState::from_raw(0), None);
    assert_eq!(RunState::from_raw(8), None);
}

#[test]
fn start_type_maps_service_values_and_refuses_driver_values() {
    assert_eq!(StartType::from_raw(2, false), Ok(StartType::Automatic));
    assert_eq!(
        StartType::from_raw(2, true),
        Ok(StartType::AutomaticDelayed)
    );
    assert_eq!(StartType::from_raw(3, true), Ok(StartType::Manual));
    assert_eq!(StartType::from_raw(4, false), Ok(StartType::Disabled));
    for raw in [0, 1, 5, u32::MAX] {
        assert_eq!(
            StartType::from_raw(raw, false),
            Err(SvcError::UnsupportedStartType(raw))
        );
    }
}

#[test]
fn error_text_names_no_service_or_path() {
    let all = [
        SvcError::NotFound,
        SvcError::AccessDenied,
        SvcError::NotActive,
        SvcError::AlreadyRunning,
        SvcError::DependentsRunning,
        SvcError::CannotAcceptControl,
        SvcError::Disabled,
        SvcError::UnsupportedStartType(0),
        SvcError::UnknownState(9),
        SvcError::Os {
            op: "query",
            code: 5,
        },
    ];
    for e in all {
        let t = e.to_string();
        assert!(!t.contains('\\') && !t.contains(':'), "{t}");
    }
}

#[test]
fn svc_error_maps_known_codes() {
    assert_eq!(SvcError::from_code("q", 1060), SvcError::NotFound);
    assert_eq!(SvcError::from_code("q", 5), SvcError::AccessDenied);
    assert_eq!(SvcError::from_code("q", 1062), SvcError::NotActive);
    assert_eq!(SvcError::from_code("q", 1056), SvcError::AlreadyRunning);
    assert_eq!(SvcError::from_code("q", 1051), SvcError::DependentsRunning);
    assert_eq!(
        SvcError::from_code("q", 1061),
        SvcError::CannotAcceptControl
    );
    assert_eq!(SvcError::from_code("q", 1058), SvcError::Disabled);
    assert_eq!(
        SvcError::from_code("q", 1053),
        SvcError::Os {
            op: "q",
            code: 1053
        }
    );
}

// ---- restore.json format ----

#[test]
fn record_round_trips_every_value() {
    for start in StartType::ALL {
        for was_running in [false, true] {
            let r = rec(start, was_running);
            let text = r.encode();
            assert_eq!(Restore::decode(text.as_bytes()), Ok(r));
            assert!(text.len() <= Restore::MAX_BYTES);
        }
    }
}

#[test]
fn record_has_the_documented_shape() {
    assert_eq!(
        rec(StartType::AutomaticDelayed, true).encode(),
        "{\"version\":1,\"service\":\"w32time\",\"start_type\":\"automatic_delayed\",\"was_running\":true}\n"
    );
}

#[test]
fn tampered_records_are_refused() {
    let good = rec(StartType::Manual, true).encode();
    let bad = [
        good.replace("w32time", "WinDefend"),
        good.replace("w32time", "W32Time"),
        good.replace("\"manual\"", "\"boot\""),
        good.replace("\"manual\"", "\"system\""),
        good.replace("\"manual\"", "\"\""),
        good.replace("\"version\":1", "\"version\":2"),
        good.replace("\"version\":1", "\"version\":0"),
        good.replace("true", "1"),
        good.replace('}', ",\"was_running\":false}"),
        good.replace("{\"version\":1,", "{\"version\":1,\"version\":1,"),
        good.replace(',', ", "),
        good.replace('\n', "\r\n"),
        format!("\u{feff}{good}"),
        format!("{good}\n"),
        good[..good.len() - 2].to_owned(),
        String::new(),
        "{}".to_owned(),
    ];
    for b in bad {
        assert_eq!(
            Restore::decode(b.as_bytes()),
            Err(RestoreFormatError::NotCanonical),
            "{b:?}"
        );
    }
}

#[test]
fn record_without_trailing_newline_is_accepted() {
    let good = rec(StartType::Disabled, false).encode();
    let trimmed = good.trim_end_matches('\n');
    assert_eq!(
        Restore::decode(trimmed.as_bytes()),
        Ok(rec(StartType::Disabled, false))
    );
}

#[test]
fn huge_record_is_refused_as_too_large() {
    let mut big = rec(StartType::Manual, true).encode().into_bytes();
    big.resize(Restore::MAX_BYTES + 1, b' ');
    assert_eq!(Restore::decode(&big), Err(RestoreFormatError::TooLarge));
}

#[test]
fn non_utf8_record_is_refused() {
    assert_eq!(
        Restore::decode(&[0xff, 0xfe, b'{']),
        Err(RestoreFormatError::NotCanonical)
    );
}
