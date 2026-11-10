//! Host wiring tests. Every dependency is a fake and time is fake, so the
//! real clock, network, services and registry are never touched.

mod common;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{Cmd, POOL, Rig, SEC, as_secs, bench, lock};
use ntpc_core::{Mono, QueryFailure, Tier};
use ntpc_service::host::{
    AdapterKey, DHCP_MIN_INTERVAL, DhcpRead, DhcpReadError, JoinClass, LEVEL_PERIOD, REARM_FIRST,
    SecureOutcome,
};
use ntpc_service::logging::{Level, LineLogger, Logger, MemorySink, RATE_MAX, escape};
use ntpc_service::status::{
    self, Blocked, FileStatusWriter, StatusError, StatusWriter, format_status, read_status,
};

const HOUR: u64 = 3600;

fn freqs(rig: &Rig) -> Vec<(Mono, f64, bool)> {
    rig.commands()
        .into_iter()
        .filter_map(|(t, c, ok)| match c {
            Cmd::Freq(f) => Some((t, f, ok)),
            _ => None,
        })
        .collect()
}

fn clock_cmds(rig: &Rig) -> Vec<(Mono, Cmd, bool)> {
    rig.commands()
        .into_iter()
        .filter(|(_, c, _)| matches!(c, Cmd::Freq(_) | Cmd::Step(_)))
        .collect()
}

// ------------------------------------------------------------ named tests

#[test]
fn applies_frequency_from_engine_actions() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.run(2 * HOUR);
    let f = freqs(&rig);
    assert!(f.len() >= 3, "frequency commands reached the clock: {f:?}");
    assert!(f.iter().all(|(_, _, ok)| *ok));
    // The clock took the rate before any frequency, and the last one sent
    // is what the world now runs at, until the stop reset.
    let cmds = rig.commands();
    assert_eq!(cmds.first().map(|c| c.1), Some(Cmd::Take));
    let last = f.last().expect("some").1;
    assert!(last.abs() > 0.0 && last.abs() <= 500.0, "{last}");
    assert!(rig.log_has("clock adjustment is on"));
}

#[test]
fn feeds_clock_failure_back_as_event() {
    let mut rig = Rig::new(0.050, 20.0);
    lock(&rig.world).fail_numbers.insert(2);
    rig.run(HOUR);
    // The engine only logs this after it got the failed ClockResult.
    assert!(rig.log_has("clock command failed: clock change rejected: injected failure"));
    assert!(rig.log_has("clock adjustment is off after a failed clock command"));
    let reports = lock(&rig.reports).clone();
    let failed_at = clock_cmds(&rig)
        .iter()
        .find(|c| !c.2)
        .map(|c| c.0)
        .expect("a failed command");
    let after = reports
        .iter()
        .find(|(t, _)| *t > failed_at)
        .expect("a report after the failure");
    assert_eq!(after.1.counters.clock_failures, 1);
    assert!(!after.1.adjustment_allowed);
    assert_eq!(after.1.adjustment_blocked, Blocked::ClockFailure);
}

#[test]
fn resets_frequency_on_shutdown() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.run(HOUR);
    let cmds = rig.commands();
    assert_eq!(cmds.iter().filter(|c| c.1 == Cmd::Reset).count(), 1);
    assert_eq!(cmds.last().map(|c| c.1), Some(Cmd::Reset), "reset is last");
    assert!(rig.log_has("clock rate handed back to the system"));
}

#[test]
fn saves_drift() {
    let mut rig = Rig::new(0.0, 20.0);
    rig.run(12 * HOUR);
    let saves = lock(&rig.drift).saves.clone();
    assert!(saves.len() >= 2, "{saves:?}");
    // Engine rate limit: ten minutes between saves, except the one at stop.
    let periodic = &saves[..saves.len() - 1];
    for pair in periodic.windows(2) {
        let gap = pair[1].0.saturating_duration_since(pair[0].0);
        assert!(gap >= Duration::from_secs(600), "gap {gap:?}");
    }
    let last = saves.last().expect("some").1;
    assert!((last - 20.0).abs() < 2.0, "learned drift {last}");
}

#[test]
fn writes_status_json() {
    let dir = Rig::temp_dir("status");
    let mut rig = Rig::new(0.050, 20.0);
    rig.status_writer = Some(Box::new(FileStatusWriter::new(&dir)));
    rig.run(30 * 60);
    let path = dir.join(status::FILE_NAME);
    let r = read_status(&path).expect("valid status file");
    assert!(!r.running, "the final write says stopped");
    assert_eq!(r.active_tier, Some(Tier::Pool));
    assert_eq!(r.sources_pool, 4);
    assert!(r.persistence);
    assert!(r.counters.queries > 0 && r.counters.samples > 0);
    assert!(!dir.join("status.json.tmp").exists(), "no temp file left");
    let text = std::fs::read_to_string(&path).expect("text");
    assert!(!text.contains("198.18."), "no address in the status file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Covers `read_status` and `format_status` only. The `status` subcommand
/// itself is wired in main.rs in 14c, which adds its own test.
#[test]
fn status_command_prints_status_json() {
    let dir = Rig::temp_dir("status-cmd");
    let mut rig = Rig::new(0.050, 20.0);
    rig.status_writer = Some(Box::new(FileStatusWriter::new(&dir)));
    rig.run(20 * 60);
    let r = read_status(&dir.join(status::FILE_NAME)).expect("valid");
    let text = format_status(&r);
    for needle in [
        "ntptimeclient-winrs",
        "(stopped)",
        "active tier:        pool",
        "adjustment:",
        "sources:            config 0, dhcp 0, pool 4",
        "queries",
    ] {
        assert!(text.contains(needle), "missing {needle} in\n{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn logs_join_state_at_start() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.join = JoinClass::Domain;
    rig.cfg.servers = vec!["ntp".to_owned()];
    rig.run(60);
    let lines = rig.lines();
    let pos = |needle: &str| lines.iter().position(|l| l.contains(needle));
    let join = pos("join state: domain joined").expect("join state logged");
    let config = pos("config: servers [ntp], dhcp off, pool pool.test").expect("config logged");
    let warning = pos("config warning: servers[0] is a single-label").expect("warning logged");
    let first_engine = pos("clock adjustment").expect("engine line");
    assert!(join < config && config < warning && warning < first_engine);
    assert!(rig.log_has("state_dir default"), "no path logged");
    assert!(rig.log_has("no saved drift: no drift file"));
}

#[test]
fn escapes_control_characters_in_logs() {
    let sink = MemorySink::new();
    let time = common::FakeTime::default();
    let log = LineLogger::new(Box::new(sink.clone()), Arc::new(time));
    let hostile =
        "a\nFAKE LINE\r\u{1b}[31mred\u{0}nul\u{2028}ls\u{2029}ps\u{202e}rlo\u{2066}iso\\x";
    log.log(Level::Warn, "test", hostile);
    let lines = sink.lines();
    assert_eq!(lines.len(), 1);
    let l = &lines[0];
    for raw in [
        '\n', '\r', '\u{1b}', '\u{0}', '\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}',
    ] {
        assert!(!l.contains(raw), "raw {raw:?} in {l:?}");
    }
    assert!(l.ends_with(
        "a\\nFAKE LINE\\r\\u{001B}[31mred\\u{0000}nul\\u{2028}ls\\u{2029}ps\\u{202E}rlo\\u{2066}iso\\\\x"
    ));
    assert_eq!(escape("plain text 123"), "plain text 123");
    // Hidden format characters (Cf): soft hyphen, Mongolian vowel separator,
    // deprecated shaping controls, annotation controls, tag characters.
    for c in [
        '\u{00AD}',
        '\u{180E}',
        '\u{206A}',
        '\u{206F}',
        '\u{FFF9}',
        '\u{FFFB}',
        '\u{E0000}',
        '\u{E0041}',
        '\u{E007F}',
    ] {
        let e = escape(&format!("a{c}b"));
        assert!(!e.contains(c), "{c:?} not escaped: {e:?}");
        assert_eq!(e, format!("a\\u{{{:04X}}}b", u32::from(c)));
    }

    // Through the host: a DHCP error text reaches the log escaped.
    let mut rig = Rig::new(0.0, 0.0);
    rig.cfg.dhcp = true;
    rig.patience = Duration::from_secs(5);
    *lock(&rig.dhcp.results) = vec![Err(DhcpReadError("bad\nINJECTED\u{1b}[2J".into()))];
    rig.run(60);
    assert!(rig.log_has("DHCP read failed: bad\\nINJECTED\\u{001B}[2J"));
    assert!(
        rig.lines()
            .iter()
            .all(|l| !l.contains('\n') && !l.contains('\u{1b}'))
    );
}

// ------------------------------------------------------------ adjustment level

#[test]
fn adjustment_starts_off_and_stays_off_while_w32time_runs() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.monitor_running = vec![(0.0, 1e9)];
    rig.run(2 * HOUR);
    // Not even the rate is taken or reset: w32time owns the clock.
    assert!(rig.commands().is_empty(), "{:?}", rig.commands());
    assert!(!lock(&rig.transport.queries).is_empty(), "still measuring");
    let last = lock(&rig.reports).last().cloned().expect("reports");
    assert_eq!(last.1.adjustment_blocked, Blocked::Starting, "final write");
    let mid = lock(&rig.reports)[10].1.clone();
    assert_eq!(mid.adjustment_blocked, Blocked::W32Time);
    assert!(rig.log_has("w32time runs or its state cannot be read"));
}

#[test]
fn no_clock_command_while_w32time_runs_mid_run() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.monitor_running = vec![(3600.0, 7200.0)];
    rig.run(3 * HOUR);
    let p = LEVEL_PERIOD.as_secs_f64();
    let cmds = clock_cmds(&rig);
    assert!(cmds.iter().any(|c| as_secs(c.0) < 3600.0));
    assert!(
        cmds.iter()
            .all(|c| !(as_secs(c.0) >= 3600.0 + p && as_secs(c.0) < 7200.0)),
        "{cmds:?}"
    );
    assert!(cmds.iter().any(|c| as_secs(c.0) >= 7200.0), "resumed after");
}

#[test]
fn level_is_re_sent_every_period() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.run(HOUR);
    let calls = lock(&rig.monitor_calls).clone();
    assert!(calls.len() >= 120, "{}", calls.len());
    for pair in calls.windows(2) {
        let gap = pair[1].saturating_duration_since(pair[0]);
        assert!(gap <= LEVEL_PERIOD, "gap {gap:?}");
    }
}

#[test]
fn clock_failure_stops_the_batch_and_rearms_after_the_delay() {
    // 0.5 s off: the engine steps at start, and the step batch also holds
    // a frequency. Command 1 is the frequency at enable, 2 is the step.
    let mut rig = Rig::new(0.5, 0.0);
    lock(&rig.world).fail_numbers.insert(2);
    rig.run(HOUR);
    let cmds = clock_cmds(&rig);
    let (failed_at, cmd, _) = cmds[1];
    assert!(matches!(cmd, Cmd::Step(_)), "{cmds:?}");
    assert!(!cmds[1].2);
    // Nothing else in that batch, nothing until the re-arm delay.
    let next = cmds[2].0;
    assert!(
        next.saturating_duration_since(failed_at) >= REARM_FIRST,
        "next command {} s after the failure",
        as_secs(next) - as_secs(failed_at)
    );
    assert!(rig.log_has("re-arming clock adjustment after a clock failure"));
    // After the re-arm the step is allowed again and taken.
    assert!(cmds[2..].iter().any(|c| matches!(c.1, Cmd::Step(_)) && c.2));
}

#[test]
fn failed_rate_take_keeps_adjustment_off_and_retries() {
    let mut rig = Rig::new(0.050, 20.0);
    lock(&rig.world).fail_take = 1;
    rig.run(HOUR);
    let cmds = rig.commands();
    let takes: Vec<f64> = cmds
        .iter()
        .filter(|c| c.1 == Cmd::Take)
        .map(|c| as_secs(c.0))
        .collect();
    assert_eq!(takes.len(), 2, "{cmds:?}");
    assert!(!cmds[0].2, "first take failed");
    let first_freq = cmds
        .iter()
        .find(|c| matches!(c.1, Cmd::Freq(_)))
        .expect("freq");
    assert!(
        as_secs(first_freq.0) >= REARM_FIRST.as_secs_f64(),
        "{cmds:?}"
    );
    assert!(rig.log_has("could not take the clock rate"));
}

#[test]
fn rearm_waits_while_w32time_runs() {
    let mut rig = Rig::new(0.5, 0.0);
    lock(&rig.world).fail_numbers.insert(2);
    // w32time starts soon after the failure and runs for an hour.
    rig.monitor_running = vec![(30.0, 3630.0)];
    rig.run(2 * HOUR);
    let cmds = clock_cmds(&rig);
    let failed = cmds.iter().position(|c| !c.2).expect("failure");
    let next = cmds.get(failed + 1).expect("commands resume");
    assert!(as_secs(next.0) >= 3630.0, "{cmds:?}");
}

// ------------------------------------------------------------ queries

#[test]
fn one_query_in_flight_per_source() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.threads = true;
    rig.patience = Duration::from_secs(5);
    Arc::get_mut(&mut rig.transport)
        .expect("not shared yet")
        .real_delay = Duration::from_millis(2);
    rig.run(HOUR);
    assert!(lock(&rig.transport.queries).len() > 20);
    assert_eq!(
        rig.transport.max_active_per_source.load(Ordering::SeqCst),
        1
    );
}

#[test]
fn failed_queries_reach_the_engine() {
    let mut rig = Rig::new(0.0, 0.0);
    for n in 1..=4 {
        lock(&rig.transport.replies).insert(
            bench(n),
            common::Reply::Fail(QueryFailure::KissOfDeath(ntpc_core::KodCode::Deny)),
        );
    }
    rig.run(HOUR);
    assert!(rig.log_has("sent kiss-of-death DENY"));
    let r = lock(&rig.reports).last().cloned().expect("report").1;
    assert!(r.counters.kiss_of_death >= 4);
    assert_eq!(r.counters.samples, 0);
}

#[test]
fn shutdown_resets_once_and_returns_while_a_worker_is_blocked() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.threads = true;
    rig.patience = Duration::from_millis(20);
    let (keep, rx) = Rig::gate();
    *lock(&rig.transport.block) = Some(rx);
    rig.run(10 * 60);
    assert_eq!(
        rig.commands().iter().filter(|c| c.1 == Cmd::Reset).count(),
        1
    );
    assert!(rig.log_has("did not return in 15 s. Counted as a timeout"));
    drop(keep);
}

// ------------------------------------------------------------ names

#[test]
fn blocking_name_lookup_does_not_stall_the_loop() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.threads = true;
    rig.patience = Duration::from_millis(20);
    let (keep, rx) = Rig::gate();
    *lock(&rig.lookup.block_first) = 1;
    *lock(&rig.lookup.gate) = Some(rx);
    rig.run(HOUR);
    // The loop kept checking w32time while the first lookup hung.
    let calls = lock(&rig.monitor_calls).clone();
    assert!(calls.iter().filter(|t| as_secs(**t) < 300.0).count() >= 10);
    assert!(rig.log_has("a name lookup did not return. Starting a fresh resolver"));
    // The fresh resolver found the pool and queries ran.
    assert!(!lock(&rig.transport.queries).is_empty());
    drop(keep);
}

#[test]
fn pool_lookup_failure_is_logged_and_retried() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.cfg.pool = "missing.test".to_owned();
    rig.run(HOUR);
    assert!(rig.log_has("lookup of missing.test failed"));
    assert!(rig.lookup.calls.load(Ordering::SeqCst) >= 5, "retried");
}

#[test]
fn network_change_forces_a_lookup() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.network_at = vec![1800.0];
    rig.run(HOUR);
    // One at start, one after the change. The hourly timer has not fired.
    assert_eq!(rig.lookup.calls.load(Ordering::SeqCst), 2);
}

// ------------------------------------------------------------ DHCP

fn dhcp_rig() -> Rig {
    let mut rig = Rig::new(0.0, 0.0);
    rig.cfg.dhcp = true;
    rig.patience = Duration::from_secs(5);
    rig
}

fn read_times(rig: &Rig) -> Vec<f64> {
    lock(&rig.dhcp_reads).iter().map(|r| as_secs(r.0)).collect()
}

#[test]
fn dhcp_reads_at_start_then_settles_after_a_signal() {
    let mut rig = dhcp_rig();
    rig.network_at = vec![1000.0];
    rig.run(HOUR);
    let t = read_times(&rig);
    assert_eq!(t.len(), 2, "{t:?}");
    assert!(t[0] < 1.0);
    assert!(t[1] >= 1010.0 && t[1] < 1011.0, "{t:?}");
}

#[test]
fn dhcp_minimum_interval_between_reads() {
    let mut rig = dhcp_rig();
    rig.network_at = vec![5.0];
    rig.run(HOUR);
    let t = read_times(&rig);
    assert_eq!(t.len(), 2, "{t:?}");
    assert!(t[1] >= DHCP_MIN_INTERVAL.as_secs_f64(), "{t:?}");
}

#[test]
fn dhcp_signal_storm_gives_one_read() {
    let mut rig = dhcp_rig();
    rig.network_at = (0..100).map(|i| 1000.0 + f64::from(i) * 0.05).collect();
    rig.run(3 * HOUR);
    let t = read_times(&rig);
    assert_eq!(t.len(), 2, "boot read plus one: {t:?}");
}

#[test]
fn dhcp_negative_cache_and_servers_reach_the_tier() {
    let mut rig = dhcp_rig();
    rig.network_at = vec![1000.0];
    *lock(&rig.dhcp.results) = vec![
        Ok(DhcpRead {
            servers: vec![Ipv4Addr::new(198, 18, 1, 1)],
            adapters: vec![AdapterKey("a".into()), AdapterKey("b".into())],
            without_option: vec![AdapterKey("b".into())],
        }),
        Ok(DhcpRead::default()),
    ];
    rig.run(HOUR);
    let reads = lock(&rig.dhcp_reads).clone();
    assert!(reads[0].1.is_empty(), "nothing skipped at boot");
    assert_eq!(reads[1].1, BTreeSet::from([AdapterKey("b".into())]));
    assert!(rig.log_has("DHCP offers NTP servers [198.18.1.1]"));
    let reports = lock(&rig.reports).clone();
    assert!(reports.iter().any(|(_, r)| r.sources_dhcp == 1));
}

#[test]
fn blocked_dhcp_read_never_stalls_the_loop() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.cfg.dhcp = true;
    rig.threads = true;
    rig.patience = Duration::from_millis(5);
    let (keep, rx) = Rig::gate();
    *lock(&rig.dhcp.gate) = Some(rx);
    rig.run(2 * HOUR);
    assert_eq!(read_times(&rig).len(), 1, "one reader, still blocked");
    let q = lock(&rig.transport.queries).clone();
    assert!(
        q.iter().any(|(t, _)| as_secs(*t) > 3600.0),
        "queries went on"
    );
    assert!(!freqs(&rig).is_empty(), "clock disciplined");
    drop(keep);
}

// ------------------------------------------------------------ persistence

#[test]
fn refused_state_dir_keeps_timekeeping_without_files() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.state = SecureOutcome::Refused {
        reason: "untrusted owner",
    };
    rig.run(2 * HOUR);
    assert_eq!(lock(&rig.drift).loads, 0);
    assert!(lock(&rig.drift).saves.is_empty(), "no drift saved");
    assert!(lock(&rig.reports).is_empty(), "no status written");
    assert!(!freqs(&rig).is_empty(), "the clock is still disciplined");
    assert!(rig.log_has("could not be secured (untrusted owner). Persistence is off"));
}

#[test]
fn status_is_written_every_30_seconds() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.run(HOUR);
    let times: Vec<Mono> = lock(&rig.reports).iter().map(|r| r.0).collect();
    assert!(times.len() >= 120);
    for pair in times[..times.len() - 1].windows(2) {
        let gap = pair[1].saturating_duration_since(pair[0]);
        assert_eq!(gap, Duration::from_secs(30));
    }
}

#[test]
fn status_writer_is_atomic_and_reader_refuses_tampering() {
    let dir = Rig::temp_dir("atomic");
    let w = FileStatusWriter::new(&dir);
    let mut rig = Rig::new(0.0, 0.0);
    rig.run(60);
    let report = lock(&rig.reports).last().cloned().expect("one").1;
    // A temp file left by a crash does not block the write.
    std::fs::write(dir.join("status.json.tmp"), b"half").expect("plant");
    w.write(&report).expect("first");
    w.write(&report).expect("replace");
    assert!(!dir.join("status.json.tmp").exists());
    assert_eq!(read_status(&w.path()).expect("reads"), report);

    let p = w.path();
    std::fs::write(&p, " ".repeat(5000)).expect("big");
    assert_eq!(read_status(&p), Err(StatusError::TooLarge));
    let v2 = status::to_json(&report).replacen("\"version\": 1", "\"version\": 2", 1);
    std::fs::write(&p, v2).expect("v2");
    assert_eq!(read_status(&p), Err(StatusError::Version(2)));
    std::fs::write(&p, b"\xff\xfe garbage").expect("garbage");
    assert_eq!(read_status(&p), Err(StatusError::NotUtf8));
    std::fs::write(&p, "{\"format\": 1}").expect("bad");
    assert!(matches!(read_status(&p), Err(StatusError::Invalid(_))));
    // A directory at the temp path fails the write, never panics.
    std::fs::create_dir(dir.join("status.json.tmp")).expect("dir");
    assert!(w.write(&report).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------ power

#[test]
fn resume_allows_one_step() {
    let mut rig = Rig::new(0.0, 0.0);
    // Two hours in, the machine wakes 2 s ahead.
    rig.power_at = vec![(7200.0, 2.0)];
    rig.run(4 * HOUR);
    let steps: Vec<(f64, f64)> = rig
        .commands()
        .iter()
        .filter_map(|(t, c, ok)| match c {
            Cmd::Step(s) if *ok => Some((as_secs(*t), *s)),
            _ => None,
        })
        .collect();
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert!(steps[0].0 >= 7200.0);
    assert!((steps[0].1 + 2.0).abs() < 0.01, "{steps:?}");
    assert!(rig.log_has("the machine resumed from sleep"));
    assert!(lock(&rig.world).err.abs() < 0.01);
}

// ------------------------------------------------------------ logging

#[test]
fn log_rate_limit_suppresses_and_summarises() {
    let sink = MemorySink::new();
    let time = common::FakeTime::default();
    let log = LineLogger::new(Box::new(sink.clone()), Arc::new(time.clone()));
    for i in 0..100 {
        log.log(Level::Warn, "flood", &format!("hostile {i}"));
    }
    log.log(Level::Info, "other", "unrelated");
    assert_eq!(sink.lines().len(), RATE_MAX as usize + 1);
    assert_eq!(log.suppressed(), 100 - u64::from(RATE_MAX));
    time.set(Mono::from_nanos(61 * SEC));
    log.flush();
    let lines = sink.lines();
    assert!(
        lines
            .last()
            .expect("line")
            .contains("suppressed 90 similar messages of kind flood")
    );
    log.log(Level::Warn, "flood", "again");
    assert!(sink.lines().last().expect("line").ends_with("again"));
}

#[test]
fn long_lines_are_capped() {
    let sink = MemorySink::new();
    let log = LineLogger::new(
        Box::new(sink.clone()),
        Arc::new(common::FakeTime::default()),
    );
    log.log(Level::Info, "long", &"x".repeat(10_000));
    let l = &sink.lines()[0];
    assert!(l.len() < 600, "{}", l.len());
    assert!(l.ends_with(" [truncated]"));
}

// ------------------------------------------------------------ end to end

fn e2e(seed_err: f64) -> (Vec<(Mono, Cmd, bool)>, f64) {
    let mut rig = Rig::new(seed_err, 20.0);
    rig.run(12 * HOUR);
    let err = lock(&rig.world).err;
    (rig.commands(), err)
}

#[test]
fn end_to_end_converges_and_repeats_exactly() {
    let (cmds, err) = e2e(0.050);
    assert!(err.abs() < 0.005, "final error {err}");
    assert!(cmds.iter().all(|c| !matches!(c.1, Cmd::Step(_))), "no step");
    assert!(cmds.iter().all(|c| c.2), "no failure");
    let (again, err2) = e2e(0.050);
    assert_eq!(cmds, again, "deterministic");
    assert!((err - err2).abs() < f64::EPSILON);
}

#[test]
fn end_to_end_with_config_and_pool_tiers() {
    let mut rig = Rig::new(0.030, -15.0);
    rig.cfg.servers = vec!["198.18.2.1".to_owned(), "198.18.2.2".to_owned()];
    rig.run(12 * HOUR);
    let last = lock(&rig.reports).last().cloned().expect("report").1;
    assert_eq!(last.active_tier, Some(Tier::Config));
    assert_eq!(last.sources_config, 2);
    assert!(lock(&rig.world).err.abs() < 0.005);
    let _ = POOL;
}

// ------------------------------------------------------------ fix round 1

fn times_of(rig: &Rig, want: Cmd) -> Vec<f64> {
    rig.commands()
        .iter()
        .filter(|c| c.1 == want)
        .map(|c| as_secs(c.0))
        .collect()
}

#[test]
fn w32time_start_hands_the_rate_back_once_and_stop_leaves_it() {
    // R98. w32time starts at 3600 s and runs to the end.
    let mut rig = Rig::new(0.050, 20.0);
    rig.monitor_running = vec![(3600.0, 1e9)];
    rig.run(3 * HOUR);
    let resets = times_of(&rig, Cmd::Reset);
    assert_eq!(resets.len(), 1, "{resets:?}");
    assert!(resets[0] >= 3600.0 && resets[0] <= 3630.0, "{resets:?}");
    assert_eq!(times_of(&rig, Cmd::Take).len(), 1);
    assert!(rig.log_has("w32time runs: clock rate handed back to the system"));
    // Nothing touches the clock after the hand-back.
    assert!(rig.commands().iter().all(|c| as_secs(c.0) <= resets[0]));
}

#[test]
fn w32time_stopping_again_retakes_the_rate() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.monitor_running = vec![(3600.0, 7200.0)];
    rig.run(3 * HOUR);
    let takes = times_of(&rig, Cmd::Take);
    let resets = times_of(&rig, Cmd::Reset);
    assert_eq!(takes.len(), 2, "{takes:?}");
    assert!(takes[1] >= 7200.0 && takes[1] <= 7230.0, "{takes:?}");
    assert_eq!(resets.len(), 2, "hand-back plus stop: {resets:?}");
    // The re-take comes before the first command after w32time stops.
    let first_after = clock_cmds(&rig)
        .into_iter()
        .find(|c| as_secs(c.0) >= 7200.0)
        .expect("commands again");
    assert!(as_secs(first_after.0) >= takes[1]);
}

#[test]
fn flapping_w32time_gives_one_reset_per_start() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.monitor_running = vec![(1000.0, 1100.0), (2000.0, 2100.0), (3000.0, 3100.0)];
    rig.run(HOUR);
    let resets = times_of(&rig, Cmd::Reset);
    let in_window = |a: f64| {
        resets
            .iter()
            .filter(|t| **t >= a && **t <= a + 30.0)
            .count()
    };
    assert_eq!(in_window(1000.0), 1, "{resets:?}");
    assert_eq!(in_window(2000.0), 1, "{resets:?}");
    assert_eq!(in_window(3000.0), 1, "{resets:?}");
    assert_eq!(resets.len(), 4, "three hand-backs and the stop: {resets:?}");
    assert_eq!(times_of(&rig, Cmd::Take).len(), 4);
}

#[test]
fn clock_failure_with_moving_time_stays_in_its_batch() {
    // I3: real time moves between the clock action and its result. With
    // time moving on every read the failed step's result must still reach
    // the engine before anything else, so no command follows it until the
    // re-arm, and after the re-arm the step is allowed again.
    let mut rig = Rig::new(0.5, 0.0);
    rig.time.advance_per_read(1);
    lock(&rig.world).fail_numbers.insert(2);
    rig.run(HOUR);
    let cmds = clock_cmds(&rig);
    assert!(matches!(cmds[1].1, Cmd::Step(_)) && !cmds[1].2, "{cmds:?}");
    let gap = cmds[2].0.saturating_duration_since(cmds[1].0);
    assert!(gap >= REARM_FIRST, "next command after {gap:?}");
    assert!(cmds[2..].iter().any(|c| matches!(c.1, Cmd::Step(_)) && c.2));
}

#[test]
fn end_to_end_with_moving_time_converges() {
    let mut rig = Rig::new(0.050, 20.0);
    rig.time.advance_per_read(1);
    rig.run(12 * HOUR);
    assert!(lock(&rig.world).err.abs() < 0.005);
    assert!(clock_cmds(&rig).iter().all(|c| c.2));
}

#[test]
fn a_panic_in_the_loop_still_resets_the_rate() {
    // I4.
    let mut rig = Rig::new(0.050, 20.0);
    rig.monitor_panic_at = Some(600.0);
    let r = rig.try_run(HOUR);
    let Err(ntpc_service::host::HostError::Panicked(msg)) = r else {
        panic!("expected a panic error, got {r:?}");
    };
    assert!(msg.contains("injected monitor panic"), "{msg}");
    assert_eq!(times_of(&rig, Cmd::Reset).len(), 1);
    assert!(rig.log_has("the host loop panicked: injected monitor panic"));
    let last = lock(&rig.reports).last().cloned().expect("final status").1;
    assert!(!last.running);
}

#[test]
fn panicking_dhcp_reads_are_reported_and_the_reader_stops() {
    let mut rig = dhcp_rig();
    rig.dhcp.panics.store(true, Ordering::SeqCst);
    rig.network_at = vec![700.0, 1400.0, 2100.0, 2800.0];
    rig.run(HOUR);
    assert!(rig.log_has("DHCP read failed: the DHCP read panicked (1 of 3)"));
    assert!(rig.log_has("DHCP read failed: the DHCP read panicked (3 of 3)"));
    assert!(rig.log_has("the DHCP reader stopped"));
    assert_eq!(
        read_times(&rig).len(),
        3,
        "no read after the reader stopped"
    );
    assert!(!freqs(&rig).is_empty(), "timekeeping goes on");
}

#[test]
fn a_panicking_resolver_is_replaced() {
    let mut rig = Rig::new(0.0, 0.0);
    *lock(&rig.lookup.panic_first) = 1;
    rig.run(HOUR);
    assert!(rig.log_has("the resolver panicked. Starting a fresh resolver"));
    // The fresh resolver found the pool within the 15 min offline cap.
    let q = lock(&rig.transport.queries).clone();
    let first = q.first().expect("queries after the panic").0;
    assert!(as_secs(first) <= 15.0 * 60.0 + 31.0, "{}", as_secs(first));
}

#[test]
fn stuck_lookups_are_capped_at_three() {
    let mut rig = Rig::new(0.0, 0.0);
    rig.threads = true;
    rig.patience = Duration::from_millis(20);
    rig.lookup.hang.store(true, Ordering::SeqCst);
    rig.run(HOUR);
    assert_eq!(rig.lookup.calls.load(Ordering::SeqCst), 3);
    assert!(rig.log_has("3 name lookups are stuck. No new lookup starts"));
    // Let the stuck threads end.
    rig.lookup.hang.store(false, Ordering::SeqCst);
}
