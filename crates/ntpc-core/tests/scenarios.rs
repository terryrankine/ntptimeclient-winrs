//! Whole-engine scenarios in the simulated world.
//!
//! Run with `cargo test -p ntpc-core --features sim`.
//!
//! Every error bound below is derived, not tuned. The shared parts are:
//!
//! - Reading noise. Each leg of a path queues for a time drawn uniformly
//!   from `[0, jitter]`. A reading's offset error is half the difference of
//!   the two legs, so it is at most `jitter / 2`. With the default 2 ms
//!   jitter that is 1 ms.
//! - Loop gain on noise. `discipline::tests::loop_does_not_oscillate_after_settling`
//!   pins the settled error of the loop under 2 ms for readings off by up to
//!   0.5 ms, a factor of 4. The loop is linear, so readings off by up to
//!   1 ms give at most 4 ms. That is [`SETTLED`].
//! - Frequency transient. The loop is a type 2 loop with natural frequency
//!   `1 / 4096 s` and damping 1. After a frequency error `df` appears, the
//!   offset is `df * t * exp(-t / 4096)`. It peaks at `df * 4096 / e`, about
//!   `df * 1507 s`. After 12 hours, `t / 4096 = 10.5`, so it is below
//!   `3e-4 * df * 4096`: 25 us for 20 ppm. A 12 hour settle removes it.

use ntpc_core::engine::{DisableReason, Engine, EngineConfig, LogEvent};
use ntpc_core::sim::{Fault, ServerSpec, SimEvent, SimReport, SimWorld};
use ntpc_core::{Offset, Ppm, Tier};

const HOUR: u64 = 3600;

/// Settled error bound for healthy exact servers with the default jitter.
/// See the module docs.
const SETTLED: f64 = 0.004;

/// Peak offset per ppm of frequency error, `4096 / e` seconds.
const TRANSIENT_PER_PPM: f64 = 4096.0 / std::f64::consts::E * 1e-6;

/// The clock rate the simulated machine needs to keep true time.
const DRIFT: f64 = 20.0;

/// An exact server on a 30 ms path with 2 ms queuing per leg.
fn healthy(tier: Tier) -> ServerSpec {
    ServerSpec {
        tier,
        ..ServerSpec::default()
    }
}

/// A world with no frequency quantisation, a 20 ppm clock and `error`
/// seconds of starting error.
fn world(seed: u64, error: f64) -> SimWorld {
    let mut w = SimWorld::new(seed, 0.0);
    w.set_true_drift(Ppm::new(DRIFT));
    w.set_clock_error(error);
    w
}

fn add_pool(w: &mut SimWorld, n: usize) {
    for i in 0..n {
        w.add_server(&format!("pool-{i}"), healthy(Tier::Pool));
    }
}

fn engine(saved_drift: Option<f64>) -> Engine {
    Engine::new(EngineConfig::default(), saved_drift.map(Ppm::new))
}

/// Asserts `value <= bound` and prints both, so `--nocapture` shows the
/// margin of every bound.
fn within(what: &str, value: f64, bound: f64) {
    eprintln!("{what}: {value:.9} <= {bound:.9}");
    assert!(value <= bound, "{what}: {value} > {bound}");
}

/// Asserts that the run took no step, showing any that it took.
fn no_steps(r: &SimReport) {
    assert_eq!(r.steps.len(), 0, "steps taken: {:?}", r.steps);
}

fn has_log(r: &SimReport, want: &LogEvent) -> bool {
    r.logs.iter().any(|(_, l)| l == want)
}

fn queries(r: &SimReport, label: &str) -> u32 {
    r.queries.get(label).copied().unwrap_or(0)
}

#[test]
fn converges_with_20ppm_drift() {
    for seed in [1, 2, 3] {
        // 50 ms is under the 128 ms step threshold, so the start slews.
        let mut w = world(seed, 0.050);
        add_pool(&mut w, 4);
        let mut e = engine(None);
        let first = w.run(&mut e, 12 * HOUR);
        // Start error plus the 20 ppm transient plus noise. The two may add
        // if the noise points the same way, so the bound is their sum.
        let bound = 0.050 + DRIFT * TRANSIENT_PER_PPM + SETTLED;
        within("first.max_abs_error", first.max_abs_error, bound);
        let settled = w.run(&mut e, 12 * HOUR);
        within("settled.max_abs_error", settled.max_abs_error, SETTLED);
        // discipline::tests::learns_drift_from_stable_samples pins 2 ppm.
        let learned = e.status().drift.value();
        within("|learned - DRIFT|", (learned - DRIFT).abs(), 2.0);
        no_steps(&first);
        no_steps(&settled);
        assert_eq!(settled.commands_while_disabled, 0);
    }
}

#[test]
fn converges_with_quantised_frequency_steps() {
    // 6.4 ppm is 100 ns per 15.625 ms clock interrupt, the coarsest step
    // `SetSystemTimeAdjustment` gives on a default Windows tick. Author's
    // guess from training data, unverified. 20 ppm then sits between the
    // levels 19.2 and 25.6, so the loop must dither.
    let g = 6.4;
    let mut w = SimWorld::new(7, g);
    w.set_true_drift(Ppm::new(DRIFT));
    add_pool(&mut w, 4);
    let mut e = engine(None);
    let _ = w.run(&mut e, 12 * HOUR);
    let settled = w.run(&mut e, 24 * HOUR);
    // The applied rate only moves when the command crosses a rounding
    // midpoint. The phase term is `x / 2048 s`, so the offset can grow to
    // `(g / 2) * 2048 s` before the rate flips. After it flips, the wrong
    // level can be held for one longest poll, `g * 1024 s`. Noise adds
    // SETTLED. Total about 6.6 + 6.6 + 4 = 17.1 ms.
    let bound = g * 1e-6 * (2048.0 / 2.0 + 1024.0) + SETTLED;
    within("settled.max_abs_error", settled.max_abs_error, bound);
    no_steps(&settled);
    // Every applied rate is a whole number of quanta.
    let q = settled.max_abs_frequency / g;
    within("|q - q.round()|", (q - q.round()).abs(), 1e-9);
}

#[test]
fn survives_one_falseticker_among_four() {
    let mut w = world(11, 0.0);
    add_pool(&mut w, 3);
    w.add_server(
        "liar",
        ServerSpec {
            fault: Fault::Falseticker(Offset::from_secs(2.0)),
            ..healthy(Tier::Pool)
        },
    );
    // The saved drift is right, so no transient: only noise moves the
    // clock. Following the liar for one 64 s poll at the 500 ppm cap would
    // move it 32 ms, eight times the bound.
    let mut e = engine(Some(DRIFT));
    let r = w.run(&mut e, 24 * HOUR);
    within("r.max_abs_error", r.max_abs_error, SETTLED);
    // A 2 s reading at start would be a step if it were followed.
    no_steps(&r);
    assert!(queries(&r, "liar") > 0, "the liar is asked, not trusted");
}

#[test]
fn kod_server_is_not_followed() {
    let mut w = world(13, 0.0);
    add_pool(&mut w, 3);
    // A KoD reply carries no usable time. The offsets are set far out so
    // any use of them would show.
    w.add_server(
        "deny",
        ServerSpec {
            offset: 30.0,
            fault: Fault::KodDeny,
            ..healthy(Tier::Pool)
        },
    );
    w.add_server(
        "rate",
        ServerSpec {
            offset: -30.0,
            fault: Fault::KodRate,
            ..healthy(Tier::Pool)
        },
    );
    let mut e = engine(Some(DRIFT));
    let r = w.run(&mut e, 24 * HOUR);
    within("r.max_abs_error", r.max_abs_error, SETTLED);
    no_steps(&r);
    // DENY silences the source for one hour, so at most one query per hour
    // plus the first.
    let n = queries(&r, "deny");
    assert!(n <= 25, "deny asked {n}");
    // RATE doubles the source's own last interval each time, starting from
    // the 64 s poll. Gap i is at least 64 * 2^i s. Ten gaps sum to
    // 128 * (2^10 - 1) s, more than a day, so at most nine gaps fit and at
    // most ten queries.
    let n = queries(&r, "rate");
    assert!(n <= 10, "rate asked {n}");
    assert!(queries(&r, "pool-0") > 30, "healthy sources keep polling");
    assert!(
        r.logs
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::KissOfDeath { .. }))
    );
}

#[test]
fn no_network_at_boot_free_runs_on_saved_drift() {
    // Saved 18 ppm, true 20 ppm. Free running, the error moves by
    // -2 ppm * t, so after 2 hours it is 0.010 - 0.0144 = -0.0044 s. No
    // quantisation, so the free run is exact.
    let mut w = world(17, 0.010);
    add_pool(&mut w, 4);
    w.schedule(0, SimEvent::NetworkDown);
    w.schedule(2 * HOUR, SimEvent::NetworkUp);
    let mut e = engine(Some(18.0));
    let down = w.run(&mut e, 2 * HOUR);
    let want = 0.010 - 2e-6 * 7200.0;
    within(
        "|down.final_error - want|",
        (down.final_error - want).abs(),
        1e-9,
    );
    // The error is linear, so its largest size is at an end: 10 ms.
    within("down.max_abs_error", down.max_abs_error, 0.010 + 1e-9);
    no_steps(&down);
    assert!(queries(&down, "pool-0") > 0, "it keeps trying");
    assert_eq!(e.status().last_offset, None);
    // Network back: a 4.4 ms offset is slewed, not stepped. The 2 ppm
    // transient adds at most 3 ms on top of the 4.4 ms and the noise.
    let up = w.run(&mut e, 12 * HOUR);
    no_steps(&up);
    within(
        "up.max_abs_error",
        up.max_abs_error,
        0.0044 + 2.0 * TRANSIENT_PER_PPM + SETTLED,
    );
    let settled = w.run(&mut e, 12 * HOUR);
    within("settled.max_abs_error", settled.max_abs_error, SETTLED);
}

#[test]
fn resume_with_large_gap_steps_once() {
    let mut w = world(19, 0.0);
    add_pool(&mut w, 4);
    let mut e = engine(Some(DRIFT));
    let before = w.run(&mut e, 6 * HOUR);
    no_steps(&before);
    // A long sleep: the clock comes back 2 s ahead of true time.
    w.schedule(6 * HOUR, SimEvent::Resume(Offset::from_secs(2.0)));
    let after = w.run(&mut e, 6 * HOUR);
    assert_eq!(after.steps.len(), 1, "{:?}", after.steps);
    let (at, step) = after.steps[0];
    // The step undoes the 2 s, give or take one reading's noise.
    within(
        "(step.as_secs() + 2.0).abs()",
        (step.as_secs() + 2.0).abs(),
        0.001,
    );
    // The resume rechecks every tier at once, so the step follows the first
    // reply, well inside one 64 s poll.
    let since = at.as_nanos() / 1_000_000_000 - 6 * HOUR;
    assert!(since < 64, "step {since} s after resume");
    // After the step the clock is within one reading of true. The 2 s is
    // gone, so the max error of the segment is the 2 s at resume.
    within("after.final_error.abs()", after.final_error.abs(), SETTLED);
    // A short sleep: 50 ms back is under the threshold and is slewed.
    w.schedule(12 * HOUR, SimEvent::Resume(Offset::from_secs(0.050)));
    let short = w.run(&mut e, 6 * HOUR);
    no_steps(&short);
    within("short.max_abs_error", short.max_abs_error, 0.050 + SETTLED);
}

#[test]
fn first_boot_with_clock_one_hour_off_steps() {
    // One hour is above the 1000 s panic threshold. The spec allows such a
    // step only when config allows it, so this machine's config does.
    let cfg = EngineConfig {
        discipline: ntpc_core::discipline::DisciplineConfig {
            allow_panic_step: true,
            ..Default::default()
        },
        ..EngineConfig::default()
    };
    let mut w = world(23, -3600.0);
    add_pool(&mut w, 4);
    let mut e = Engine::new(cfg, None);
    let first = w.run(&mut e, 12 * HOUR);
    assert_eq!(first.steps.len(), 1, "{:?}", first.steps);
    within(
        "|first.steps[0].1.as_secs() - 3600.0|",
        (first.steps[0].1.as_secs() - 3600.0).abs(),
        0.001,
    );
    let settled = w.run(&mut e, 12 * HOUR);
    within("settled.max_abs_error", settled.max_abs_error, SETTLED);
    no_steps(&settled);

    // Default config: the step is refused and the clock is held at the
    // learned rate (ruling R20 and R25). With no saved drift that is
    // nominal, so the error only moves by the 20 ppm drift: 0.432 s in 6 h.
    let mut w = world(23, -3600.0);
    add_pool(&mut w, 4);
    let mut e = engine(None);
    let r = w.run(&mut e, 6 * HOUR);
    no_steps(&r);
    let moved = r.final_error + 3600.0;
    within(
        "|moved + DRIFT * 1e-6 * 6.0 * 3600.0|",
        (moved + DRIFT * 1e-6 * 6.0 * 3600.0).abs(),
        1e-6,
    );
    assert!(
        r.logs
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::StepRefused { .. }))
    );
}

#[test]
fn never_steps_during_normal_operation() {
    let mut w = world(29, 0.0);
    add_pool(&mut w, 2);
    // A lossy path, a slow asymmetric path and a dead server.
    w.add_server(
        "lossy",
        ServerSpec {
            loss_rate: 0.2,
            ..healthy(Tier::Pool)
        },
    );
    w.add_server(
        "far",
        ServerSpec {
            delay: 0.120,
            asymmetry: 0.002,
            jitter: 0.004,
            ..healthy(Tier::Pool)
        },
    );
    w.add_server(
        "dead",
        ServerSpec {
            fault: Fault::Unreachable,
            ..healthy(Tier::Pool)
        },
    );
    // A busy machine warms up on day three and runs 5 ppm slower.
    w.schedule(3 * 24 * HOUR, SimEvent::SetDrift(Ppm::new(DRIFT + 5.0)));
    let mut e = engine(Some(DRIFT));
    let r = w.run(&mut e, 7 * 24 * HOUR);
    no_steps(&r);
    // The 5 ppm change gives a 7.5 ms transient. At a 1024 s poll the loop
    // first sees it one poll late, 5 ppm * 1024 s = 5.1 ms more. "far"
    // has 4 ms legs, so its readings are off by up to 2 ms, plus 1 ms of
    // asymmetry bias. Noise at that size gives 4 * 3 ms = 12 ms. Sum about
    // 24.7 ms. A step needs 128 ms.
    let bound = 5.0 * TRANSIENT_PER_PPM + 5.0e-6 * 1024.0 + 4.0 * 0.003;
    within("r.max_abs_error", r.max_abs_error, bound);
    assert!(queries(&r, "dead") > 0);
}

#[test]
fn dhcp_lease_change_switches_sources_without_clock_jump() {
    let mut w = world(31, 0.0);
    w.add_server("dhcp-a", healthy(Tier::Dhcp));
    w.add_server("dhcp-b", healthy(Tier::Dhcp));
    add_pool(&mut w, 4);
    let mut e = engine(Some(DRIFT));
    let first = w.run(&mut e, 6 * HOUR);
    assert_eq!(e.status().active_tier, Some(Tier::Dhcp));
    no_steps(&first);
    // The new network's servers read 3 ms ahead of true time. They are
    // added to the network now and listed by the lease change.
    let ahead = ServerSpec {
        offset: 0.003,
        ..healthy(Tier::Dhcp)
    };
    w.add_server("dhcp-c", ahead);
    w.add_server("dhcp-d", ahead);
    let list = ["dhcp-c", "dhcp-d", "pool-0", "pool-1", "pool-2", "pool-3"];
    w.schedule(
        6 * HOUR,
        SimEvent::SourcesChanged(list.iter().map(ToString::to_string).collect()),
    );
    let second = w.run(&mut e, 12 * HOUR);
    no_steps(&second);
    assert_eq!(e.status().active_tier, Some(Tier::Dhcp));
    // No tier fell away during the change.
    assert!(
        !second
            .logs
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::TierChanged { .. }))
    );
    // The clock slews 3 ms toward the new servers. That is a phase step of
    // 3 ms with no overshoot (damping 1), plus noise.
    within(
        "second.max_abs_error",
        second.max_abs_error,
        0.003 + SETTLED,
    );
    assert_eq!(queries(&second, "dhcp-a"), 0, "old lease forgotten");
    assert!(queries(&second, "dhcp-c") > 0);
    // Truth is 3 ms behind the new servers, so the error ends near +3 ms.
    within(
        "(second.final_error - 0.003).abs()",
        (second.final_error - 0.003).abs(),
        SETTLED,
    );
}

#[test]
fn w32time_restart_stops_adjustment() {
    let mut w = world(37, 0.0);
    add_pool(&mut w, 4);
    let mut e = engine(Some(DRIFT));
    let _ = w.run(&mut e, 6 * HOUR);
    w.schedule(6 * HOUR, SimEvent::W32TimeStarted);
    let r = w.run(&mut e, 2 * HOUR);
    assert_eq!(r.commands_while_disabled, 0);
    no_steps(&r);
    let off = LogEvent::AdjustmentDisabled {
        reason: DisableReason::Host,
    };
    assert!(has_log(&r, &off));
    assert!(!e.status().adjustment_allowed);
    // It keeps measuring.
    assert!(queries(&r, "pool-0") > 0);
    assert!(e.status().last_good_age.is_some_and(|a| a.as_secs() < 1100));
}

/// Added beyond the brief: `W32TimeStarted` followed by `W32TimeStopped`.
/// The re-enable is neither a start nor a resume, so no step is allowed.
#[test]
fn adjustment_disabled_by_w32time_then_reenabled_does_not_jump() {
    let mut w = world(41, 0.0);
    add_pool(&mut w, 4);
    let mut e = engine(Some(DRIFT));
    let _ = w.run(&mut e, 6 * HOUR);
    // The sim's w32time runs the clock at nominal for 4 hours. At 20 ppm
    // that is 288 ms behind, above the step threshold.
    w.schedule(6 * HOUR, SimEvent::W32TimeStarted);
    // One second after the segment ends, so the re-enable falls in `back`.
    // An event at a run's last instant belongs to that run.
    w.schedule(10 * HOUR + 1, SimEvent::W32TimeStopped);
    let off = w.run(&mut e, 4 * HOUR);
    within(
        "|off.final_error + 0.288|",
        (off.final_error + 0.288).abs(),
        SETTLED,
    );
    let back = w.run(&mut e, 12 * HOUR);
    assert!(has_log(&back, &LogEvent::AdjustmentEnabled));
    no_steps(&back);
    // Slewed within the cap. Zero quantisation, so the applied rate is the
    // command.
    within("back.max_abs_frequency", back.max_abs_frequency, 500.0);
    // A phase error with damping 1 does not overshoot, so the error only
    // shrinks from the 288 ms.
    within("back.max_abs_error", back.max_abs_error, 0.288 + SETTLED);
    within("back.final_error.abs()", back.final_error.abs(), SETTLED);
    assert_eq!(
        off.commands_while_disabled + back.commands_while_disabled,
        0
    );
}

#[test]
fn asymmetric_delay_error_stays_within_half_the_asymmetry() {
    // The outbound leg is 20 ms longer than the return leg on every path.
    // NTP cannot see this. The readings are 10 ms high and the clock ends
    // 10 ms ahead.
    let asym = 0.020;
    let mut w = world(43, 0.0);
    for i in 0..4 {
        w.add_server(
            &format!("pool-{i}"),
            ServerSpec {
                delay: 0.040,
                asymmetry: asym,
                jitter: 0.0005,
                ..healthy(Tier::Pool)
            },
        );
    }
    let mut e = engine(Some(DRIFT));
    let _ = w.run(&mut e, 12 * HOUR);
    let r = w.run(&mut e, 12 * HOUR);
    // 0.5 ms legs give readings off by 0.25 ms, so 1 ms of loop noise.
    let noise = 4.0 * 0.0005 / 2.0;
    within("r.max_abs_error", r.max_abs_error, asym / 2.0 + noise);
    // The bias is real, which shows the sim does not leak true time.
    assert!(r.final_error >= asym / 2.0 - noise, "{}", r.final_error);
    no_steps(&r);
}

/// Added beyond the brief. DOCUMENTS CURRENT BEHAVIOUR FOR AN OPEN
/// DECISION. The pool cross-check only vetoes steps. A config server 10 s
/// wrong is never stepped to, but the loop slews toward it at the 500 ppm
/// cap and the clock ends 10 s wrong. Spec line 198 and the anti-goal "lets
/// one bad or hostile source set the time" are not met. The owner must
/// decide (refuse the slew past the step threshold while the pool
/// disagrees, or fall to the pool tier). Change these assertions when that
/// decision is made.
#[test]
fn bad_config_server_with_healthy_pool_documents_current_behaviour() {
    let mut w = world(47, 0.0);
    w.add_server(
        "bad-config",
        ServerSpec {
            offset: 10.0,
            ..healthy(Tier::Config)
        },
    );
    add_pool(&mut w, 4);
    let mut e = engine(Some(DRIFT));
    // 10 s at 500 ppm is 20 000 s. The last second is a linear tail with
    // the 2048 s phase constant, so 16 hours is ample.
    let r = w.run(&mut e, 16 * HOUR);
    no_steps(&r);
    assert!(
        r.logs
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::StepRefused { .. }))
    );
    assert_eq!(e.status().active_tier, Some(Tier::Config));
    // The slew stays within the cap, drift included.
    within("r.max_abs_frequency", r.max_abs_frequency, 500.0);
    // CURRENT behaviour, not the wanted one: the clock follows the bad
    // server. Within one reading's noise plus the settled loop error.
    within(
        "(r.final_error - 10.0).abs()",
        (r.final_error - 10.0).abs(),
        SETTLED,
    );
}

#[test]
fn same_seed_gives_the_same_run() {
    let run = |seed| {
        let mut w = world(seed, 0.020);
        add_pool(&mut w, 4);
        w.add_server(
            "lossy",
            ServerSpec {
                loss_rate: 0.3,
                ..healthy(Tier::Pool)
            },
        );
        let mut e = engine(None);
        w.run(&mut e, 6 * HOUR)
    };
    assert_eq!(run(5), run(5));
    assert_ne!(run(5), run(6));
}

/// Added beyond the brief, so `ExternalStep` is exercised. Another program
/// moves the clock. After the first sync the engine slews it back without
/// a step, as the spec asks.
///
/// It also guards ruling R50. Tier usability judges each source by its
/// lowest-delay sample of the last eight. While the loop slews at hundreds
/// of ppm those samples come from different polls. Uncorrected, they stop
/// overlapping and the tier flapped between Dhcp, no tier and Pool. The
/// engine now corrects each stored offset for the slew it applied since.
#[test]
fn external_step_is_slewed_back_without_a_step() {
    for (seed, jump) in [(53, 1.0), (59, 5.0)] {
        let mut w = world(seed, 0.0);
        for label in ["dhcp-a", "dhcp-b", "dhcp-c"] {
            w.add_server(label, healthy(Tier::Dhcp));
        }
        add_pool(&mut w, 4);
        let mut e = engine(Some(DRIFT));
        let _ = w.run(&mut e, 6 * HOUR);
        w.schedule(6 * HOUR, SimEvent::ExternalStep(Offset::from_secs(jump)));
        let r = w.run(&mut e, 12 * HOUR);
        no_steps(&r);
        within("r.max_abs_frequency", r.max_abs_frequency, 500.0);
        // The jump with damping 1 shrinks without overshoot. 12 hours is
        // over 20 phase constants, so only the settled noise is left.
        within("r.max_abs_error", r.max_abs_error, jump + SETTLED);
        within("r.final_error.abs()", r.final_error.abs(), SETTLED);
        assert_eq!(e.status().active_tier, Some(Tier::Dhcp));
        // Zero tier changes. Every server is healthy and answers every
        // query, so a tier can only fail when its sources disagree.
        // Corrected readings differ by reading noise (2 ms at most) plus
        // what the correction misses. It uses the commanded slew, which
        // the clock applies exactly here (no quantisation). It misses only
        // the error of the learned drift, under 2 ppm, over a sample age of
        // at most 448 s: 0.9 ms. Each interval is at least 15 ms wide on
        // either side, so the sources always overlap.
        let changes: Vec<_> = r
            .logs
            .iter()
            .filter(|(_, l)| matches!(l, LogEvent::TierChanged { .. }))
            .collect();
        assert_eq!(changes.len(), 0, "jump {jump}: tier flapped {changes:?}");
    }
}

/// Added in round 2. The clock fails a step end to end. The host stops
/// the rest of the batch. The failure latches: the host's periodic `true`
/// does not re-open adjustment. Only a re-arm (`false` then `true`) does,
/// and it allows the step that never reached the clock once more.
#[test]
fn clock_failure_stops_the_batch_and_latches_until_rearm() {
    let mut w = world(61, 0.0);
    add_pool(&mut w, 4);
    let mut e = engine(Some(DRIFT));
    let _ = w.run(&mut e, 6 * HOUR);
    w.schedule(6 * HOUR, SimEvent::ClockFails(true));
    // A wake 2 s off asks for a step. Step and SetFrequency are one batch.
    w.schedule(6 * HOUR, SimEvent::Resume(Offset::from_secs(2.0)));
    let broken = w.run(&mut e, 2 * HOUR);
    assert_eq!(broken.clock_failures, 1);
    assert_eq!(broken.skipped_after_failure, 1, "the batch's SetFrequency");
    no_steps(&broken);
    // The level is re-sent every 300 s, 24 times here. None re-opens.
    assert_eq!(broken.commands_while_disabled, 0);
    let off = LogEvent::AdjustmentDisabled {
        reason: DisableReason::ClockFailed,
    };
    assert!(has_log(&broken, &off));
    assert!(!e.status().adjustment_allowed);
    // Nothing moved the clock. Its last rate was the drift plus a settled
    // phase term under 0.2 ppm, so 2 h add under 1.5 ms.
    within(
        "|broken.final_error - 2|",
        (broken.final_error - 2.0).abs(),
        SETTLED,
    );
    w.schedule(8 * HOUR, SimEvent::ClockFails(false));
    w.schedule(8 * HOUR, SimEvent::HostRearm);
    let fixed = w.run(&mut e, 6 * HOUR);
    assert!(e.status().adjustment_allowed);
    assert_eq!(fixed.steps.len(), 1, "{:?}", fixed.steps);
    within(
        "|step + 2|",
        (fixed.steps[0].1.as_secs() + 2.0).abs(),
        0.002,
    );
    within("fixed.final_error.abs()", fixed.final_error.abs(), SETTLED);
    assert_eq!(fixed.clock_failures + fixed.commands_while_disabled, 0);
}
