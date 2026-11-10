//! Scripted tests for the engine.

use super::*;
use crate::Delay;
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;

type Reply = Box<dyn FnMut(SourceId, u64) -> Result<f64, QueryFailure>>;
type DelayOf = Box<dyn FnMut(SourceId, u64) -> f64>;

const NANOS: u64 = 1_000_000_000;

fn at(secs: u64) -> Mono {
    Mono::from_nanos(secs * NANOS)
}

fn secs(m: Mono) -> u64 {
    m.as_nanos() / NANOS
}

fn id(n: u32) -> SourceId {
    SourceId::new(n)
}

fn addr(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 123)
}

fn spec(n: u8, tier: Tier) -> SourceSpec {
    SourceSpec {
        id: id(n.into()),
        tier,
        addr: addr(n),
        label: format!("s{n}"),
    }
}

fn sample_with(source: SourceId, offset: f64, delay: f64, t: Mono) -> Sample {
    Sample {
        source,
        offset: Offset::from_secs(offset),
        delay: Delay::from_secs(delay),
        stratum: 2,
        unsynchronised: false,
        leap_alarm: false,
        at: t,
    }
}

fn sample(source: SourceId, offset: f64, t: Mono) -> Sample {
    sample_with(source, offset, 0.010, t)
}

fn steady(offset: f64) -> Reply {
    Box::new(move |_, _| Ok(offset))
}

fn timeout() -> Reply {
    Box::new(|_, _| Err(QueryFailure::Timeout))
}

fn near(o: Offset, want: f64) -> bool {
    (o.as_secs() - want).abs() < 1e-9
}

/// Clock seen by the servers. It moves by the frequencies and steps the
/// engine emits, so a slew changes the offsets the servers report.
#[derive(Default)]
struct ClockModel {
    shift: f64,
    ppm: f64,
    since: u64,
}

impl ClockModel {
    fn shift_at(&self, t: u64) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let dt = t.saturating_sub(self.since) as f64 / 1e9;
        self.shift - self.ppm * 1e-6 * dt
    }
}

/// Feeds events and answers queries after `rtt` through `reply`.
struct Harness {
    e: Engine,
    now: Mono,
    reply: Reply,
    delay: DelayOf,
    rtt: Duration,
    /// Queries to these sources are never answered.
    lost: Vec<SourceId>,
    model: Option<ClockModel>,
    inbox: Vec<(Mono, Event)>,
    log: Vec<(u64, Action)>,
}

impl Harness {
    fn new(cfg: EngineConfig, reply: Reply) -> Self {
        Self {
            e: Engine::new(cfg, None),
            now: at(0),
            reply,
            delay: Box::new(|_, _| 0.010),
            rtt: Duration::ZERO,
            lost: Vec::new(),
            model: None,
            inbox: Vec::new(),
            log: Vec::new(),
        }
    }

    /// Adjustment on, then the sources.
    fn start(specs: Vec<SourceSpec>, reply: Reply) -> Self {
        Self::start_with(EngineConfig::default(), specs, reply)
    }

    fn start_with(cfg: EngineConfig, specs: Vec<SourceSpec>, reply: Reply) -> Self {
        let mut h = Self::new(cfg, reply);
        h.feed(Event::AdjustmentAllowed(true));
        h.feed(Event::SourcesChanged(specs));
        h
    }

    fn feed(&mut self, ev: Event) -> Vec<Action> {
        let acts = self.e.handle(ev);
        let mut all = Vec::new();
        for a in acts {
            self.log.push((secs(self.now), a.clone()));
            self.react(&a);
            all.push(a);
        }
        // Replies due now go in before time moves on.
        while let Some(i) = self.inbox.iter().position(|(t, _)| *t <= self.now) {
            let (_, ev) = self.inbox.remove(i);
            all.extend(self.feed(ev));
        }
        all
    }

    fn react(&mut self, a: &Action) {
        let n = self.now.as_nanos();
        match a {
            Action::Query { source, .. } if !self.lost.contains(source) => {
                let due = later(self.now, self.rtt);
                let shift = self
                    .model
                    .as_ref()
                    .map_or(0.0, |m| m.shift_at(due.as_nanos()));
                let ev = match (self.reply)(*source, secs(self.now)) {
                    Ok(o) => {
                        let d = (self.delay)(*source, secs(self.now));
                        Event::Sample(sample_with(*source, o + shift, d, due))
                    }
                    Err(f) => Event::Failed(*source, f),
                };
                self.inbox.push((due, ev));
            }
            Action::SetFrequency(f) => {
                if let Some(m) = self.model.as_mut() {
                    m.shift = m.shift_at(n);
                    m.ppm = f.value();
                    m.since = n;
                }
            }
            Action::Step(o) => {
                if let Some(m) = self.model.as_mut() {
                    m.shift = m.shift_at(n) - o.as_secs();
                    m.since = n;
                }
            }
            _ => {}
        }
    }

    fn run(&mut self, until: u64) {
        loop {
            let wake = self.e.next_wake().expect("engine gives a wake time");
            let reply = self.inbox.iter().map(|(t, _)| *t).min();
            let t = reply.map_or(wake, |r| r.min(wake));
            if secs(t) > until {
                return;
            }
            assert!(t > self.now, "time must move forward");
            self.now = t;
            if reply == Some(t) {
                let i = self.inbox.iter().position(|(r, _)| *r == t).expect("reply");
                let (_, ev) = self.inbox.remove(i);
                // A failure carries no time, so the host ticks first.
                if matches!(ev, Event::Failed(..)) {
                    self.feed(Event::Tick(t));
                }
                self.feed(ev);
            } else {
                self.feed(Event::Tick(t));
            }
        }
    }

    fn queries(&self, n: u32) -> Vec<u64> {
        self.times(|a| matches!(a, Action::Query { source, .. } if *source == id(n)))
    }

    fn logs(&self) -> Vec<(u64, LogEvent)> {
        self.log
            .iter()
            .filter_map(|(t, a)| match a {
                Action::Log(l) => Some((*t, l.clone())),
                _ => None,
            })
            .collect()
    }

    fn times(&self, f: impl Fn(&Action) -> bool) -> Vec<u64> {
        self.log
            .iter()
            .filter(|(_, a)| f(a))
            .map(|(t, _)| *t)
            .collect()
    }

    fn steps(&self) -> Vec<u64> {
        self.times(|a| matches!(a, Action::Step(_)))
    }

    fn status(&self) -> EngineStatus {
        self.e.status()
    }
}

fn touches_clock(a: &Action) -> bool {
    matches!(a, Action::Step(_) | Action::SetFrequency(_))
}

fn is_freq(a: &Action) -> bool {
    matches!(a, Action::SetFrequency(_))
}

fn gaps(t: &[u64]) -> Vec<u64> {
    t.windows(2).map(|w| w[1] - w[0]).collect()
}

fn refused(l: &LogEvent, want: f64) -> bool {
    matches!(l, LogEvent::StepRefused { offset } if near(*offset, want))
}

fn kod_waits(h: &Harness) -> Vec<u64> {
    h.logs()
        .iter()
        .filter_map(|(_, l)| match l {
            LogEvent::KissOfDeath { wait, .. } => Some(wait.as_secs()),
            _ => None,
        })
        .collect()
}

#[test]
fn backs_off_on_kiss_of_death() {
    let reply: Reply = Box::new(|_, t| {
        Err(if t == 0 {
            QueryFailure::KissOfDeath(KodCode::Rate)
        } else {
            QueryFailure::Timeout
        })
    });
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], reply);
    h.run(300);
    let kod = LogEvent::KissOfDeath {
        source: id(1),
        code: KodCode::Rate,
        wait: Duration::from_secs(128),
    };
    assert!(h.logs().contains(&(0, kod)));
    // No interval measured yet, so the scheduled 64 s is doubled.
    assert_eq!(h.queries(1)[..2], [0, 128]);
}

#[test]
fn rate_kod_at_max_poll_still_backs_off() {
    let n = Rc::new(Cell::new(0_u32));
    let k = Rc::clone(&n);
    let reply: Reply = Box::new(move |_, t| {
        if t >= 3000 && k.get() == 0 {
            k.set(1);
            Err(QueryFailure::KissOfDeath(KodCode::Rate))
        } else {
            Ok(0.001)
        }
    });
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], reply);
    h.run(9000);
    assert_eq!(kod_waits(&h), vec![2048]);
    let q = h.queries(1);
    let kod_at = *q.iter().find(|&&t| t >= 3000).expect("kod query");
    let next = *q.iter().find(|&&t| t > kod_at).expect("next query");
    assert!(
        next - kod_at >= 2048,
        "next query {} s later",
        next - kod_at
    );
}

#[test]
fn rate_kod_on_cross_check_doubles_its_own_interval() {
    let reply: Reply = Box::new(|s, t| {
        if s == id(2) && t > 0 {
            Err(QueryFailure::KissOfDeath(KodCode::Rate))
        } else {
            Ok(0.001)
        }
    });
    let mut h = Harness::start(vec![spec(1, Tier::Config), spec(2, Tier::Pool)], reply);
    h.run(2000);
    assert_eq!(h.queries(2)[..2], [0, 900]);
    assert_eq!(kod_waits(&h)[0], 1800);
}

#[test]
fn repeated_rate_kod_doubles_up_to_one_day() {
    let reply: Reply = Box::new(|_, _| Err(QueryFailure::KissOfDeath(KodCode::Rate)));
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], reply);
    h.run(600_000);
    let w = kod_waits(&h);
    assert!(w.windows(2).all(|p| p[1] >= p[0]), "waits {w:?}");
    assert!(w.iter().any(|&x| x > 1024), "not capped at max_poll: {w:?}");
    assert_eq!(w.iter().max(), Some(&86_400));
    assert!(w.iter().filter(|&&x| x == 86_400).count() >= 2);
}

#[test]
fn deny_kod_silences_source_for_one_hour() {
    for code in [KodCode::Deny, KodCode::Rstr] {
        let reply: Reply = Box::new(move |_, t| {
            if t == 0 {
                Err(QueryFailure::KissOfDeath(code))
            } else {
                Ok(0.0)
            }
        });
        let mut h = Harness::start(vec![spec(1, Tier::Pool)], reply);
        h.run(5000);
        let q = h.queries(1);
        assert_eq!(q[0], 0);
        assert!(
            (3600..3600 + 1024).contains(&q[1]),
            "{code:?} next query at {}",
            q[1]
        );
        let wait = Duration::from_secs(3600);
        let kod = LogEvent::KissOfDeath {
            source: id(1),
            code,
            wait,
        };
        assert!(h.logs().contains(&(0, kod)));
    }
}

#[test]
fn idle_polling_backs_off_when_every_tier_fails() {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], timeout());
    h.run(6000);
    assert_eq!(h.status().active_tier, None);
    let g = gaps(&h.queries(1));
    assert_eq!(g[..5], [128, 256, 512, 1024, 1024]);
    assert!(g.iter().all(|&x| x <= 1024));
}

#[test]
fn polls_faster_when_unstable() {
    let jumpy: Reply = Box::new(|_, t| Ok(if (t / 64) % 2 == 0 { 0.0 } else { 0.05 }));
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], jumpy);
    h.run(3000);
    assert!(gaps(&h.queries(1)).iter().all(|&g| g == 64));
    let mut calm = Harness::start(vec![spec(1, Tier::Pool)], steady(0.001));
    calm.run(3000);
    assert!(gaps(&calm.queries(1)).iter().any(|&g| g >= 512));
}

#[test]
fn lan_noise_below_floor_does_not_hold_poll_at_min() {
    // A 0.5 ms delay gives a 0.25 ms bound. The 4 ms swing is still noise.
    let noisy: Reply = Box::new(|_, t| Ok(if (t / 64) % 2 == 0 { -0.002 } else { 0.002 }));
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], noisy);
    h.delay = Box::new(|_, _| 0.0005);
    h.run(8000);
    assert_eq!(gaps(&h.queries(1)).last(), Some(&1024));
}

#[test]
fn steady_slew_is_not_jitter() {
    // The clock model follows the slew. A 120 ms offset closes by about
    // 15 ms in 256 s, which would count as jitter without the slew term.
    let mut h = Harness::new(EngineConfig::default(), steady(0.120));
    h.model = Some(ClockModel::default());
    h.delay = Box::new(|_, _| 0.001);
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(4000);
    let g = gaps(&h.queries(1));
    assert_eq!(g[..6], [64, 64, 128, 256, 512, 1024], "gaps {g:?}");
    assert_eq!(h.steps(), Vec::<u64>::new());
}

#[test]
fn respects_min_and_max_poll() {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(0.001));
    h.run(20_000);
    let g = gaps(&h.queries(1));
    assert!(g.iter().all(|&g| (64..=1024).contains(&g)));
    assert_eq!(g.last(), Some(&1024));
    let cfg = EngineConfig {
        min_poll: Duration::from_secs(16),
        max_poll: Duration::from_secs(128),
        ..EngineConfig::default()
    };
    let mut h = Harness::start_with(cfg, vec![spec(1, Tier::Pool)], steady(0.001));
    h.run(5000);
    let g = gaps(&h.queries(1));
    assert!(g.iter().all(|&g| (16..=128).contains(&g)));
    assert_eq!(g.iter().max(), Some(&128));
}

#[test]
fn sources_changed_rechecks_tier() {
    let mut h = Harness::start(vec![spec(1, Tier::Dhcp)], steady(0.001));
    h.run(100);
    assert_eq!(h.status().active_tier, Some(Tier::Dhcp));
    let with_config = vec![spec(1, Tier::Dhcp), spec(2, Tier::Config)];
    let acts = h.feed(Event::SourcesChanged(with_config));
    let probe = Action::Query {
        source: id(2),
        observe_only: true,
    };
    assert!(acts.contains(&probe), "new source is queried at once");
    // Still bootstrapping, so a usable higher tier takes over at once.
    assert_eq!(h.status().active_tier, Some(Tier::Config));
    // The switch came from an observe-only reply. It does not feed the clock.
    assert!(!acts.iter().any(touches_clock));
    let switched = secs(h.now);
    h.run(switched + 64);
    let fed = h.times(is_freq);
    assert!(
        fed.iter().any(|&t| t > switched),
        "next regular round feeds"
    );
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Dhcp)]));
    let gone_at = secs(h.now);
    h.run(1000);
    assert_eq!(h.status().active_tier, Some(Tier::Dhcp));
    assert!(h.queries(2).iter().all(|&t| t <= gone_at));
}

#[test]
fn logs_single_source_tier() {
    let mut h = Harness::start(vec![spec(1, Tier::Config)], steady(0.001));
    h.run(3000);
    let single = LogEvent::SingleSourceTier {
        tier: Tier::Config,
        source: id(1),
    };
    assert_eq!(h.logs().iter().filter(|(_, l)| *l == single).count(), 1);
    let two = vec![spec(1, Tier::Config), spec(2, Tier::Config)];
    let mut h = Harness::start(two, steady(0.001));
    h.run(3000);
    assert!(
        !h.logs()
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::SingleSourceTier { .. }))
    );
}

#[test]
fn logs_when_dhcp_differs_from_config() {
    let count = |h: &Harness| {
        let logs = h.logs();
        logs.iter()
            .filter(|(_, l)| matches!(l, LogEvent::DhcpDiffersFromConfig { .. }))
            .count()
    };
    let specs = vec![spec(1, Tier::Config), spec(2, Tier::Dhcp)];
    let mut h = Harness::start(specs.clone(), timeout());
    h.feed(Event::SourcesChanged(specs));
    let diff = LogEvent::DhcpDiffersFromConfig {
        dhcp_only: vec![id(2)],
        config_only: vec![id(1)],
    };
    assert!(h.logs().iter().any(|(_, l)| *l == diff));
    assert_eq!(count(&h), 1, "logged once per difference");
    let mut same = spec(3, Tier::Dhcp);
    same.addr = addr(1);
    let mut h = Harness::start(vec![spec(1, Tier::Config), same], timeout());
    h.run(100);
    assert_eq!(count(&h), 0);
    // No config servers, so there is nothing to differ from.
    let h = Harness::start(vec![spec(2, Tier::Dhcp)], timeout());
    assert_eq!(count(&h), 0);
}

#[test]
fn no_actions_that_touch_clock_when_adjustment_disallowed() {
    let mut h = Harness::new(EngineConfig::default(), steady(5.0));
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(1000);
    h.feed(Event::Resumed(h.now));
    h.run(4000);
    h.reply = timeout();
    // Long enough for MAX_HOLD and for every tier to fail.
    h.run(9000);
    h.feed(Event::ClockResult(Err(ClockError::Unavailable)));
    // The failure latches, so a level `true` does not re-open the gate.
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::AdjustmentAllowed(true));
    h.reply = steady(5.0);
    h.run(12_000);
    assert!(!h.log.iter().any(|(_, a)| touches_clock(a)));
    assert!(
        h.status().last_offset.is_some_and(|o| near(o, 5.0)),
        "still measures"
    );
    assert!(!h.status().adjustment_allowed);
}

#[test]
fn failed_clock_result_disables_adjustment() {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(0.001));
    h.run(200);
    let acts = h.feed(Event::ClockResult(Err(ClockError::PermissionDenied)));
    let failed = LogEvent::ClockCommandFailed {
        error: ClockError::PermissionDenied,
    };
    assert!(acts.contains(&Action::Log(failed)));
    let off = LogEvent::AdjustmentDisabled {
        reason: DisableReason::ClockFailed,
    };
    assert!(acts.contains(&Action::Log(off)));
    let n = h.log.len();
    h.feed(Event::AdjustmentAllowed(true));
    h.run(4000);
    assert!(!h.log[n..].iter().any(|(_, a)| touches_clock(a)));
    assert!(!h.status().adjustment_allowed);
    // The host re-arms with `false` then `true`.
    h.feed(Event::AdjustmentAllowed(false));
    let acts = h.feed(Event::AdjustmentAllowed(true));
    assert!(acts.iter().any(is_freq));
    assert!(h.status().adjustment_allowed);
}

#[test]
fn reenable_after_failed_step_allows_another_step() {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(5.0));
    h.run(100);
    assert_eq!(h.steps().len(), 1);
    h.feed(Event::ClockResult(Err(ClockError::PermissionDenied)));
    h.run(300);
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::AdjustmentAllowed(true));
    h.run(1000);
    assert_eq!(h.steps().len(), 2);
    // A step that succeeded is not repeated after a later re-enable.
    h.feed(Event::ClockResult(Ok(())));
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::AdjustmentAllowed(true));
    h.run(3000);
    assert_eq!(h.steps().len(), 2);
}

/// Syncs a pool source, then lets every query time out.
fn gone_silent() -> (Harness, u64) {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(0.001));
    h.run(500);
    let last = *h.queries(1).last().expect("queried");
    h.reply = timeout();
    h.run(6000);
    (h, last)
}

#[test]
fn reports_holdover_age_when_no_sources_answer() {
    let (h, last) = gone_silent();
    let s = h.status();
    assert_eq!(
        s.last_good_age,
        Some(Duration::from_secs(secs(h.now) - last))
    );
    assert_eq!(s.active_tier, None);
    assert!(s.holdover);
    assert!(
        h.logs()
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::TierChanged { to: None, .. }))
    );
}

#[test]
fn max_hold_expiry_calls_free_run() {
    let (h, last) = gone_silent();
    let drift = h.status().drift;
    let hold = last + 2048;
    let holdover = LogEvent::HoldoverStarted { frequency: drift };
    let started: Vec<u64> = h
        .logs()
        .into_iter()
        .filter(|(_, l)| *l == holdover)
        .map(|(t, _)| t)
        .collect();
    assert_eq!(started, vec![hold]);
    let freq = h.times(|a| *a == Action::SetFrequency(drift));
    assert!(freq.contains(&hold));
    assert!(
        h.times(touches_clock)
            .iter()
            .all(|&t| t <= last || t == hold)
    );
}

#[test]
fn saves_drift_at_most_every_ten_minutes() {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(0.05));
    h.run(7200);
    let saves = h.times(|a| matches!(a, Action::SaveDrift(_)));
    assert!(saves.len() >= 3, "saves {saves:?}");
    assert!(gaps(&saves).iter().all(|&g| g >= 600), "saves {saves:?}");
}

#[test]
fn drift_save_allowed_at_exactly_ten_minutes() {
    let cfg = EngineConfig {
        min_poll: Duration::from_secs(100),
        max_poll: Duration::from_secs(100),
        ..EngineConfig::default()
    };
    let mut h = Harness::start_with(cfg, vec![spec(1, Tier::Pool)], steady(0.05));
    h.run(1500);
    // Round 0 is observe only. Round 100 starts the loop. Round 200 teaches.
    let saves = h.times(|a| matches!(a, Action::SaveDrift(_)));
    assert_eq!(saves, vec![200, 800, 1400]);
}

#[test]
fn stale_lowest_delay_sample_feeds_the_loop_once() {
    // The first reply has the lowest delay and stays best in the window.
    let mut h = Harness::new(EngineConfig::default(), steady(0.05));
    h.delay = Box::new(|_, t| if t == 0 { 0.001 } else { 0.050 });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(500);
    // Round 64 uses the 0 s sample. Rounds 128 to 448 bring nothing better.
    let fed: Vec<u64> = h.times(is_freq).into_iter().filter(|&t| t > 0).collect();
    assert_eq!(fed, vec![64]);
}

#[test]
fn drift_does_not_wind_up_on_one_stale_sample() {
    let cfg = EngineConfig {
        selection: SelectionConfig {
            max_age: Duration::from_secs(4000),
            ..SelectionConfig::default()
        },
        ..EngineConfig::default()
    };
    let n = Rc::new(Cell::new(0_u32));
    let k = Rc::clone(&n);
    let reply: Reply = Box::new(move |_, _| {
        k.set(k.get() + 1);
        if k.get() <= 2 {
            Ok(0.05)
        } else {
            Err(QueryFailure::Malformed)
        }
    });
    let mut h = Harness::start_with(cfg, vec![spec(1, Tier::Pool)], reply);
    h.run(64 + 20 * 64);
    assert!(n.get() >= 20, "rounds {}", n.get());
    // One update only, and a first update never teaches.
    assert_eq!(h.status().drift, Ppm::new(0.0));
    let fed: Vec<u64> = h.times(is_freq).into_iter().filter(|&t| t > 0).collect();
    assert_eq!(fed, vec![64]);
}

#[test]
fn stale_pool_sample_is_pending() {
    // Adjustment stays off, so no frequency change limits the window.
    let mut e = Engine::new(EngineConfig::default(), None);
    let _ = e.handle(Event::SourcesChanged(vec![
        spec(1, Tier::Config),
        spec(2, Tier::Pool),
    ]));
    let _ = e.handle(Event::Sample(sample(id(2), 0.5, at(10))));
    let _ = e.handle(Event::Tick(at(910)));
    assert_eq!(
        e.cross_check(Tier::Config),
        CrossCheck::Offset(Offset::from_secs(0.5))
    );
    let _ = e.handle(Event::Tick(at(911)));
    assert_eq!(e.cross_check(Tier::Config), CrossCheck::Pending);
    assert_eq!(e.cross_check(Tier::Pool), CrossCheck::NotRequired);
}

/// Config and pool with a 300 ms reply delay. `pool` gives the pool
/// offset at a time in seconds.
fn config_and_pool(config: Reply, pool: Reply, until: u64) -> Harness {
    let (mut config, mut pool) = (config, pool);
    let reply: Reply = Box::new(move |s, t| if s == id(1) { config(s, t) } else { pool(s, t) });
    let mut h = Harness::start(vec![spec(1, Tier::Config), spec(2, Tier::Pool)], reply);
    h.rtt = Duration::from_millis(300);
    h.run(until);
    assert_eq!(h.status().active_tier, Some(Tier::Config));
    h
}

#[test]
fn refuses_step_when_pool_cross_check_disagrees() {
    // The pool disagrees first, then agrees from its 900 s round. An
    // always-Pending check would never step. No check would step at once.
    let pool: Reply = Box::new(|_, t| Ok(if t < 800 { 0.0 } else { 5.05 }));
    let h = config_and_pool(steady(5.0), pool, 3600);
    let steps = h.steps();
    assert_eq!(steps.len(), 1, "steps {steps:?}");
    assert!(steps[0] > 900, "step at {}", steps[0]);
    let refusals: Vec<u64> = h
        .logs()
        .iter()
        .filter(|(_, l)| refused(l, 5.0))
        .map(|(t, _)| *t)
        .collect();
    assert_eq!(refusals.len(), 1, "logged on change only: {refusals:?}");
    assert!(refusals[0] < 900);
    assert!(h.times(is_freq).len() > 3);
}

#[test]
fn allows_step_when_pool_cross_check_agrees() {
    let h = config_and_pool(steady(5.0), steady(5.05), 3600);
    let steps: Vec<&Action> = h
        .log
        .iter()
        .map(|(_, a)| a)
        .filter(|a| matches!(a, Action::Step(_)))
        .collect();
    assert_eq!(steps.len(), 1);
    assert!(matches!(steps[0], Action::Step(o) if near(*o, 5.0)));
    // The step comes before its frequency.
    let i = h
        .log
        .iter()
        .position(|(_, a)| matches!(a, Action::Step(_)))
        .expect("step");
    assert!(h.log[i + 1..].iter().any(|(_, a)| is_freq(a)));
    assert!(
        h.logs()
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::StepTaken { offset } if near(*offset, 5.0)))
    );
}

#[test]
fn slews_only_when_no_pool_cross_check_sample_exists_yet() {
    let h = config_and_pool(steady(5.0), timeout(), 3600);
    assert_eq!(h.steps(), Vec::<u64>::new());
    assert_eq!(h.logs().iter().filter(|(_, l)| refused(l, 5.0)).count(), 1);
    assert!(
        h.log
            .iter()
            .any(|(_, a)| matches!(a, Action::SetFrequency(f) if f.value() > 100.0))
    );
}

#[test]
fn slewed_config_offset_does_not_slip_under_stale_pool_veto() {
    // Pool 4.7 disagrees with 5.0. After a slew the config reads 4.8, which
    // would agree with the old pool reading. That reading predates the slew.
    let config: Reply = Box::new(|_, t| Ok(if t < 100 { 5.0 } else { 4.8 }));
    let n = Rc::new(Cell::new(0_u32));
    let k = Rc::clone(&n);
    let pool: Reply = Box::new(move |_, _| {
        k.set(k.get() + 1);
        if k.get() == 1 {
            Ok(4.7)
        } else {
            Err(QueryFailure::Timeout)
        }
    });
    let h = config_and_pool(config, pool, 3600);
    assert_eq!(h.steps(), Vec::<u64>::new());
}

#[test]
fn old_survivor_sample_cannot_decide_a_step() {
    // Config source 1 answers once. Its sample stays a survivor until it
    // ages out at 1024 s. It predates the refusal at 64 s, so no step may
    // rest on it, even when the pool agrees from 900 s.
    let n = Rc::new(Cell::new(0_u32));
    let k = Rc::clone(&n);
    let reply: Reply = Box::new(move |s, t| {
        if s == id(1) {
            k.set(k.get() + 1);
            if k.get() == 1 {
                Ok(5.0)
            } else {
                Err(QueryFailure::Timeout)
            }
        } else if s == id(3) {
            Ok(5.0)
        } else {
            Ok(if t < 800 { 0.0 } else { 5.05 })
        }
    });
    let specs = vec![
        spec(1, Tier::Config),
        spec(2, Tier::Pool),
        spec(3, Tier::Config),
    ];
    let mut h = Harness::new(EngineConfig::default(), reply);
    h.rtt = Duration::from_millis(300);
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(specs));
    h.run(3600);
    let steps = h.steps();
    assert_eq!(steps.len(), 1, "steps {steps:?}");
    assert!(steps[0] > 1024, "step at {}", steps[0]);
}

#[test]
fn resumed_allows_one_step() {
    let offset = Rc::new(Cell::new(0.001));
    let o = Rc::clone(&offset);
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], Box::new(move |_, _| Ok(o.get())));
    h.run(300);
    offset.set(5.0);
    h.run(1500);
    assert_eq!(h.steps(), Vec::<u64>::new(), "no step after the first sync");
    h.feed(Event::Resumed(h.now));
    h.run(4000);
    assert_eq!(h.steps().len(), 1);
}

#[test]
fn reply_across_resume_ends_its_wait() {
    let mut e = Engine::new(EngineConfig::default(), None);
    let _ = e.handle(Event::AdjustmentAllowed(true));
    let _ = e.handle(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    let _ = e.handle(Event::Resumed(at(1)));
    // The pre-sleep reply arrives. It is dropped, but its round closes, so
    // the recheck round goes out at once instead of after 30 s.
    let acts = e.handle(Event::Sample(sample(id(1), 9.0, at(2))));
    assert!(acts.contains(&Action::Query {
        source: id(1),
        observe_only: true
    }));
    assert_eq!(e.status().last_offset, None);
}

#[test]
fn probes_building_tier_faster_than_reprobe_every() {
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(0.001));
    h.run(1000);
    let added = secs(h.now);
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Config),
    ]));
    h.run(3000);
    let switch = LogEvent::TierChanged {
        from: Some(Tier::Pool),
        to: Some(Tier::Config),
    };
    let (when, _) = h
        .logs()
        .into_iter()
        .find(|(_, l)| *l == switch)
        .expect("Config takes over");
    assert!(
        when >= added + 600 && when <= added + 600 + 64,
        "switch at {when}"
    );
    let probes: Vec<u64> = h.queries(2).into_iter().filter(|&t| t <= when).collect();
    assert!(gaps(&probes).iter().all(|&g| g <= 64), "probes {probes:?}");
}

#[test]
fn overdue_probe_with_slow_reply_is_not_skipped() {
    // Every reply takes 5 s. The chooser measures reprobe_every from the
    // reply, so the Config probe is due 905 s after the last one went out.
    // A wake at 900 s would find nothing due and slip it to a later round.
    let reply: Reply = Box::new(|s, _| {
        if s == id(2) {
            Err(QueryFailure::Malformed)
        } else {
            Ok(0.001)
        }
    });
    let mut h = Harness::new(EngineConfig::default(), reply);
    h.rtt = Duration::from_secs(5);
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Dhcp),
        spec(2, Tier::Config),
    ]));
    h.run(5000);
    assert_eq!(h.status().active_tier, Some(Tier::Dhcp));
    let g = gaps(&h.queries(2));
    assert!(g.len() >= 3, "probes {:?}", h.queries(2));
    assert!(g.iter().all(|&x| x == 905), "gaps {g:?}");
}

#[test]
fn lost_query_closes_round_after_timeout() {
    let mut h = Harness::start(
        vec![spec(1, Tier::Pool), spec(2, Tier::Pool)],
        steady(0.001),
    );
    h.lost = vec![id(2)];
    h.run(200);
    // Round 64 waits for source 2 until 94 s, then feeds the clock.
    assert!(h.times(is_freq).contains(&94), "{:?}", h.times(is_freq));
    assert!(h.queries(2).len() >= 2, "source 2 is asked again");
}

#[test]
fn selection_never_uses_non_active_tier_samples() {
    let h = config_and_pool(steady(0.010), steady(0.100), 3000);
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.010)));
    let flags = |n: u32| -> Vec<bool> {
        h.log
            .iter()
            .filter_map(|(t, a)| match a {
                Action::Query {
                    source,
                    observe_only,
                } if *source == id(n) && *t > 0 => Some(*observe_only),
                _ => None,
            })
            .collect()
    };
    assert!(flags(2).iter().all(|&f| f), "pool is observe only");
    assert!(
        !flags(1).is_empty() && flags(1).iter().all(|&f| !f),
        "config feeds the clock"
    );
}

#[test]
fn adjustment_allowed_true_again_restores_emission() {
    let mut h = Harness::new(EngineConfig::default(), steady(0.001));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(500);
    assert!(!h.log.iter().any(|(_, a)| touches_clock(a)));
    let acts = h.feed(Event::AdjustmentAllowed(true));
    assert!(acts.contains(&Action::SetFrequency(h.status().drift)));
    assert!(acts.contains(&Action::Log(LogEvent::AdjustmentEnabled)));
    let n = h.log.len();
    h.run(3000);
    assert!(h.log[n..].iter().any(|(_, a)| touches_clock(a)));
}

#[test]
fn source_removed_mid_round_is_dropped() {
    let mut e = Engine::new(EngineConfig::default(), None);
    let acts = e.handle(Event::SourcesChanged(vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
    ]));
    assert_eq!(
        acts.iter()
            .filter(|a| matches!(a, Action::Query { .. }))
            .count(),
        2
    );
    let _ = e.handle(Event::Sample(sample(id(1), 0.002, at(0))));
    let _ = e.handle(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    // The round no longer waits for the removed source.
    assert_eq!(e.status().active_tier, Some(Tier::Pool));
    let _ = e.handle(Event::Sample(sample(id(2), 9.0, at(1))));
    let acts = e.handle(Event::Tick(at(64)));
    assert!(
        !acts
            .iter()
            .any(|a| matches!(a, Action::Query { source, .. } if *source == id(2)))
    );
    let _ = e.handle(Event::Sample(sample(id(1), 0.003, at(64))));
    assert!(e.status().last_offset.is_some_and(|o| near(o, 0.003)));
}

#[test]
fn out_of_order_time_does_not_panic() {
    let mut e = Engine::new(EngineConfig::default(), Some(Ppm::new(3.0)));
    let events = [
        Event::AdjustmentAllowed(true),
        Event::SourcesChanged(vec![spec(1, Tier::Pool)]),
        Event::Tick(at(1000)),
        Event::Sample(sample(id(1), 0.01, at(5))),
        Event::Tick(at(10)),
        Event::Resumed(at(3)),
        Event::Failed(id(1), QueryFailure::KissOfDeath(KodCode::Rate)),
        Event::Tick(at(0)),
        Event::Sample(sample(id(1), 0.02, at(2000))),
        Event::Tick(at(1500)),
        Event::Tick(Mono::from_nanos(u64::MAX)),
        Event::Failed(id(1), QueryFailure::KissOfDeath(KodCode::Deny)),
        Event::Tick(at(1)),
    ];
    for ev in events {
        let _ = e.handle(ev);
    }
    let _ = e.next_wake();
    let _ = e.status();
}

#[test]
fn start_sets_saved_drift_as_frequency() {
    let mut e = Engine::new(EngineConfig::default(), Some(Ppm::new(12.5)));
    // Adjustment starts off, so nothing touches the clock yet.
    assert!(!e.handle(Event::Tick(at(0))).iter().any(touches_clock));
    let acts = e.handle(Event::AdjustmentAllowed(true));
    assert!(acts.contains(&Action::SetFrequency(Ppm::new(12.5))));
    assert_eq!(e.status().drift, Ppm::new(12.5));
}

/// Release only: a debug build asserts finiteness when the offset is built.
#[cfg(not(debug_assertions))]
#[test]
fn non_finite_offset_changes_nothing() {
    let mut e = Engine::new(EngineConfig::default(), None);
    let _ = e.handle(Event::AdjustmentAllowed(true));
    let _ = e.handle(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    let _ = e.handle(Event::Sample(sample(id(1), 0.001, at(0))));
    let _ = e.handle(Event::Tick(at(64)));
    // 1e308 weighted by 1 / 10 ms overflows to infinity in selection.
    let acts = e.handle(Event::Sample(sample(id(1), 1e308, at(64))));
    assert!(!acts.iter().any(touches_clock));
    let s = e.status();
    assert_eq!(s.last_offset, None);
    assert_eq!(s.last_good_age, None);
    assert!(!s.holdover);
}
