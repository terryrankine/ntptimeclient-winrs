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
    /// Mono resolution in nanoseconds, as on a host with coarse ticks. The
    /// engine sees stamps rounded down and ticks rounded up to it.
    grid: Option<u64>,
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
            grid: None,
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

    fn down(&self, m: Mono) -> Mono {
        self.grid
            .map_or(m, |g| Mono::from_nanos(m.as_nanos() / g * g))
    }

    fn up(&self, m: Mono) -> Mono {
        self.grid.map_or(m, |g| {
            Mono::from_nanos(m.as_nanos().div_ceil(g).saturating_mul(g))
        })
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
                        Event::Sample(sample_with(*source, o + shift, d, self.down(due)))
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
            let wake = self.up(wake);
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
                    self.feed(Event::Tick(self.down(t)));
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
    // A batch of Step then SetFrequency: the step fails, the frequency
    // result is Ok. The failure must stay latched.
    let before = h.steps().len();
    h.feed(Event::Resumed(h.now));
    h.run(1300);
    assert_eq!(h.steps().len(), before + 1);
    h.feed(Event::ClockResult(Err(ClockError::PermissionDenied)));
    h.feed(Event::ClockResult(Ok(())));
    assert!(!h.status().adjustment_allowed);
    h.feed(Event::AdjustmentAllowed(true));
    h.run(1600);
    assert_eq!(h.steps().len(), before + 1, "a level true does not re-open");
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::AdjustmentAllowed(true));
    h.run(2000);
    assert_eq!(
        h.steps().len(),
        before + 2,
        "re-enable allows the step again"
    );
    // A step that succeeded is not repeated after a later re-enable.
    h.feed(Event::ClockResult(Ok(())));
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::AdjustmentAllowed(true));
    h.run(4000);
    assert_eq!(h.steps().len(), before + 2);
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
fn stale_lowest_delay_sample_is_not_reused() {
    // The 64 s reply has the lowest delay and stays best in the filter.
    // Every later round must feed its own new reading instead.
    let reply: Reply = Box::new(|_, t| Ok(if t == 64 { 0.05 } else { 0.01 }));
    let mut h = Harness::new(EngineConfig::default(), reply);
    // Later delays stay under 3 x 10 ms, so the spike guard keeps out of it.
    h.delay = Box::new(|_, t| {
        if t == 64 {
            0.010
        } else {
            0.020 + 0.002 * f64::from(u8::try_from(t / 64 % 5).unwrap_or(0))
        }
    });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(500);
    let fed: Vec<u64> = h.times(is_freq).into_iter().filter(|&t| t > 0).collect();
    assert_eq!(fed[..3], [64, 128, 192], "fed {fed:?}");
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.01)));
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
    // The pool disagrees first, then agrees from 800 s. An always-Pending
    // check would never step. No check would step at once.
    let pool: Reply = Box::new(|_, t| Ok(if t < 800 { 0.0 } else { 5.05 }));
    let h = config_and_pool(steady(5.0), pool, 3600);
    let steps = h.steps();
    assert_eq!(steps.len(), 1, "steps {steps:?}");
    // Every refusal asks the pool again, at most once per poll, whether its
    // reading is missing, stale or disagreeing. The first ask at or after
    // 800 s gets an agreeing reply and the next config round steps. Worst
    // case two polls.
    assert!(
        (800..=800 + 2 * 64).contains(&steps[0]),
        "step at {}",
        steps[0]
    );
    let refusals: Vec<u64> = h
        .logs()
        .iter()
        .filter(|(_, l)| refused(l, 5.0))
        .map(|(t, _)| *t)
        .collect();
    assert_eq!(refusals.len(), 1, "logged on change only: {refusals:?}");
    assert!(refusals[0] < 800);
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
fn large_start_offset_steps_soon_after_pool_answers() {
    // The pool misses its first query. The refusal at 64 s asks it again at
    // once, so the step comes one poll later, not after reprobe_every.
    let pool: Reply = Box::new(|_, t| {
        if t == 0 {
            Err(QueryFailure::Timeout)
        } else {
            Ok(5.05)
        }
    });
    let h = config_and_pool(steady(5.0), pool, 1000);
    assert_eq!(h.queries(2)[..2], [0, 64]);
    assert_eq!(h.steps(), vec![128]);
}

#[test]
fn vetoed_step_asks_pool_at_most_once_per_poll() {
    let h = config_and_pool(steady(5.0), timeout(), 3600);
    assert_eq!(h.steps(), Vec::<u64>::new());
    let q = h.queries(2);
    assert!(q.len() > 20, "pool asked again: {q:?}");
    assert!(gaps(&q).iter().all(|&g| g >= 64), "pool queries {q:?}");
    assert!(h.queries(2).len() <= h.queries(1).len());
}

#[test]
fn pool_ask_is_deduped_within_one_poll() {
    // Refusals come once per config round, so only the guard itself can be
    // driven twice inside one poll.
    let mut h = config_and_pool(steady(5.0), timeout(), 200);
    let pool = slot(Tier::Pool);
    assert!(!h.e.recheck[pool]);
    h.e.ask_pool_now();
    assert!(!h.e.recheck[pool], "pool was asked less than a poll ago");
    h.e.now = later(h.e.now, h.e.poll);
    h.e.ask_pool_now();
    assert!(h.e.recheck[pool]);
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
fn old_sample_is_left_out_of_step_decision() {
    // Config source 1 answers once. Its sample stays in the filter until it
    // ages out at 1024 s. It predates the refusal at 64 s, so it never feeds
    // the loop or decides the step. It still counts for tier usability,
    // corrected for the slew since (ruling R50). The step rests on source 3
    // alone, soon after the pool agrees from 800 s.
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
    // The refusal slews at 500 ppm, so real readings move with it. Without
    // the model source 3 would read 5 s for 700 s of slewing, and the
    // slew-corrected old sample of source 1 (ruling R50) would disagree.
    h.model = Some(ClockModel::default());
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(specs));
    h.run(3600);
    let steps = h.steps();
    assert_eq!(steps.len(), 1, "steps {steps:?}");
    assert!(
        (800..=800 + 3 * 64).contains(&steps[0]),
        "step at {}",
        steps[0]
    );
}

#[test]
fn two_config_sources_with_varying_delays_step_after_pool_agrees() {
    // Reviewer probe. The pool misses its first query, then agrees. Config
    // delays vary per round and per source, so no newest sample is also
    // the lowest-delay one for long.
    let reply: Reply = Box::new(|s, t| {
        if s == id(2) {
            if t == 0 {
                Err(QueryFailure::Timeout)
            } else {
                Ok(5.05)
            }
        } else {
            Ok(5.0)
        }
    });
    let mut h = Harness::new(EngineConfig::default(), reply);
    h.rtt = Duration::from_millis(300);
    h.delay = Box::new(|s, t| {
        let k = (t / 64 * 7 + u64::from(s.get()) * 3) % 5;
        0.010 + 0.002 * f64::from(u8::try_from(k).unwrap_or(0))
    });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Config),
        spec(2, Tier::Pool),
        spec(3, Tier::Config),
    ]));
    h.run(3600);
    let steps = h.steps();
    assert_eq!(steps.len(), 1, "steps {steps:?}");
    // Refused at 64 s, pool asked then, step one poll later.
    assert!(steps[0] <= 64 + 64 + 1, "step at {}", steps[0]);
}

#[test]
fn drift_does_not_wind_up_on_an_old_low_delay_sample_of_one_source() {
    // Two pool sources agree on zero. Source 1's 64 s reply reads 4 ms with
    // a 1 ms delay and would outweigh everything for eight rounds. Every
    // later reading is zero, so the drift must not move at all.
    let reply: Reply = Box::new(|s, t| Ok(if s == id(1) && t == 64 { 0.004 } else { 0.0 }));
    let mut h = Harness::new(EngineConfig::default(), reply);
    h.delay = Box::new(|s, t| {
        if s == id(1) && t == 64 {
            0.001
        } else {
            let k = (t / 64 + u64::from(s.get())) % 5;
            0.020 + 0.002 * f64::from(u8::try_from(k).unwrap_or(0))
        }
    });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
    ]));
    h.run(20_000);
    assert!(h.queries(1).len() >= 20, "rounds {}", h.queries(1).len());
    assert!(
        h.status().drift.value().abs() < 1e-12,
        "drift {:?}",
        h.status().drift
    );
}

#[test]
fn panic_refusal_does_not_ask_the_pool() {
    // 2000 s is above the 1000 s panic threshold. The pool cannot help, so
    // it stays on its reprobe_every schedule.
    let h = config_and_pool(steady(2000.0), timeout(), 3600);
    assert_eq!(h.steps(), Vec::<u64>::new());
    let q = h.queries(2);
    assert!(gaps(&q).iter().all(|&g| g >= 900), "pool queries {q:?}");
}

#[test]
fn refusal_is_logged_again_after_resume_and_reenable() {
    let refusals = |h: &Harness| h.logs().iter().filter(|(_, l)| refused(l, 5.0)).count();
    let mut h = config_and_pool(steady(5.0), timeout(), 600);
    assert_eq!(refusals(&h), 1);
    h.feed(Event::Resumed(h.now));
    h.run(1200);
    assert_eq!(refusals(&h), 2, "new episode after resume");
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::AdjustmentAllowed(true));
    h.run(1800);
    assert_eq!(refusals(&h), 3, "new episode after re-enable");
}

#[test]
fn sample_from_before_a_frequency_change_does_not_feed_the_loop() {
    // Replies take 40 s, so each lands after its round timed out and is
    // first seen by the next round. The reply to the 128 s query lands at
    // 168 s, as the re-enable sets a new frequency. It does not postdate
    // that change, so round 192 (closed at 222 s) must not use it. Round
    // 256 feeds again from the 232 s reply.
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], steady(0.01));
    h.rtt = Duration::from_secs(40);
    h.run(169);
    assert!(h.times(is_freq).contains(&158), "{:?}", h.times(is_freq));
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::AdjustmentAllowed(true));
    h.run(300);
    assert!(h.queries(1).contains(&192), "{:?}", h.queries(1));
    let fed: Vec<u64> = h.times(is_freq).into_iter().filter(|&t| t > 168).collect();
    assert_eq!(fed, vec![286]);
}

#[test]
fn lone_falseticker_is_not_fed_when_majority_misses_rounds() {
    // Reviewer probe. Sources 1 and 2 read 0, source 3 reads +100 ms. From
    // 1000 s to 1100 s only source 3 answers. The tier still holds the
    // agreeing pair in its eight-sample window, so source 3 alone must not
    // feed the loop.
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let reply: Reply = Box::new(|s, t| {
        if s == id(3) {
            Ok(0.100)
        } else if (1000..1100).contains(&t) {
            Err(QueryFailure::Timeout)
        } else {
            Ok(0.0)
        }
    });
    let specs = vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
        spec(3, Tier::Pool),
    ];
    let mut h = Harness::start_with(cfg, specs, reply);
    h.run(990);
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.0)));
    let n = h.log.len();
    h.run(1100);
    let after = h.status().last_offset.expect("offset");
    assert!(
        after.as_secs().abs() < 0.01,
        "falseticker fed alone: {}",
        after.as_secs()
    );
    assert!(!h.log[n..].iter().any(|(_, a)| is_freq(a)), "nothing fed");
    h.run(1300);
    assert!(
        h.status().last_offset.is_some_and(|o| near(o, 0.0)),
        "majority feeds again"
    );
}

#[test]
fn one_lost_majority_reply_with_a_falseticker_feeds_nothing() {
    // Defined behaviour: sources 1 and 2 read 0, source 3 reads +100 ms.
    // Source 1 loses one reply. The new samples are 2 and 3, which do not
    // agree, so that round feeds nothing. The tier stays usable and the
    // next full round feeds 0 again.
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let reply: Reply = Box::new(|s, t| {
        if s == id(3) {
            Ok(0.100)
        } else if s == id(1) && t == 640 {
            Err(QueryFailure::Timeout)
        } else {
            Ok(0.0)
        }
    });
    let specs = vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
        spec(3, Tier::Pool),
    ];
    let mut h = Harness::start_with(cfg, specs, reply);
    h.run(700);
    let fed = h.times(is_freq);
    assert!(fed.contains(&576) && !fed.contains(&640), "fed {fed:?}");
    assert_eq!(h.status().active_tier, Some(Tier::Pool));
    h.run(800);
    assert!(h.times(is_freq).contains(&704), "next full round feeds");
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.0)));
}

#[test]
fn one_lost_reply_among_agreeing_sources_still_feeds() {
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let reply: Reply = Box::new(|s, t| {
        if s == id(1) && t == 640 {
            Err(QueryFailure::Timeout)
        } else {
            Ok(0.002)
        }
    });
    let specs = vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
        spec(3, Tier::Pool),
    ];
    let mut h = Harness::start_with(cfg, specs, reply);
    h.run(700);
    assert!(h.times(is_freq).contains(&640), "{:?}", h.times(is_freq));
}

#[test]
fn start_step_with_zero_rtt_pool_reply() {
    // The pool reply lands at the very instant of the refusal's frequency
    // change. It must still count.
    let reply: Reply = Box::new(|s, t| {
        if s == id(1) {
            Ok(5.0)
        } else if t == 0 {
            Err(QueryFailure::Timeout)
        } else {
            Ok(5.05)
        }
    });
    let mut h = Harness::start(vec![spec(1, Tier::Config), spec(2, Tier::Pool)], reply);
    h.run(1000);
    assert_eq!(h.steps(), vec![128]);
}

#[test]
fn start_step_with_coarse_mono_ticks() {
    // A 15.6 ms Mono and a 5 ms pool reply: the reply carries the same
    // stamp as the frequency change.
    let reply: Reply = Box::new(|s, t| {
        if s == id(1) {
            Ok(5.0)
        } else if t == 0 {
            Err(QueryFailure::Timeout)
        } else {
            Ok(5.05)
        }
    });
    let mut h = Harness::new(EngineConfig::default(), reply);
    h.grid = Some(15_625_000);
    h.rtt = Duration::from_millis(5);
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Config),
        spec(2, Tier::Pool),
    ]));
    h.run(1000);
    let steps = h.steps();
    assert_eq!(steps.len(), 1, "steps {steps:?}");
    assert!(steps[0] <= 64 * 3, "step at {}", steps[0]);
}

#[test]
fn delay_spike_is_not_fed() {
    // 20 ms path with one 300 ms spike reading +50 ms. The spike must not
    // move the clock or teach drift.
    let reply: Reply = Box::new(|_, t| Ok(if t == 640 { 0.050 } else { 0.0 }));
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let mut h = Harness::new(cfg, reply);
    h.delay = Box::new(|_, t| if t == 640 { 0.300 } else { 0.020 });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(1000);
    assert!(!h.times(is_freq).contains(&640));
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.0)));
    assert!(h.status().drift.value().abs() < 1e-12);
    assert_eq!(h.status().active_tier, Some(Tier::Pool), "still usable");
}

#[test]
fn path_that_stays_slow_is_fed_after_eight_samples() {
    // From 640 s the path goes from 20 ms to 200 ms for good. The first
    // seven slow samples still sit beside fast ones and are spikes. The
    // eighth slow sample evicts the last fast one and is fed.
    let reply: Reply = Box::new(|_, t| Ok(if t >= 640 { 0.004 } else { 0.0 }));
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let mut h = Harness::new(cfg, reply);
    h.delay = Box::new(|_, t| if t >= 640 { 0.200 } else { 0.020 });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(2000);
    let fed: Vec<u64> = h.times(is_freq).into_iter().filter(|&t| t >= 640).collect();
    assert_eq!(fed.first(), Some(&(640 + 7 * 64)), "fed {fed:?}");
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.004)));
}

#[test]
fn lan_delay_bump_below_floor_is_fed() {
    // A 0.3 ms LAN path reads 2 ms once. That is over 3 x its best, but
    // under the 10 ms floor, so it is still fed.
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let mut h = Harness::new(cfg, steady(0.001));
    h.delay = Box::new(|_, t| if t == 640 { 0.002 } else { 0.0003 });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(700);
    assert!(h.times(is_freq).contains(&640), "{:?}", h.times(is_freq));
}

#[test]
fn first_slow_samples_of_a_source_are_fed() {
    // A 250 ms path from the start. With fewer than eight samples the best
    // is the source's own, so nothing is a spike.
    let mut h = Harness::new(EngineConfig::default(), steady(0.003));
    h.delay = Box::new(|_, _| 0.250);
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(200);
    let fed: Vec<u64> = h.times(is_freq).into_iter().filter(|&t| t > 0).collect();
    assert_eq!(fed[..2], [64, 128], "fed {fed:?}");
}

#[test]
fn source_turned_false_cannot_vote_with_its_old_good_sample() {
    // Reviewer probe. Two pool sources read 0 at 20 ms. From 704 s source 2
    // reads +100 ms at 25 ms, so its old 20 ms sample stays its best of
    // eight. Source 1 loses the 704 s reply. The loop must not move toward
    // source 2.
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let reply: Reply = Box::new(|s, t| {
        if s == id(1) && t == 704 {
            Err(QueryFailure::Timeout)
        } else if s == id(2) && t >= 704 {
            Ok(0.100)
        } else {
            Ok(0.0)
        }
    });
    let mut h = Harness::new(cfg, reply);
    h.delay = Box::new(|s, t| if s == id(2) && t >= 704 { 0.025 } else { 0.020 });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
    ]));
    h.run(4000);
    let late: Vec<f64> = h
        .log
        .iter()
        .filter(|(t, _)| *t >= 704)
        .filter_map(|(_, a)| match a {
            Action::SetFrequency(f) => Some(f.value()),
            _ => None,
        })
        .collect();
    assert!(
        late.iter().all(|f| f.abs() < 1.0),
        "slewed toward the falseticker: {late:?}"
    );
    assert!(
        h.status()
            .last_offset
            .is_some_and(|o| o.as_secs().abs() < 0.01)
    );
}

#[test]
fn source_turned_good_is_not_held_back_by_an_old_sample() {
    // Reviewer probe. Pool sources 1 and 3 read 0 at 20 ms. Source 2 reads
    // +25 ms at 40 ms, but at 20 ms every eighth poll. At 40 ms it agrees,
    // at 20 ms it does not. Its best of eight is the disagreeing 20 ms one,
    // yet most rounds must still feed the loop.
    let reply: Reply = Box::new(|s, _| Ok(if s == id(2) { 0.025 } else { 0.0 }));
    let cfg = EngineConfig {
        max_poll: Duration::from_secs(64),
        ..EngineConfig::default()
    };
    let mut h = Harness::new(cfg, reply);
    h.delay = Box::new(|s, t| {
        if s == id(2) && (t / 64) % 8 != 0 {
            0.040
        } else {
            0.020
        }
    });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![
        spec(1, Tier::Pool),
        spec(2, Tier::Pool),
        spec(3, Tier::Pool),
    ]));
    h.run(3600);
    let rounds = h.queries(1).iter().filter(|&&t| t >= 64).count();
    let fed = h.times(is_freq).iter().filter(|&&t| t >= 64).count();
    assert!(fed * 10 >= rounds * 9, "fed {fed} of {rounds} rounds");
}

#[test]
fn spike_starved_loop_polls_fast_until_the_slow_path_is_learned() {
    // The poll has reached 1024 s. Then the path turns from 20 ms to 200 ms
    // for good. Each round that feeds nothing because of a spike drops the
    // poll to 64 s, so the eighth slow sample comes 7 x 64 s after the
    // first, not 7 x 1024 s.
    let reply: Reply = Box::new(|_, t| Ok(if t >= 6000 { 0.004 } else { 0.001 }));
    let mut h = Harness::new(EngineConfig::default(), reply);
    h.delay = Box::new(|_, t| if t >= 6000 { 0.200 } else { 0.020 });
    h.feed(Event::AdjustmentAllowed(true));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(6000);
    assert_eq!(gaps(&h.queries(1)).last(), Some(&1024));
    h.run(12_000);
    let first_slow = *h
        .queries(1)
        .iter()
        .find(|&&t| t >= 6000)
        .expect("slow round");
    let fed = *h
        .times(is_freq)
        .iter()
        .find(|&&t| t >= 6000)
        .expect("fed again");
    assert!(
        fed - first_slow <= 8 * 64,
        "fed {} s after the first slow sample",
        fed - first_slow
    );
    assert!(h.status().last_offset.is_some_and(|o| near(o, 0.004)));
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

#[test]
fn reply_measured_before_a_step_is_dropped() {
    // R99. A config probe is in flight when a pool round steps the clock.
    // Its reply measured the clock before the step, so it must not count,
    // and its tier gets a fresh round. The config server never answers on
    // its own. A resume makes one more step allowed, and the pool reads
    // 0.5 s only while a config round is open, so the step lands then.
    let mut e = Engine::new(EngineConfig::default(), None);
    let mut now = at(1);
    let _ = e.handle(Event::Tick(now));
    let _ = e.handle(Event::AdjustmentAllowed(true));
    let specs = vec![
        spec(1, Tier::Config),
        spec(2, Tier::Pool),
        spec(3, Tier::Pool),
        spec(4, Tier::Pool),
    ];
    let mut queue: Vec<Action> = e.handle(Event::SourcesChanged(specs));
    let mut resumed = false;
    let mut stepped_with_probe_open = false;
    for _ in 0..500 {
        let mut stepped = false;
        while let Some(a) = queue.pop() {
            match a {
                Action::Query { source, .. } if source != id(1) => {
                    let off = if resumed && e.round_of(id(1)).is_some() {
                        0.5
                    } else {
                        0.0
                    };
                    queue.extend(e.handle(Event::Sample(sample(source, off, now))));
                }
                Action::Step(_) => stepped = true,
                _ => {}
            }
        }
        if stepped {
            stepped_with_probe_open = e.round_of(id(1)).is_some();
            break;
        }
        now = e.next_wake().expect("wake");
        if !resumed && secs(now) >= 600 {
            resumed = true;
            queue = e.handle(Event::Resumed(now));
        } else {
            queue = e.handle(Event::Tick(now));
        }
    }
    assert!(
        stepped_with_probe_open,
        "a step with the config probe in flight"
    );
    let mut acts = e.handle(Event::Sample(sample(id(1), 0.5, now)));
    assert!(
        e.sources[&id(1)].filter.best().is_none(),
        "pre-step reply kept"
    );
    acts.extend(e.handle(Event::Tick(e.next_wake().expect("wake"))));
    assert!(
        acts.iter()
            .any(|a| matches!(a, Action::Query { source, .. } if *source == id(1))),
        "fresh config round: {acts:?}"
    );
}
