//! Scripted tests for the engine.

use super::*;
use crate::Delay;
use std::cell::Cell;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;

type Reply = Box<dyn FnMut(SourceId, u64) -> Result<f64, QueryFailure>>;

fn at(secs: u64) -> Mono {
    Mono::from_nanos(secs * 1_000_000_000)
}

fn secs(m: Mono) -> u64 {
    m.as_nanos() / 1_000_000_000
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

fn sample(source: SourceId, offset: f64, t: Mono) -> Sample {
    Sample {
        source,
        offset: Offset::from_secs(offset),
        delay: Delay::from_secs(0.010),
        stratum: 2,
        unsynchronised: false,
        leap_alarm: false,
        at: t,
    }
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

/// Feeds events and answers every query at once through `reply`.
struct Harness {
    e: Engine,
    now: Mono,
    reply: Reply,
    log: Vec<(u64, Action)>,
}

impl Harness {
    fn new(cfg: EngineConfig, reply: Reply) -> Self {
        Self {
            e: Engine::new(cfg, None),
            now: at(0),
            reply,
            log: Vec::new(),
        }
    }

    fn start(specs: Vec<SourceSpec>, reply: Reply) -> Self {
        Self::start_with(EngineConfig::default(), specs, reply)
    }

    fn start_with(cfg: EngineConfig, specs: Vec<SourceSpec>, reply: Reply) -> Self {
        let mut h = Self::new(cfg, reply);
        h.feed(Event::SourcesChanged(specs));
        h
    }

    fn feed(&mut self, ev: Event) -> Vec<Action> {
        let mut queue = VecDeque::from([ev]);
        let mut all = Vec::new();
        while let Some(ev) = queue.pop_front() {
            for a in self.e.handle(ev) {
                if let Action::Query { source, .. } = a {
                    queue.push_back(match (self.reply)(source, secs(self.now)) {
                        Ok(o) => Event::Sample(sample(source, o, self.now)),
                        Err(f) => Event::Failed(source, f),
                    });
                }
                self.log.push((secs(self.now), a.clone()));
                all.push(a);
            }
        }
        all
    }

    fn run(&mut self, until: u64) {
        loop {
            let t = self.e.next_wake().expect("engine gives a wake time");
            if secs(t) > until {
                return;
            }
            assert!(t > self.now, "next_wake must move forward");
            self.now = t;
            self.feed(Event::Tick(t));
        }
    }

    fn queries(&self, n: u32) -> Vec<u64> {
        self.log
            .iter()
            .filter(|(_, a)| matches!(a, Action::Query { source, .. } if *source == id(n)))
            .map(|(t, _)| *t)
            .collect()
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

    fn status(&self) -> EngineStatus {
        self.e.status()
    }
}

fn touches_clock(a: &Action) -> bool {
    matches!(a, Action::Step(_) | Action::SetFrequency(_))
}

fn gaps(t: &[u64]) -> Vec<u64> {
    t.windows(2).map(|w| w[1] - w[0]).collect()
}

fn refused(l: &LogEvent, want: f64) -> bool {
    matches!(l, LogEvent::StepRefused { offset } if near(*offset, want))
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
    // Rounds run every 64 s. The source waits twice that.
    assert_eq!(h.queries(1), vec![0, 128, 256]);
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
        h.run(3700);
        let q = h.queries(1);
        assert_eq!(q[0], 0);
        assert!(
            (3600..3664).contains(&q[1]),
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
    let gone_at = secs(h.now);
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Dhcp)]));
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
    let specs = vec![spec(1, Tier::Config), spec(2, Tier::Dhcp)];
    let mut h = Harness::start(specs.clone(), timeout());
    h.feed(Event::SourcesChanged(specs));
    let diff = LogEvent::DhcpDiffersFromConfig {
        dhcp_only: vec![id(2)],
        config_only: vec![id(1)],
    };
    let count = |h: &Harness| {
        let logs = h.logs();
        logs.iter()
            .filter(|(_, l)| matches!(l, LogEvent::DhcpDiffersFromConfig { .. }))
            .count()
    };
    assert!(h.logs().iter().any(|(_, l)| *l == diff));
    assert_eq!(count(&h), 1, "logged once per difference");
    let mut same = spec(3, Tier::Dhcp);
    same.addr = addr(1);
    let mut h = Harness::start(vec![spec(1, Tier::Config), same], timeout());
    h.run(100);
    assert_eq!(count(&h), 0);
}

#[test]
fn no_actions_that_touch_clock_when_adjustment_disallowed() {
    let mut h = Harness::new(EngineConfig::default(), steady(5.0));
    h.feed(Event::AdjustmentAllowed(false));
    h.feed(Event::SourcesChanged(vec![spec(1, Tier::Pool)]));
    h.run(3600);
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
    h.run(4000);
    assert!(!h.log[n..].iter().any(|(_, a)| touches_clock(a)));
    assert!(!h.status().adjustment_allowed);
    assert!(
        h.feed(Event::ClockResult(Ok(())))
            .iter()
            .all(|a| !touches_clock(a))
    );
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
    // The first round only starts the loop. The second teaches drift.
    let saves = h.times(|a| matches!(a, Action::SaveDrift(_)));
    assert_eq!(saves, vec![100, 700, 1300]);
}

fn config_and_pool(config: f64, pool: Result<f64, QueryFailure>) -> Harness {
    let reply: Reply = Box::new(move |s, _| if s == id(1) { Ok(config) } else { pool });
    let mut h = Harness::start(vec![spec(1, Tier::Config), spec(2, Tier::Pool)], reply);
    h.run(3600);
    assert_eq!(h.status().active_tier, Some(Tier::Config));
    h
}

#[test]
fn refuses_step_when_pool_cross_check_disagrees() {
    let h = config_and_pool(5.0, Ok(0.0));
    assert_eq!(h.times(|a| matches!(a, Action::Step(_))), Vec::<u64>::new());
    let refused_after_pool = h
        .logs()
        .iter()
        .filter(|(t, l)| *t > 0 && refused(l, 5.0))
        .count();
    assert!(refused_after_pool > 0);
    assert!(h.times(|a| matches!(a, Action::SetFrequency(_))).len() > 3);
}

#[test]
fn allows_step_when_pool_cross_check_agrees() {
    let h = config_and_pool(5.0, Ok(5.05));
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
    assert!(
        h.log[i + 1..]
            .iter()
            .any(|(_, a)| matches!(a, Action::SetFrequency(_)))
    );
    assert!(
        h.logs()
            .iter()
            .any(|(_, l)| matches!(l, LogEvent::StepTaken { offset } if near(*offset, 5.0)))
    );
}

#[test]
fn slews_only_when_no_pool_cross_check_sample_exists_yet() {
    let h = config_and_pool(5.0, Err(QueryFailure::Timeout));
    assert_eq!(h.times(|a| matches!(a, Action::Step(_))), Vec::<u64>::new());
    assert!(
        h.logs()
            .iter()
            .all(|(_, l)| !matches!(l, LogEvent::StepRefused { .. }) || refused(l, 5.0))
    );
    assert!(h.logs().iter().filter(|(_, l)| refused(l, 5.0)).count() > 3);
    assert!(
        h.log
            .iter()
            .any(|(_, a)| matches!(a, Action::SetFrequency(f) if f.value() > 100.0))
    );
}

#[test]
fn resumed_allows_one_step() {
    let offset = Rc::new(Cell::new(0.001));
    let o = Rc::clone(&offset);
    let mut h = Harness::start(vec![spec(1, Tier::Pool)], Box::new(move |_, _| Ok(o.get())));
    h.run(300);
    offset.set(5.0);
    h.run(1500);
    assert!(
        h.times(|a| matches!(a, Action::Step(_))).is_empty(),
        "no step after the first sync"
    );
    h.feed(Event::Resumed(h.now));
    h.run(4000);
    let steps = h.times(|a| matches!(a, Action::Step(_)));
    assert_eq!(steps.len(), 1);
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
fn selection_never_uses_non_active_tier_samples() {
    let h = config_and_pool(0.010, Ok(0.100));
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
    h.feed(Event::AdjustmentAllowed(false));
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
    assert!(e.status().last_offset.is_some_and(|o| near(o, 0.002)));
    let acts = e.handle(Event::Tick(at(64)));
    assert!(
        !acts
            .iter()
            .any(|a| matches!(a, Action::Query { source, .. } if *source == id(2)))
    );
}

#[test]
fn out_of_order_time_does_not_panic() {
    let mut e = Engine::new(EngineConfig::default(), Some(Ppm::new(3.0)));
    let events = [
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
    let acts = e.handle(Event::Tick(at(0)));
    assert_eq!(acts.first(), Some(&Action::SetFrequency(Ppm::new(12.5))));
    assert_eq!(e.status().drift, Ppm::new(12.5));
}
