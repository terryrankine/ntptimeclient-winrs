//! The simulated host, network and clock.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{Fault, Rng, ServerSpec, SimEvent, SimReport};
use crate::engine::{Action, Engine, Event};
use crate::{
    ClockError, Delay, KodCode, Mono, Offset, Ppm, QueryFailure, Sample, SourceId, SourceSpec,
};

/// The host's query timeout. The engine closes a round after 30 s and asks
/// for well under that.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// A send on a machine with no route fails almost at once.
const NO_ROUTE: Duration = Duration::from_millis(1);

/// How often the host re-checks `w32time` and re-sends the level. Author's
/// guess at a host poll. The engine must treat a repeat as a no-op.
const LEVEL_CHECK: Duration = Duration::from_secs(300);

/// Addresses come from 198.18.0.0/15, the benchmark range, so no real host
/// is named.
const ADDR_BASE: u32 = 0xC612_0000;

/// The hidden true clock. `err` is local minus true, in seconds, at `at`.
#[derive(Debug, Clone)]
struct TrueClock {
    err: f64,
    at: Mono,
    /// Rate the clock runs at after quantisation, in ppm.
    applied: f64,
    /// Rate the clock needs to keep true time, in ppm.
    need: f64,
    /// Clock commands fail while set.
    broken: bool,
}

impl TrueClock {
    /// Brings `err` up to `now`. A positive applied rate above the need
    /// makes the local clock gain.
    fn settle(&mut self, now: Mono) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.err += (self.applied - self.need) * 1e-6 * dt;
        self.at = self.at.max(now);
    }
}

/// What the host knows about adjustment.
#[derive(Debug, Clone, Copy, Default)]
struct Host {
    /// The adjustment level the host last sent.
    level: bool,
    /// A clock command failed and the host has not re-armed the engine.
    latched: bool,
}

#[derive(Debug, Clone)]
struct Server {
    label: String,
    spec: ServerSpec,
    id: SourceId,
}

/// A query in flight.
#[derive(Debug, Clone)]
struct Pending {
    at: Mono,
    seq: u64,
    sent: Mono,
    reply: Reply,
}

#[derive(Debug, Clone)]
enum Reply {
    /// A good reply. The reading is built on arrival, from the clock error
    /// at send and at arrival.
    Reading {
        source: SourceId,
        sent_err: f64,
        server_err: f64,
        out: f64,
        back: f64,
    },
    Failed(SourceId, QueryFailure),
}

/// Offset and delay a client computes from the four NTP timestamps.
///
/// With true send time `T1`: `t1 = T1 + e1`, `t2 = t3 = T1 + out + s`,
/// `t4 = T1 + out + back + e4`. Offset is `((t2 - t1) + (t3 - t4)) / 2` and
/// delay is `(t4 - t1) - (t3 - t2)`. `T1` cancels, so no true time is
/// needed.
fn reading(e1: f64, e4: f64, s: f64, out: f64, back: f64) -> (f64, f64) {
    let offset = s + (out - back) / 2.0 - f64::midpoint(e1, e4);
    let delay = out + back + e4 - e1;
    (offset, delay)
}

/// Rounds to a whole number of quanta, as the platform does.
fn quantise(ppm: f64, granularity: f64) -> f64 {
    if granularity > 0.0 {
        (ppm / granularity).round() * granularity
    } else {
        ppm
    }
}

fn later(at: Mono, by: Duration) -> Mono {
    at.checked_add(by).unwrap_or(Mono::from_nanos(u64::MAX))
}

fn later_secs(at: Mono, secs: f64) -> Mono {
    later(at, Duration::from_secs_f64(secs.max(0.0)))
}

/// The simulated world. See the module docs.
#[derive(Debug, Clone)]
pub struct SimWorld {
    rng: Rng,
    granularity: f64,
    clock: TrueClock,
    servers: Vec<Server>,
    /// Indexes of the servers the host lists.
    listed: Vec<usize>,
    started: bool,
    now: Mono,
    /// Latest time the engine has seen.
    seen: Mono,
    network_up: bool,
    host: Host,
    next_check: Mono,
    events: Vec<(Mono, u64, SimEvent)>,
    pending: Vec<Pending>,
    seq: u64,
    report: SimReport,
}

impl SimWorld {
    /// An empty world. The clock starts on time with no drift. Each applied
    /// frequency is rounded to `tick_granularity_ppm`. Zero or less turns
    /// rounding off.
    #[must_use]
    pub fn new(seed: u64, tick_granularity_ppm: f64) -> Self {
        Self {
            rng: Rng(seed),
            granularity: tick_granularity_ppm,
            clock: TrueClock {
                err: 0.0,
                at: Mono::from_nanos(0),
                applied: 0.0,
                need: 0.0,
                broken: false,
            },
            servers: Vec::new(),
            listed: Vec::new(),
            started: false,
            now: Mono::from_nanos(0),
            seen: Mono::from_nanos(0),
            network_up: true,
            host: Host::default(),
            next_check: Mono::from_nanos(0),
            events: Vec::new(),
            pending: Vec::new(),
            seq: 0,
            report: SimReport::default(),
        }
    }

    /// The rate the clock needs to keep true time. A clock that loses 20
    /// ppm needs +20 ppm.
    pub fn set_true_drift(&mut self, drift: Ppm) {
        self.clock.settle(self.now);
        self.clock.need = drift.value();
    }

    /// Sets the clock error now, local minus true, in seconds.
    pub fn set_clock_error(&mut self, secs: f64) {
        self.clock.settle(self.now);
        self.clock.err = secs;
    }

    /// The clock error now, local minus true, in seconds.
    #[must_use]
    pub fn error(&self) -> f64 {
        let mut c = self.clock.clone();
        c.settle(self.now);
        c.err
    }

    /// Virtual monotonic time now.
    #[must_use]
    pub fn now(&self) -> Mono {
        self.now
    }

    /// Puts a server on the network. Servers added before the first
    /// [`SimWorld::run`] are listed at start. Later ones are listed only by
    /// [`SimEvent::SourcesChanged`].
    ///
    /// # Panics
    /// If the label is taken, or past 100 000 servers.
    pub fn add_server(&mut self, label: &str, spec: ServerSpec) {
        assert!(
            self.servers.iter().all(|s| s.label != label),
            "server label {label} is taken"
        );
        let n = u32::try_from(self.servers.len() + 1).expect("server count fits u32");
        assert!(n < 100_000, "too many servers");
        self.servers.push(Server {
            label: label.to_string(),
            spec,
            id: SourceId::new(n),
        });
        if !self.started {
            self.listed.push(self.servers.len() - 1);
        }
    }

    /// Schedules an event at `at_secs` of virtual time. Events at the same
    /// time happen in the order scheduled. A time already past happens at
    /// the start of the next run.
    pub fn schedule(&mut self, at_secs: u64, ev: SimEvent) {
        let at = later(Mono::from_nanos(0), Duration::from_secs(at_secs));
        self.seq += 1;
        self.events.push((at, self.seq, ev));
    }

    /// Runs the world for `secs` more seconds of virtual time and reports
    /// on that stretch. The first run turns adjustment on and lists the
    /// servers, as a host does at start.
    ///
    /// # Panics
    /// If a [`SimEvent::SourcesChanged`] names an unknown server.
    pub fn run(&mut self, engine: &mut Engine, secs: u64) -> SimReport {
        let end = later(self.now, Duration::from_secs(secs));
        self.report = SimReport::default();
        self.track();
        if !self.started {
            self.started = true;
            self.host.level = true;
            self.feed(engine, Event::AdjustmentAllowed(self.host.level));
            let list = self.specs();
            self.feed(engine, Event::SourcesChanged(list));
            self.next_check = later(self.now, LEVEL_CHECK);
        }
        loop {
            let next_reply = self.pending.iter().map(|p| p.at).min();
            let next_event = self.events.iter().map(|e| e.0).min();
            let next_wake = engine.next_wake();
            let Some(t) = [next_reply, next_event, next_wake, Some(self.next_check)]
                .into_iter()
                .flatten()
                .min()
            else {
                break;
            };
            if t > end {
                break;
            }
            self.advance(t);
            if next_reply.is_some_and(|r| r <= self.now) {
                self.deliver(engine);
            } else if next_event.is_some_and(|e| e <= self.now) {
                self.apply_event(engine);
            } else if self.next_check <= self.now {
                self.next_check = later(self.now, LEVEL_CHECK);
                self.feed(engine, Event::AdjustmentAllowed(self.host.level));
            } else {
                self.feed(engine, Event::Tick(self.now));
            }
        }
        self.advance(end);
        self.report.final_error = self.clock.err;
        std::mem::take(&mut self.report)
    }

    fn advance(&mut self, t: Mono) {
        self.now = self.now.max(t);
        self.clock.settle(self.now);
        self.track();
    }

    fn track(&mut self) {
        let e = self.clock.err.abs();
        if e > self.report.max_abs_error {
            self.report.max_abs_error = e;
        }
    }

    fn specs(&self) -> Vec<SourceSpec> {
        self.listed
            .iter()
            .map(|&i| {
                let s = &self.servers[i];
                SourceSpec {
                    id: s.id,
                    tier: s.spec.tier,
                    addr: SocketAddr::new(Ipv4Addr::from(ADDR_BASE + s.id.get()).into(), 123),
                    label: s.label.clone(),
                }
            })
            .collect()
    }

    fn server(&self, id: SourceId) -> Option<&Server> {
        self.servers.iter().find(|s| s.id == id)
    }

    /// Hands one event to the engine and performs its actions, as the host
    /// contract asks.
    fn feed(&mut self, engine: &mut Engine, ev: Event) {
        let timeless = !matches!(ev, Event::Tick(_) | Event::Sample(_) | Event::Resumed(_));
        // `Failed` and the others carry no time. The engine stamps them with
        // the latest time it has seen, so it must see now first.
        if timeless && self.seen < self.now {
            self.feed(engine, Event::Tick(self.now));
        }
        match &ev {
            Event::Tick(t) | Event::Resumed(t) => self.seen = self.seen.max(*t),
            Event::Sample(s) => self.seen = self.seen.max(s.at),
            _ => {}
        }
        let actions = engine.handle(ev);
        let mut results = Vec::new();
        // Host contract: after the first failure the rest of the batch's
        // clock actions are not performed.
        let mut failed = false;
        for a in actions {
            let clock = matches!(a, Action::SetFrequency(_) | Action::Step(_));
            if clock && failed {
                self.report.skipped_after_failure += 1;
                continue;
            }
            if clock {
                self.clock_command();
                if self.clock.broken {
                    failed = true;
                    self.host.latched = true;
                    self.report.clock_failures += 1;
                    results.push(Err(ClockError::Rejected("simulated failure".into())));
                    continue;
                }
            }
            match a {
                Action::Query { source, .. } => self.send(source),
                Action::SetFrequency(f) => {
                    self.clock.settle(self.now);
                    self.clock.applied = quantise(f.value(), self.granularity);
                    let size = self.clock.applied.abs();
                    if size > self.report.max_abs_frequency {
                        self.report.max_abs_frequency = size;
                    }
                    results.push(Ok(()));
                }
                Action::Step(o) => {
                    self.clock.settle(self.now);
                    self.clock.err += o.as_secs();
                    self.report.steps.push((self.now, o));
                    self.track();
                    results.push(Ok(()));
                }
                Action::SaveDrift(p) => self.report.saved_drift = Some(p),
                Action::Log(l) => self.report.logs.push((self.now, l)),
            }
        }
        // Results in action order, after the batch.
        for r in results {
            self.feed(engine, Event::ClockResult(r));
        }
    }

    fn clock_command(&mut self) {
        self.report.clock_commands += 1;
        // After a failure the engine must stay silent until re-armed, even
        // while the host keeps sending `true`.
        if !self.host.level || self.host.latched {
            self.report.commands_while_disabled += 1;
        }
    }

    fn push(&mut self, at: Mono, reply: Reply) {
        self.seq += 1;
        self.pending.push(Pending {
            at,
            seq: self.seq,
            sent: self.now,
            reply,
        });
    }

    fn send(&mut self, id: SourceId) {
        let Some(server) = self.server(id).cloned() else {
            // The engine only asks for listed sources. Answer anyway, as the
            // contract asks for exactly one answer per query.
            self.push(
                later(self.now, NO_ROUTE),
                Reply::Failed(id, QueryFailure::Unreachable),
            );
            return;
        };
        *self.report.queries.entry(server.label).or_default() += 1;
        let spec = server.spec;
        let timeout = later(self.now, QUERY_TIMEOUT);
        if !self.network_up {
            let at = later(self.now, NO_ROUTE);
            self.push(at, Reply::Failed(id, QueryFailure::Unreachable));
            return;
        }
        let kod = |code| Reply::Failed(id, QueryFailure::KissOfDeath(code));
        let mut server_err = spec.offset;
        match spec.fault {
            Fault::Unreachable => {
                self.push(timeout, Reply::Failed(id, QueryFailure::Timeout));
                return;
            }
            Fault::KodDeny => {
                self.push(later_secs(self.now, spec.delay), kod(KodCode::Deny));
                return;
            }
            Fault::KodRate => {
                self.push(later_secs(self.now, spec.delay), kod(KodCode::Rate));
                return;
            }
            Fault::Falseticker(o) => server_err += o.as_secs(),
            Fault::None => {}
        }
        if self.rng.unit() < spec.loss_rate {
            self.push(timeout, Reply::Failed(id, QueryFailure::Timeout));
            return;
        }
        let out = f64::midpoint(spec.delay, spec.asymmetry) + spec.jitter * self.rng.unit();
        let back = (spec.delay - spec.asymmetry) / 2.0 + spec.jitter * self.rng.unit();
        let (out, back) = (out.max(0.0), back.max(0.0));
        let at = later_secs(self.now, out + back);
        let sent_err = self.clock.err;
        self.push(
            at,
            Reply::Reading {
                source: id,
                sent_err,
                server_err,
                out,
                back,
            },
        );
    }

    /// Delivers the earliest reply that is due.
    fn deliver(&mut self, engine: &mut Engine) {
        let Some(i) = self
            .pending
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| (p.at, p.seq))
            .map(|(i, _)| i)
        else {
            return;
        };
        let p = self.pending.remove(i);
        match p.reply {
            Reply::Failed(id, why) => self.feed(engine, Event::Failed(id, why)),
            Reply::Reading {
                source,
                sent_err,
                server_err,
                out,
                back,
            } => {
                let (offset, delay) = reading(sent_err, self.clock.err, server_err, out, back);
                let s = Sample {
                    source,
                    offset: Offset::from_secs(offset),
                    delay: Delay::from_secs(delay),
                    stratum: 2,
                    unsynchronised: false,
                    leap_alarm: false,
                    at: self.now,
                };
                self.feed(engine, Event::Sample(s));
            }
        }
    }

    /// Replies in flight are lost. Each query still gets its timeout.
    fn lose_in_flight(&mut self) {
        for p in &mut self.pending {
            if let Reply::Reading { source, .. } = p.reply {
                p.reply = Reply::Failed(source, QueryFailure::Timeout);
                p.at = later(p.sent, QUERY_TIMEOUT).max(self.now);
            }
        }
    }

    fn apply_event(&mut self, engine: &mut Engine) {
        let Some(i) = self
            .events
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| (e.0, e.1))
            .map(|(i, _)| i)
        else {
            return;
        };
        let (_, _, ev) = self.events.remove(i);
        match ev {
            SimEvent::Resume(jump) => {
                self.clock.err += jump.as_secs();
                self.track();
                self.lose_in_flight();
                self.feed(engine, Event::Resumed(self.now));
                // The host checks `w32time` again after a wake.
                self.feed(engine, Event::AdjustmentAllowed(self.host.level));
            }
            SimEvent::SourcesChanged(labels) => {
                self.listed = labels
                    .iter()
                    .map(|l| {
                        self.servers
                            .iter()
                            .position(|s| &s.label == l)
                            .unwrap_or_else(|| panic!("unknown server {l}"))
                    })
                    .collect();
                let specs = self.specs();
                self.feed(engine, Event::SourcesChanged(specs));
            }
            SimEvent::NetworkDown => {
                self.network_up = false;
                self.lose_in_flight();
            }
            SimEvent::NetworkUp => self.network_up = true,
            SimEvent::ExternalStep(o) => {
                self.clock.err += o.as_secs();
                self.track();
            }
            SimEvent::W32TimeStarted => {
                self.clock.applied = 0.0;
                self.host.level = false;
                self.feed(engine, Event::AdjustmentAllowed(false));
            }
            SimEvent::W32TimeStopped => {
                self.host.level = true;
                self.feed(engine, Event::AdjustmentAllowed(true));
            }
            SimEvent::SetDrift(p) => self.clock.need = p.value(),
            SimEvent::ClockFails(yes) => self.clock.broken = yes,
            SimEvent::HostRearm => {
                self.host.latched = false;
                self.feed(engine, Event::AdjustmentAllowed(false));
                self.feed(engine, Event::AdjustmentAllowed(self.host.level));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;

    #[test]
    fn reading_of_symmetric_path_is_the_server_error() {
        // Clock 0.3 s ahead, server exact, 10 ms each way.
        let (o, d) = reading(0.3, 0.3, 0.0, 0.010, 0.010);
        assert!((o + 0.3).abs() < 1e-12);
        assert!((d - 0.020).abs() < 1e-12);
    }

    #[test]
    fn asymmetry_reads_as_half_its_size() {
        let (o, d) = reading(0.0, 0.0, 0.0, 0.030, 0.010);
        assert!((o - 0.010).abs() < 1e-12);
        assert!((d - 0.040).abs() < 1e-12);
    }

    #[test]
    fn clock_moving_in_flight_shows_in_offset_and_delay() {
        // The clock gains 2 ms during the round trip.
        let (o, d) = reading(0.0, 0.002, 0.0, 0.010, 0.010);
        assert!((o + 0.001).abs() < 1e-12);
        assert!((d - 0.022).abs() < 1e-12);
    }

    #[test]
    fn quantise_rounds_to_nearest_quantum() {
        assert!((quantise(20.0, 6.4) - 19.2).abs() < 1e-9);
        assert!((quantise(23.0, 6.4) - 25.6).abs() < 1e-9);
        assert!((quantise(-3.3, 6.4) + 6.4).abs() < 1e-9);
        assert!((quantise(20.0, 0.0) - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn free_running_clock_drifts_at_its_need() {
        let mut w = SimWorld::new(1, 0.0);
        w.set_true_drift(Ppm::new(10.0));
        let mut e = Engine::new(EngineConfig::default(), None);
        // No servers: the engine never steers, so the clock loses 10 ppm.
        let r = w.run(&mut e, 1000);
        assert!((r.final_error + 0.010).abs() < 1e-9, "{}", r.final_error);
        assert!((w.error() + 0.010).abs() < 1e-9);
        assert_eq!(w.now(), Mono::from_nanos(1000 * 1_000_000_000));
    }

    #[test]
    fn every_query_gets_one_answer() {
        let mut w = SimWorld::new(3, 0.0);
        for (label, fault) in [
            ("ok", Fault::None),
            ("deny", Fault::KodDeny),
            ("dead", Fault::Unreachable),
        ] {
            w.add_server(
                label,
                ServerSpec {
                    fault,
                    loss_rate: 0.5,
                    ..ServerSpec::default()
                },
            );
        }
        let mut e = Engine::new(EngineConfig::default(), None);
        let _ = w.run(&mut e, 3600);
        w.schedule(3600, SimEvent::NetworkDown);
        w.schedule(4000, SimEvent::Resume(Offset::from_secs(1.0)));
        let _ = w.run(&mut e, 3600);
        // Anything still pending is due within the timeout.
        let limit = later(w.now(), QUERY_TIMEOUT);
        assert!(w.pending.iter().all(|p| p.at <= limit));
    }

    #[test]
    #[should_panic(expected = "unknown server")]
    fn unknown_label_panics() {
        let mut w = SimWorld::new(1, 0.0);
        w.schedule(0, SimEvent::SourcesChanged(vec!["nope".into()]));
        let mut e = Engine::new(EngineConfig::default(), None);
        let _ = w.run(&mut e, 10);
    }
}
