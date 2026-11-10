//! The loop state and one turn of the loop.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ntpc_core::engine::{Action, Engine, Event};
use ntpc_core::{Mono, Offset, Ppm, QueryFailure, SourceId, SourceSpec, Tier};

use super::dhcp::DhcpSchedule;
use super::inflight::InFlight;
use super::startup::{load_drift, log_start, secure_state_dir, start_dhcp_reader};
use super::{
    AdapterKey, ClockControl, DriftFile, HostDeps, HostResolver, Inbox, Inner, LEVEL_PERIOD, Msg,
    NetworkEvents, PowerEvents, QUERY_TIMEOUT, QUERY_WATCHDOG, REARM_FIRST, REARM_MAX,
    RESOLVE_GIVE_UP, STATUS_PERIOD, ServiceMonitor, SharedLookup, SharedOwn, Spawn, Waiter,
};
use crate::config::Config;
use crate::logging::{Level, Logger, engine_event};
use crate::resolver::Resolver;
use crate::status::{Blocked, Counters, StatusReport, StatusWriter};
use crate::transport::{TimeSource, Transport};

/// Lookup workers given up and still stuck before no new one starts. Each
/// is a thread blocked in the system resolver.
const MAX_ABANDONED_LOOKUPS: usize = 3;

/// True when the engine must see a `Tick(now)` before `ev`. The contract
/// asks for one before an event without a time when time has moved. A
/// `ClockResult` is not such an event: it belongs to the batch that made
/// the action, and a tick in between could run new clock actions before
/// the engine hears of a failure, or pair a result with the wrong action.
///
/// `AdjustmentAllowed(false)` gets none either. It must close the gate
/// before anything else runs: a tick first could run clock actions after
/// the host has seen w32time running. The engine stamps the close with the
/// last time it saw, at most one loop turn old, which only dates the zero
/// slew it records.
fn needs_tick(ev: &Event, fed: Option<Mono>, now: Mono) -> bool {
    let timeless = matches!(
        ev,
        Event::Failed(..) | Event::SourcesChanged(_) | Event::AdjustmentAllowed(true)
    );
    timeless && fed.is_none_or(|f| f < now)
}

/// Name of every query worker thread.
const QUERY_THREAD: &str = "ntpc-query";
/// Name of the lookup worker thread.
const RESOLVE_THREAD: &str = "ntpc-resolve";

fn later(at: Mono, by: Duration) -> Mono {
    at.checked_add(by).unwrap_or(Mono::from_nanos(u64::MAX))
}

struct DhcpReader {
    requests: Sender<BTreeSet<AdapterKey>>,
    schedule: DhcpSchedule,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent loop flags, each read in one place"
)]
pub(super) struct Host {
    cfg: Config,
    engine: Engine,
    clock: Box<dyn ClockControl>,
    transport: Arc<dyn Transport>,
    drift: Box<dyn DriftFile>,
    status: Box<dyn StatusWriter>,
    monitor: Box<dyn ServiceMonitor>,
    network: Box<dyn NetworkEvents>,
    power: Box<dyn PowerEvents>,
    logger: Arc<dyn Logger>,
    time: Arc<dyn TimeSource>,
    spawn: Arc<dyn Spawn>,
    waiter: Box<dyn Waiter>,
    inbox: Inbox,
    tx: Sender<Msg>,

    lookup: SharedLookup,
    own: SharedOwn,
    resolver: Arc<Mutex<HostResolver>>,
    generation: u64,
    resolving_since: Option<Mono>,
    /// Generations whose lookup worker was given up and has not returned.
    abandoned: BTreeSet<u64>,
    /// New lookups are held back because too many are stuck.
    lookups_held: bool,
    resolve_force: bool,
    last_resolved: Option<Mono>,

    specs: Vec<SourceSpec>,
    addrs: BTreeMap<SourceId, (SocketAddr, String)>,
    in_flight: InFlight,

    dhcp: Option<DhcpReader>,
    dhcp_servers: Vec<Ipv4Addr>,

    persistence: bool,
    /// Latest time the engine has been given.
    fed: Option<Mono>,
    level: bool,
    checked: bool,
    w32time_running: bool,
    /// A clock command failed and the engine has not been re-armed.
    latched: bool,
    rearm_at: Option<Mono>,
    failures_in_row: u32,
    next_level: Mono,
    next_status: Mono,
    started_at: Mono,
    stopping: bool,
    /// `take_rate_control` succeeded. Then stop resets the rate.
    rate_taken: bool,
    /// A hand-back to w32time failed and is retried (R102).
    reset_pending: bool,
    last_saved_drift: Option<Ppm>,
    last_step: Option<(i128, f64)>,
    counters: Counters,
}

impl Host {
    pub(super) fn start(cfg: Config, deps: HostDeps, inbox: Inbox) -> Self {
        let HostDeps {
            clock,
            transport,
            drift,
            status,
            lookup,
            own,
            monitor,
            network,
            power,
            dhcp,
            state_dir,
            join,
            logger,
            time,
            spawn,
            waiter,
        } = deps;
        let now = time.mono();
        let lookup = SharedLookup(lookup);
        let own = SharedOwn(own);
        let tx = inbox.sender();

        log_start(&cfg, &*join, &*logger);
        let persistence = secure_state_dir(&*state_dir, &*logger);
        let loaded = if persistence {
            load_drift(&*drift, &*logger)
        } else {
            None
        };
        let engine = Engine::new(cfg.engine_config(), loaded);

        let dhcp_reader = if cfg.dhcp {
            start_dhcp_reader(dhcp, tx.clone(), &*logger).map(|requests| DhcpReader {
                requests,
                schedule: DhcpSchedule::new(now),
            })
        } else {
            None
        };

        let resolver = Arc::new(Mutex::new(Resolver::new(lookup.clone(), own.clone())));
        let mut host = Self {
            cfg,
            engine,
            clock,
            transport,
            drift,
            status,
            monitor,
            network,
            power,
            logger,
            time,
            spawn,
            waiter,
            inbox,
            tx,
            lookup,
            own,
            resolver,
            generation: 0,
            resolving_since: None,
            abandoned: BTreeSet::new(),
            lookups_held: false,
            resolve_force: true,
            last_resolved: None,
            specs: Vec::new(),
            addrs: BTreeMap::new(),
            in_flight: InFlight::default(),
            dhcp: dhcp_reader,
            dhcp_servers: Vec::new(),
            persistence,
            fed: None,
            level: false,
            checked: false,
            w32time_running: false,
            latched: false,
            rearm_at: None,
            failures_in_row: 0,
            next_level: now,
            next_status: now,
            started_at: now,
            stopping: false,
            rate_taken: false,
            reset_pending: false,
            last_saved_drift: loaded,
            last_step: None,
            counters: Counters::default(),
        };

        // R34: adjustment starts off. The first check below may enable it.
        // The clock rate is taken only then, so a running w32time is never
        // touched.
        host.send_level(false);
        host
    }

    fn log(&self, level: Level, kind: &'static str, msg: &str) {
        self.logger.log(level, kind, msg);
    }

    /// One loop turn. False when the loop must stop.
    pub(super) fn turn(&mut self) -> bool {
        let now = self.time.mono();
        self.poll_events(now);
        self.run_timers(now);
        let deadline = self.deadline(now);
        let outstanding = self.outstanding();
        let msg = self.waiter.wait(&self.inbox, deadline, outstanding);
        match msg {
            Some(Msg(Inner::Shutdown)) => false,
            Some(Msg(inner)) => {
                self.on_message(inner);
                true
            }
            None => true,
        }
    }

    fn outstanding(&self) -> usize {
        self.in_flight.len()
            + usize::from(self.resolving_since.is_some())
            + usize::from(self.dhcp.as_ref().is_some_and(|d| d.schedule.busy()))
    }

    fn poll_events(&mut self, now: Mono) {
        if self.power.resumed() {
            self.log(Level::Info, "resumed", "the machine resumed from sleep");
            self.feed(Event::Resumed(now));
            // The host checks `w32time` again after a wake, as the sim does.
            self.check_level(now);
        }
        if self.network.changed(Duration::ZERO) {
            if let Some(d) = self.dhcp.as_mut() {
                d.schedule.on_signal(now);
            }
            // R66: a network change ends the resolver's back-off.
            self.resolve_force = true;
        }
    }

    fn run_timers(&mut self, now: Mono) {
        if now >= self.next_level {
            self.check_level(now);
        }
        self.run_watchdog(now);
        self.maybe_resolve(now);
        self.maybe_read_dhcp(now);
        if self.engine.next_wake().is_some_and(|w| w <= now) {
            self.feed(Event::Tick(now));
        }
        if now >= self.next_status {
            self.next_status = later(now, STATUS_PERIOD);
            self.logger.flush();
            self.write_status(now, true);
        }
    }

    fn deadline(&self, now: Mono) -> Mono {
        let mut d = vec![
            Some(self.next_level),
            Some(self.next_status),
            self.engine.next_wake(),
        ];
        d.push(self.in_flight.next_expiry(QUERY_WATCHDOG));
        d.push(
            self.resolving_since
                .and_then(|t| t.checked_add(RESOLVE_GIVE_UP)),
        );
        d.push(self.dhcp.as_ref().and_then(|r| r.schedule.due_at()));
        let next = d
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(later(now, LEVEL_PERIOD));
        // Work due now was done in this turn. A deadline at or before now
        // would spin.
        next.max(later(now, Duration::from_millis(1)))
    }

    // ------------------------------------------------------------ engine

    /// Feeds one event and performs its actions, as the engine contract asks.
    fn feed(&mut self, ev: Event) {
        let now = self.time.mono();
        if needs_tick(&ev, self.fed, now) {
            self.feed(Event::Tick(now));
        }
        match &ev {
            Event::Tick(t) | Event::Resumed(t) => {
                self.fed = Some(self.fed.map_or(*t, |f| f.max(*t)));
            }
            Event::Sample(s) => self.fed = Some(self.fed.map_or(s.at, |f| f.max(s.at))),
            _ => {}
        }
        let actions = self.engine.handle(ev);
        let mut results = Vec::new();
        // Answers the host gives itself (a query it could not start). They
        // go in after this batch's clock results, never in the middle.
        let mut later_events = Vec::new();
        let mut failed = false;
        for action in actions {
            match action {
                Action::SetFrequency(_) | Action::Step(_) if failed => {}
                Action::SetFrequency(f) => {
                    let r = self.clock.set_frequency(f);
                    failed = self.clock_outcome(r.is_err());
                    results.push(r);
                }
                Action::Step(o) => {
                    let r = self.clock.step(o);
                    failed = self.clock_outcome(r.is_err());
                    if r.is_ok() {
                        self.note_step(o);
                    }
                    results.push(r);
                }
                Action::Query { source, .. } => later_events.extend(self.start_query(source)),
                Action::SaveDrift(p) => self.save_drift(p),
                Action::Log(e) => {
                    let addrs = &self.addrs;
                    let label = |id: SourceId| match addrs.get(&id) {
                        Some((_, l)) => format!("source {} ({l})", id.get()),
                        None => format!("source {}", id.get()),
                    };
                    let (level, kind, msg) = engine_event(&e, &label);
                    self.logger.log(level, kind, &msg);
                }
            }
        }
        for r in results {
            self.feed(Event::ClockResult(r));
        }
        for ev in later_events {
            self.feed(ev);
        }
    }

    /// Counts a clock command. Returns whether it failed.
    fn clock_outcome(&mut self, failed: bool) -> bool {
        self.counters.clock_commands += 1;
        if failed {
            self.counters.clock_failures += 1;
            self.failures_in_row = self.failures_in_row.saturating_add(1);
            let shift = self.failures_in_row.saturating_sub(1).min(16);
            let wait = REARM_FIRST.saturating_mul(1 << shift).min(REARM_MAX);
            self.latched = true;
            self.rearm_at = Some(later(self.time.mono(), wait));
        } else {
            self.failures_in_row = 0;
        }
        failed
    }

    fn note_step(&mut self, o: Offset) {
        self.counters.steps += 1;
        self.last_step = Some((self.time.wall_ns(), o.as_secs()));
    }

    fn save_drift(&mut self, p: Ppm) {
        if !self.persistence {
            return;
        }
        match self.drift.save(p) {
            Ok(()) => {
                self.counters.drift_saves += 1;
                self.last_saved_drift = Some(p);
            }
            Err(e) => {
                self.counters.drift_save_failures += 1;
                self.log(Level::Warn, "drift_save", &format!("drift not saved: {e}"));
            }
        }
    }

    fn send_level(&mut self, allowed: bool) {
        self.level = allowed;
        self.feed(Event::AdjustmentAllowed(allowed));
    }

    /// Resets the rate for w32time. On failure the reset stays pending.
    fn hand_back(&mut self) {
        match self.clock.reset_frequency() {
            Ok(()) => {
                self.reset_pending = false;
                self.log(
                    Level::Info,
                    "rate_control",
                    "w32time runs: clock rate handed back to the system",
                );
            }
            Err(e) => {
                self.reset_pending = true;
                self.counters.clock_failures += 1;
                // Rate limited by kind, so a reset that keeps failing
                // every 30 s cannot fill the log.
                self.log(
                    Level::Error,
                    "rate_control",
                    &format!(
                        "w32time runs: could not hand the clock rate back: {e}. Retrying in {} s",
                        LEVEL_PERIOD.as_secs()
                    ),
                );
            }
        }
    }

    /// Asks the monitor, re-sends the level and re-arms after a failure.
    fn check_level(&mut self, now: Mono) {
        self.next_level = later(now, LEVEL_PERIOD);
        let running = self.monitor.is_running();
        let first = !self.checked;
        self.checked = true;
        if running {
            if !self.w32time_running || first {
                self.log(
                    Level::Warn,
                    "w32time",
                    "w32time runs or its state cannot be read. Clock adjustment stays off",
                );
            }
            self.w32time_running = true;
            // A false also clears the engine's failure latch. The next true
            // after w32time stops opens adjustment.
            self.latched = false;
            self.send_level(false);
            // R98: hand the rate back at once, so our last frequency with
            // the OS kept out does not stay in force under w32time. The
            // next enable takes it again. Stop then leaves it alone. R102:
            // a failed hand-back is retried at every check while w32time
            // runs.
            if self.rate_taken || self.reset_pending {
                self.rate_taken = false;
                self.hand_back();
            }
            return;
        }
        if self.w32time_running {
            self.log(Level::Info, "w32time", "w32time stopped");
        }
        self.w32time_running = false;
        let rearm_due = self.rearm_at.is_some_and(|t| now >= t);
        if !self.rate_taken {
            // A failed take waits out the same back-off as a failed command.
            if self.latched && !rearm_due {
                self.send_level(false);
                return;
            }
            // R71: nominal with the OS kept out, once, before the first
            // enable. Not at start: w32time may still own the clock then.
            match self.clock.take_rate_control() {
                Ok(()) => {
                    self.rate_taken = true;
                    // Taking the rate overrides a hand-back still pending.
                    self.reset_pending = false;
                    self.latched = false;
                    self.log(
                        Level::Info,
                        "rate_control",
                        "took the clock rate at nominal, with the OS kept out",
                    );
                }
                Err(e) => {
                    self.clock_outcome(true);
                    self.log(
                        Level::Error,
                        "rate_control",
                        &format!("could not take the clock rate: {e}. Adjustment stays off"),
                    );
                    self.send_level(false);
                    return;
                }
            }
        }
        if self.latched && rearm_due {
            self.log(
                Level::Info,
                "rearm",
                "re-arming clock adjustment after a clock failure",
            );
            self.latched = false;
            self.send_level(false);
        }
        // While latched, a re-sent true does not reopen adjustment (R39).
        self.send_level(true);
    }

    // ------------------------------------------------------------ queries

    /// Starts a query. Returns the event to feed if it could not start.
    fn start_query(&mut self, source: SourceId) -> Option<Event> {
        if self.stopping {
            return None;
        }
        let Some((addr, _)) = self.addrs.get(&source).cloned() else {
            // The engine only asks for listed sources. Answer anyway, the
            // contract wants one answer per query.
            self.counters.unreachable += 1;
            return Some(Event::Failed(source, QueryFailure::Unreachable));
        };
        let Some(ticket) = self.in_flight.begin(source, addr, self.time.mono()) else {
            // R15: the running query answers this one too.
            self.counters.duplicate_queries += 1;
            return None;
        };
        self.counters.queries += 1;
        let transport = Arc::clone(&self.transport);
        let tx = self.tx.clone();
        let job = Box::new(move || {
            let result = transport.query(source, addr, QUERY_TIMEOUT);
            let _ = tx.send(Msg(Inner::Query {
                source,
                ticket,
                result,
            }));
        });
        if !self.spawn.spawn(QUERY_THREAD, job) {
            self.in_flight.abandon(source);
            self.counters.unreachable += 1;
            self.log(
                Level::Error,
                "spawn",
                "could not start a query thread. The query counts as unreachable",
            );
            return Some(Event::Failed(source, QueryFailure::Unreachable));
        }
        None
    }

    fn run_watchdog(&mut self, now: Mono) {
        for id in self.in_flight.take_expired(now, QUERY_WATCHDOG) {
            self.counters.timeouts += 1;
            self.log(
                Level::Warn,
                "watchdog",
                &format!(
                    "source {} query did not return in {} s. Counted as a timeout",
                    id.get(),
                    QUERY_WATCHDOG.as_secs()
                ),
            );
            self.feed(Event::Failed(id, QueryFailure::Timeout));
        }
    }

    fn on_query(
        &mut self,
        source: SourceId,
        ticket: u64,
        result: Result<ntpc_core::Sample, QueryFailure>,
    ) {
        // A late answer after the watchdog gave up is dropped.
        let Some(sent_to) = self.in_flight.finish(source, ticket) else {
            return;
        };
        // A fresh resolver restarts ids at 0, so this id may now name
        // another server. The answer ends its wait but is not a sample of
        // the server the id names now.
        if self.addrs.get(&source).is_some_and(|(a, _)| *a != sent_to) {
            self.feed(Event::Failed(source, QueryFailure::Timeout));
            return;
        }
        match result {
            Ok(s) => {
                self.counters.samples += 1;
                self.feed(Event::Sample(s));
            }
            Err(why) => {
                match why {
                    QueryFailure::Timeout => self.counters.timeouts += 1,
                    QueryFailure::KissOfDeath(_) => self.counters.kiss_of_death += 1,
                    QueryFailure::Unreachable => self.counters.unreachable += 1,
                    QueryFailure::Malformed => self.counters.malformed += 1,
                }
                self.feed(Event::Failed(source, why));
            }
        }
    }

    // ------------------------------------------------------------ DHCP

    fn maybe_read_dhcp(&mut self, now: Mono) {
        if self.stopping {
            return;
        }
        let Some(d) = self.dhcp.as_mut() else {
            return;
        };
        if d.schedule.due_at().is_none_or(|t| t > now) {
            return;
        }
        let skip = d.schedule.start(now);
        if d.requests.send(skip).is_err() {
            // The reader thread is gone. No more DHCP for this run.
            self.dhcp = None;
            self.log(
                Level::Error,
                "dhcp",
                "the DHCP reader stopped. DHCP servers are no longer read",
            );
        }
    }

    fn on_dhcp(&mut self, result: Result<super::DhcpRead, super::DhcpReadError>) {
        if let Some(d) = self.dhcp.as_mut() {
            d.schedule.finish(&result);
        }
        match result {
            Ok(read) => {
                let mut servers = read.servers;
                servers.sort_unstable();
                servers.dedup();
                if servers != self.dhcp_servers {
                    let list: Vec<String> = servers.iter().map(ToString::to_string).collect();
                    self.log(
                        Level::Info,
                        "dhcp",
                        &format!("DHCP offers NTP servers [{}]", list.join(", ")),
                    );
                    self.dhcp_servers = servers;
                    self.resolve_force = true;
                }
            }
            Err(e) => {
                self.counters.dhcp_read_failures += 1;
                self.log(
                    Level::Warn,
                    "dhcp",
                    &format!("DHCP read failed: {e}. The last list is kept"),
                );
            }
        }
    }

    fn on_message(&mut self, inner: Inner) {
        match inner {
            Inner::Shutdown | Inner::Wake => {}
            Inner::Query {
                source,
                ticket,
                result,
            } => self.on_query(source, ticket, result),
            Inner::Resolved {
                generation,
                specs,
                notes,
            } => self.on_resolved(generation, specs, notes),
            Inner::ResolveFailed { generation } => self.on_resolve_failed(generation),
            Inner::Dhcp(result) => self.on_dhcp(result),
        }
    }

    // ------------------------------------------------------------ status

    fn blocked(&self, allowed: bool) -> Blocked {
        if allowed {
            Blocked::None
        } else if !self.checked || self.stopping {
            Blocked::Starting
        } else if self.w32time_running {
            Blocked::W32Time
        } else if self.latched {
            Blocked::ClockFailure
        } else {
            Blocked::Starting
        }
    }

    fn report(&self, now: Mono, running: bool) -> StatusReport {
        let es = self.engine.status();
        let tier_count = |t: Tier| self.specs.iter().filter(|s| s.tier == t).count() as u64;
        let tier_addrs = |t: Tier| -> BTreeSet<SocketAddr> {
            self.specs
                .iter()
                .filter(|s| s.tier == t)
                .map(|s| s.addr)
                .collect()
        };
        let (config, dhcp) = (tier_addrs(Tier::Config), tier_addrs(Tier::Dhcp));
        let stats = self.transport.stats();
        let mut counters = self.counters;
        counters.nonce_failures = stats.nonce_failures;
        counters.datagrams_discarded = stats.discarded;
        counters.icmp_resets = stats.resets;
        counters.log_suppressed = self.logger.suppressed();
        let wall_s = |ns: i128| i64::try_from(ns.div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
        StatusReport {
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            written_unix_s: wall_s(self.time.wall_ns()),
            running,
            uptime_s: now.saturating_duration_since(self.started_at).as_secs(),
            active_tier: es.active_tier,
            last_offset_s: es.last_offset.map(Offset::as_secs),
            drift_ppm: es.drift.value(),
            last_good_age_s: es.last_good_age.map(|d| d.as_secs()),
            holdover: es.holdover,
            adjustment_allowed: es.adjustment_allowed,
            adjustment_blocked: self.blocked(es.adjustment_allowed),
            last_step_unix_s: self.last_step.map(|(t, _)| wall_s(t)),
            last_step_s: self.last_step.map(|(_, s)| s),
            persistence: self.persistence,
            sources_config: tier_count(Tier::Config),
            sources_dhcp: tier_count(Tier::Dhcp),
            sources_pool: tier_count(Tier::Pool),
            dhcp_differs: !config.is_empty() && !dhcp.is_empty() && config != dhcp,
            counters,
        }
    }

    fn write_status(&mut self, now: Mono, running: bool) {
        if !self.persistence {
            return;
        }
        let report = self.report(now, running);
        if let Err(e) = self.status.write(&report) {
            self.counters.status_write_failures += 1;
            self.log(
                Level::Warn,
                "status_write",
                &format!("status not written: {e}"),
            );
        }
    }

    // ------------------------------------------------------------ stop

    /// The stop sequence. The rate reset comes first, before any log line,
    /// so a log sink that panics cannot skip it. `panic` is the text of a
    /// loop panic, logged right after the reset.
    pub(super) fn shutdown(&mut self, panic: Option<&str>) {
        let now = self.time.mono();
        self.stopping = true;
        // R71: hand the rate back so w32time can take over. Skipped if it
        // was never taken and no hand-back is pending: then the clock is
        // not ours to touch.
        let reset = (self.rate_taken || self.reset_pending).then(|| self.clock.reset_frequency());
        if let Some(m) = panic {
            self.log(
                Level::Error,
                "panic",
                &format!("the host loop panicked: {m}. Stopping"),
            );
        }
        self.log(Level::Info, "stop", "stopping");
        match reset {
            None => {}
            Some(Ok(())) => self.log(Level::Info, "stop", "clock rate handed back to the system"),
            Some(Err(e)) => {
                self.counters.clock_failures += 1;
                self.log(
                    Level::Error,
                    "stop",
                    &format!("could not hand the clock rate back: {e}"),
                );
            }
        }
        let drift = self.engine.status().drift;
        // Saving an unchanged or never-learnt drift would turn "no saved
        // drift" into a saved zero.
        if self.persistence && self.last_saved_drift != Some(drift) && self.learnt(drift) {
            self.save_drift(drift);
        }
        self.write_status(now, false);
        // Dropping the request sender ends the DHCP reader after its current
        // read. It is not joined.
        self.dhcp = None;
        self.log(Level::Info, "stop", "stopped");
    }

    /// True unless the drift is still the zero a fresh engine starts with.
    fn learnt(&self, drift: Ppm) -> bool {
        self.last_saved_drift.is_some() || drift.value() != 0.0
    }
}

mod resolve;

#[cfg(test)]
mod tests {
    use super::*;
    use ntpc_core::ClockError;

    #[test]
    fn clock_result_never_gets_a_tick_first() {
        let then = Mono::from_nanos(10);
        let fed = Some(then);
        let now = Mono::from_nanos(11);
        assert!(!needs_tick(&Event::ClockResult(Ok(())), fed, now));
        assert!(!needs_tick(
            &Event::ClockResult(Err(ClockError::Unavailable)),
            fed,
            now
        ));
        assert!(needs_tick(
            &Event::Failed(SourceId::new(1), QueryFailure::Timeout),
            fed,
            now
        ));
        assert!(needs_tick(&Event::AdjustmentAllowed(true), fed, now));
        assert!(!needs_tick(&Event::AdjustmentAllowed(false), fed, now));
        assert!(!needs_tick(&Event::AdjustmentAllowed(true), fed, then));
        assert!(!needs_tick(&Event::Tick(now), fed, now));
    }
}
