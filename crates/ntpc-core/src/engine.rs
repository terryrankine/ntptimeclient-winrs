//! The engine. A pure state machine that turns events into actions.
//!
//! It owns the tier chooser, one filter per source, the clock discipline and
//! the poll timers. The host performs every action and reports back through
//! events. The engine reads no clock and draws no random numbers, so the
//! simulator can replay it exactly.
//!
//! Host contract:
//! - Answer every [`Action::Query`] with exactly one [`Event::Sample`] or
//!   [`Event::Failed`]. Time a query out in well under 30 s. The engine
//!   closes a round after 30 s and a later reply then counts for nothing.
//!   [`Event::Failed`] carries no time. The engine stamps it with the latest
//!   time it has seen, so send a [`Event::Tick`] first when time has moved.
//! - Report each clock action, in order, through [`Event::ClockResult`].
//!   Stop the rest of a batch's clock actions after the first failure.
//! - [`Event::AdjustmentAllowed`] is a level. Adjustment starts off. Send it
//!   at start and again whenever the `w32time` or domain-join state is
//!   checked. A failed clock command turns adjustment off and keeps it
//!   off. Sending `true` again does not turn it back on. Only
//!   `AdjustmentAllowed(false)` followed by `AdjustmentAllowed(true)` does.
//! - [`ClockError`] text reaches the log. It must not carry file paths.
//! - Send [`Event::Tick`] at [`Engine::next_wake`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use crate::discipline::{Correction, CrossCheck, Discipline, DisciplineConfig, MAX_HOLD};
use crate::filter::SourceFilter;
use crate::select::{Selection, SelectionConfig};
use crate::tier::{TierChooser, TierConfig};
use crate::{
    ClockError, KodCode, Mono, Offset, Ppm, QueryFailure, Sample, SourceId, SourceSpec, Tier,
};

/// Tuning for [`Engine`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EngineConfig {
    /// Selection inside one tier.
    pub selection: SelectionConfig,
    /// Tier choice and probing.
    pub tier: TierConfig,
    /// The clock loop.
    pub discipline: DisciplineConfig,
    /// Shortest poll interval. Default 64 s. Zero is treated as 1 s.
    pub min_poll: Duration,
    /// Longest poll interval. Default 1024 s. Never below `min_poll`.
    pub max_poll: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            selection: SelectionConfig::default(),
            tier: TierConfig::default(),
            discipline: DisciplineConfig::default(),
            min_poll: Duration::from_secs(64),
            max_poll: Duration::from_secs(1024),
        }
    }
}

/// Input from the host.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Time has passed. Send it at [`Engine::next_wake`].
    Tick(Mono),
    /// A source answered a query.
    Sample(Sample),
    /// A query gave no sample.
    Failed(SourceId, QueryFailure),
    /// The full list of sources. It replaces the previous list.
    SourcesChanged(Vec<SourceSpec>),
    /// The machine woke from sleep at this time.
    Resumed(Mono),
    /// Whether the engine may move the clock. The host sets it from the
    /// `w32time` monitor and the domain-join rule.
    AdjustmentAllowed(bool),
    /// The outcome of the last clock action.
    ClockResult(Result<(), ClockError>),
}

/// Output for the host.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Query one source.
    Query {
        /// The source to query.
        source: SourceId,
        /// True when the source's tier is not active as the query is sent:
        /// a probe, a pool cross-check, or any query while no tier is active.
        /// The reply never triggers a clock update. It may switch the tier.
        /// Once its tier is active a later round may still select it.
        observe_only: bool,
    },
    /// Set the clock frequency, absolute from nominal.
    SetFrequency(Ppm),
    /// Move the clock by this offset. A `SetFrequency` follows.
    Step(Offset),
    /// Save the learned drift.
    SaveDrift(Ppm),
    /// Write one log line.
    Log(LogEvent),
}

/// Why clock adjustment stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableReason {
    /// The host turned adjustment off.
    Host,
    /// A clock command failed.
    ClockFailed,
}

/// One log line.
///
/// Sources appear by id only. The host maps an id to its label. No variant
/// holds an address, so nothing about the local machine reaches the log.
#[derive(Debug, Clone, PartialEq)]
pub enum LogEvent {
    /// The active tier changed. `None` means no tier is working.
    TierChanged {
        /// The tier before.
        from: Option<Tier>,
        /// The tier now.
        to: Option<Tier>,
    },
    /// The active tier has one source. Only the pool cross-check guards it.
    SingleSourceTier {
        /// The active tier.
        tier: Tier,
        /// Its only source.
        source: SourceId,
    },
    /// DHCP offers servers that differ from the config file.
    DhcpDiffersFromConfig {
        /// DHCP sources whose address the config file does not list.
        dhcp_only: Vec<SourceId>,
        /// Config sources whose address DHCP does not offer.
        config_only: Vec<SourceId>,
    },
    /// A server sent a kiss-of-death.
    KissOfDeath {
        /// The source.
        source: SourceId,
        /// Its code.
        code: KodCode,
        /// For `DENY` and `RSTR` the silence. Otherwise the new shortest
        /// interval between queries of this source.
        wait: Duration,
    },
    /// The clock was stepped.
    StepTaken {
        /// The step.
        offset: Offset,
    },
    /// A step was needed and refused. The clock slews instead.
    StepRefused {
        /// The offset that was not stepped.
        offset: Offset,
    },
    /// The engine stopped adjusting the clock. It keeps measuring.
    AdjustmentDisabled {
        /// Why.
        reason: DisableReason,
    },
    /// The host allowed adjustment again.
    AdjustmentEnabled,
    /// A clock command failed.
    ClockCommandFailed {
        /// The error the host reported.
        error: ClockError,
    },
    /// No update arrived within the hold limit. The clock runs on the drift.
    HoldoverStarted {
        /// The frequency set for holdover.
        frequency: Ppm,
    },
}

/// A snapshot for `status.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineStatus {
    /// The tier selection uses.
    pub active_tier: Option<Tier>,
    /// The latest selected offset of the active tier.
    pub last_offset: Option<Offset>,
    /// The learned drift.
    pub drift: Ppm,
    /// Time since the latest update from a fresh sample.
    pub last_good_age: Option<Duration>,
    /// The clock runs on the drift alone.
    pub holdover: bool,
    /// The engine may move the clock.
    pub adjustment_allowed: bool,
}

/// Highest priority first. The index of a tier in this list is its slot.
const TIERS: [Tier; 3] = [Tier::Config, Tier::Dhcp, Tier::Pool];

/// Global Constraints: `DENY` and `RSTR` silence a source for one hour.
const KOD_QUIET: Duration = Duration::from_secs(3600);

/// Longest interval `RATE` can push a source to. A server that keeps asking
/// is still heard from once a day.
const KOD_RATE_MAX: Duration = Duration::from_secs(24 * 3600);

/// Fewer writes to the drift store. A lost save costs at most ten minutes of
/// learning.
const DRIFT_SAVE_EVERY: Duration = Duration::from_secs(600);

/// A round still open after this long is closed. A lost reply must not stall
/// its tier, because a tier runs one round at a time.
const ROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Smallest offset movement that counts as jitter. A LAN path can give an
/// error bound well under a millisecond, while Windows timestamps and
/// scheduling still move a reading by a few milliseconds. Below this floor
/// that noise would pin the poll at its minimum.
const JITTER_FLOOR: Duration = Duration::from_millis(5);

/// A new sample this many times slower than the source's best of its last
/// eight is a delay spike. Queuing on such a path skews the offset, and the
/// skew is not symmetric, so the loop must not follow it.
pub(super) const POPCORN_RATIO: f64 = 3.0;

/// Below this delay a spike is ignored. A LAN path at 0.3 ms that reads 1 ms
/// once is still far better than any internet path, and its offset error is
/// bounded by half that delay.
pub(super) const POPCORN_FLOOR: Duration = Duration::from_millis(10);

const PPM_PER_UNIT: f64 = 1e-6;

fn slot(tier: Tier) -> usize {
    match tier {
        Tier::Config => 0,
        Tier::Dhcp => 1,
        Tier::Pool => 2,
    }
}

/// `at + by`, held at the end of time instead of overflowing.
fn later(at: Mono, by: Duration) -> Mono {
    at.checked_add(by).unwrap_or(Mono::from_nanos(u64::MAX))
}

/// What the engine keeps about one source.
#[derive(Debug, Clone)]
struct Source {
    spec: SourceSpec,
    filter: SourceFilter,
    /// Set by `DENY` and `RSTR`. No query before this time.
    quiet_until: Option<Mono>,
    /// Raised by `RATE`. Shortest gap between two queries of this source.
    rate_floor: Duration,
    last_query: Option<Mono>,
    prev_query: Option<Mono>,
    /// Time of the last sample of this source that the loop considered.
    /// Only later samples may feed it again.
    fed_until: Option<Mono>,
}

impl Source {
    fn new(spec: SourceSpec) -> Self {
        Self {
            spec,
            filter: SourceFilter::new(),
            quiet_until: None,
            rate_floor: Duration::ZERO,
            last_query: None,
            prev_query: None,
            fed_until: None,
        }
    }

    fn may_query(&self, now: Mono) -> bool {
        self.quiet_until.is_none_or(|q| now >= q)
            && self
                .last_query
                .is_none_or(|q| now.saturating_duration_since(q) >= self.rate_floor)
    }
}

/// Who may move the clock. The host's wish is a level. A clock failure is a
/// latch that only a host `false` clears, so a re-sent `true` cannot retry a
/// command that just failed.
#[derive(Debug, Clone, Copy, Default)]
struct Gate {
    host: bool,
    failed: bool,
}

impl Gate {
    fn open(self) -> bool {
        self.host && !self.failed
    }
}

/// Whether the last step reached the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepState {
    Idle,
    /// A step was sent. The next clock result is its outcome.
    Awaiting,
    /// The step failed. A re-enable allows one more.
    Failed,
}

/// The NTP client engine.
#[derive(Debug, Clone)]
pub struct Engine {
    cfg: EngineConfig,
    tiers: TierChooser,
    discipline: Discipline,
    sources: BTreeMap<SourceId, Source>,
    rounds: [Option<Round>; 3],
    last_round: [Option<Mono>; 3],
    /// When each tier was last observed. The chooser measures its reprobe
    /// interval from here, so `next_wake` must too.
    last_observed: [Option<Mono>; 3],
    /// Start a round of this tier at the next chance.
    recheck: [bool; 3],
    /// Tiers that failed since the idle poll last doubled.
    idle_failed: [bool; 3],
    /// Latest time seen. It never goes back.
    now: Mono,
    started: bool,
    /// Poll interval of the active tier, or of every tier while none is.
    poll: Duration,
    /// Previous selected offset and when it was taken.
    prev_offset: Option<(Offset, Mono)>,
    gate: Gate,
    step: StepState,
    /// A frequency the host has not been sent yet.
    pending_frequency: Option<Ppm>,
    /// Slew part of the frequency over time. Zero while the clock is not
    /// steered.
    steer: Steer,
    /// When the frequency last changed. Samples from before it measured a
    /// clock that has moved since, so they cannot decide a step.
    freq_changed_at: Option<Mono>,
    /// When the loop last set the frequency. Starts the `MAX_HOLD` window.
    held_since: Option<Mono>,
    holdover: bool,
    /// Set while the loop refuses steps, so the refusal logs once.
    refusing: Option<Mono>,
    last_offset: Option<Offset>,
    last_good: Option<Mono>,
    saved_drift: Ppm,
    saved_at: Option<Mono>,
    resumed_at: Option<Mono>,
    single_logged: Option<(Tier, SourceId)>,
    dhcp_logged: Option<(Vec<SourceId>, Vec<SourceId>)>,
}

impl Engine {
    /// A new engine. `drift` is the saved drift, if any. Adjustment starts
    /// off. `AdjustmentAllowed(true)` sets the frequency to the drift.
    #[must_use]
    pub fn new(mut cfg: EngineConfig, drift: Option<Ppm>) -> Self {
        // A zero poll would query without pause.
        cfg.min_poll = cfg.min_poll.max(Duration::from_secs(1));
        cfg.max_poll = cfg.max_poll.max(cfg.min_poll);
        let discipline = Discipline::new(cfg.discipline, drift);
        let saved_drift = discipline.drift();
        Self {
            tiers: TierChooser::new(cfg.tier),
            discipline,
            sources: BTreeMap::new(),
            rounds: [None, None, None],
            last_round: [None; 3],
            last_observed: [None; 3],
            recheck: [false; 3],
            idle_failed: [false; 3],
            now: Mono::from_nanos(0),
            started: false,
            poll: cfg.min_poll,
            prev_offset: None,
            gate: Gate::default(),
            step: StepState::Idle,
            pending_frequency: None,
            steer: Steer::default(),
            freq_changed_at: None,
            held_since: None,
            holdover: false,
            refusing: None,
            last_offset: None,
            last_good: None,
            saved_drift,
            saved_at: None,
            resumed_at: None,
            single_logged: None,
            dhcp_logged: None,
            cfg,
        }
    }

    /// Takes one event and returns the actions to perform, in order.
    #[must_use]
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        let mut out = Vec::new();
        self.started = true;
        match ev {
            Event::Tick(at) => {
                self.advance(at);
                // A probed tier can turn stable between observations.
                let before = self.tiers.active();
                self.tiers.tick(self.now);
                self.note_tier_change(before, &mut out);
            }
            Event::Sample(s) => self.on_sample(s, &mut out),
            Event::Failed(id, why) => self.on_failed(id, why, &mut out),
            Event::SourcesChanged(specs) => self.on_sources(specs, &mut out),
            Event::Resumed(at) => self.on_resumed(at),
            Event::AdjustmentAllowed(yes) => {
                // A host `false` also clears a clock failure. That is how
                // the host re-arms the engine.
                let failed = self.gate.failed && yes;
                let gate = Gate { host: yes, failed };
                self.set_gate(gate, DisableReason::Host, &mut out);
            }
            Event::ClockResult(result) => self.on_clock_result(result, &mut out),
        }
        self.maintain(&mut out);
        out
    }

    /// When the host should send the next [`Event::Tick`]. Always later than
    /// the latest time seen, once the first event is handled. `None` only
    /// when time cannot advance any more.
    #[must_use]
    pub fn next_wake(&self) -> Option<Mono> {
        let now = self.now;
        if !self.started {
            return Some(now);
        }
        let reprobe = self.cfg.tier.reprobe_every;
        let mut wake: Vec<Option<Mono>> = vec![now.checked_add(self.cfg.max_poll)];
        for round in self.rounds.iter().flatten() {
            wake.push(round.started.checked_add(ROUND_TIMEOUT));
        }
        match self.tiers.active() {
            None => wake.extend(TIERS.map(|t| self.due_at(t, self.poll))),
            Some(active) => {
                wake.push(self.due_at(active, self.poll));
                let probe = self.tiers.due_probe(now);
                for t in TIERS.into_iter().filter(|&t| t < active) {
                    if probe == Some(t) {
                        wake.push(self.due_at(t, self.cfg.min_poll));
                    } else if self.rounds[slot(t)].is_none() {
                        // Same clock as `due_probe`: the last observation.
                        let seen = self.last_observed[slot(t)];
                        wake.push(seen.map_or(Some(now), |s| s.checked_add(reprobe)));
                    }
                }
                if active != Tier::Pool {
                    wake.push(self.due_at(Tier::Pool, reprobe));
                }
            }
        }
        if self.gate.open() {
            wake.push(self.held_since.and_then(|t| t.checked_add(MAX_HOLD)));
        }
        if self.discipline.drift() != self.saved_drift {
            wake.push(
                self.saved_at
                    .map_or(Some(now), |t| t.checked_add(DRIFT_SAVE_EVERY)),
            );
        }
        // The last event did all work due by now. A time at or before now is
        // work the engine may not start yet, such as a probe of a lower
        // priority tier.
        wake.into_iter().flatten().filter(|&t| t > now).min()
    }

    /// A snapshot of the engine state.
    #[must_use]
    pub fn status(&self) -> EngineStatus {
        EngineStatus {
            active_tier: self.tiers.active(),
            last_offset: self.last_offset,
            drift: self.discipline.drift(),
            last_good_age: self
                .last_good
                .map(|t| self.now.saturating_duration_since(t)),
            holdover: self.holdover,
            adjustment_allowed: self.gate.open(),
        }
    }

    fn advance(&mut self, at: Mono) {
        self.now = self.now.max(at);
    }

    fn on_sample(&mut self, s: Sample, out: &mut Vec<Action>) {
        self.advance(s.at);
        if !self.sources.contains_key(&s.source) {
            return;
        }
        // A reply measured across a sleep holds the suspend error.
        let stale = self.resumed_at.is_some_and(|r| s.at < r)
            || self.round_of(s.source).is_some_and(|r| r.stale);
        if !stale && let Some(src) = self.sources.get_mut(&s.source) {
            src.filter.push(s);
        }
        // Dropped or kept, the reply ends its wait.
        self.answered(s.source, out);
    }

    fn on_failed(&mut self, id: SourceId, why: QueryFailure, out: &mut Vec<Action>) {
        let Some(tier) = self.sources.get(&id).map(|s| s.spec.tier) else {
            return;
        };
        let scheduled = self.interval_of(tier);
        if let QueryFailure::KissOfDeath(code) = why
            && let Some(src) = self.sources.get_mut(&id)
        {
            let wait = match code {
                KodCode::Deny | KodCode::Rstr => {
                    src.quiet_until = Some(later(self.now, KOD_QUIET));
                    KOD_QUIET
                }
                // An unknown code is treated as RATE. Slowing down is the
                // safe answer to a server that complains.
                KodCode::Rate | KodCode::Other => {
                    // The source's own last interval. A probe or a cross-check
                    // runs slower than the engine poll.
                    let own = match (src.prev_query, src.last_query) {
                        (Some(p), Some(l)) => l.saturating_duration_since(p),
                        _ => scheduled,
                    };
                    let doubled = own.max(src.rate_floor).saturating_mul(2);
                    src.rate_floor = doubled.min(KOD_RATE_MAX);
                    src.rate_floor
                }
            };
            out.push(Action::Log(LogEvent::KissOfDeath {
                source: id,
                code,
                wait,
            }));
        }
        self.answered(id, out);
    }

    /// The interval at which the engine queries a tier now.
    fn interval_of(&self, tier: Tier) -> Duration {
        match self.tiers.active() {
            None => self.poll,
            Some(a) if a == tier => self.poll,
            // Below the active tier only the pool cross-check runs.
            Some(a) if tier > a => self.cfg.tier.reprobe_every,
            Some(_) => self.cfg.min_poll,
        }
    }

    fn on_sources(&mut self, specs: Vec<SourceSpec>, out: &mut Vec<Action>) {
        let mut old = std::mem::take(&mut self.sources);
        let mut changed = [false; 3];
        let mut kept = BTreeSet::new();
        for spec in specs {
            let src = match old.remove(&spec.id) {
                // Same server, so its samples and back-off still hold.
                Some(o) if o.spec.tier == spec.tier && o.spec.addr == spec.addr => {
                    kept.insert(spec.id);
                    Source { spec, ..o }
                }
                prev => {
                    if let Some(p) = prev {
                        changed[slot(p.spec.tier)] = true;
                    }
                    kept.remove(&spec.id);
                    changed[slot(spec.tier)] = true;
                    Source::new(spec)
                }
            };
            self.sources.insert(src.spec.id, src);
        }
        for o in old.values() {
            changed[slot(o.spec.tier)] = true;
        }
        for t in TIERS {
            let Some(round) = self.rounds[slot(t)].as_mut() else {
                continue;
            };
            // A reply for a removed or replaced source must not count.
            round.waiting.retain(|w| kept.contains(w));
            if round.waiting.is_empty() {
                self.close_round(t, out);
            }
        }
        for t in TIERS {
            self.recheck[slot(t)] |= changed[slot(t)];
        }
        if self.tiers.active().is_none_or(|a| changed[slot(a)]) {
            self.poll = self.cfg.min_poll;
        }
        self.log_dhcp_difference(out);
    }

    fn on_resumed(&mut self, at: Mono) {
        self.advance(at);
        self.discipline.note_resume();
        self.resumed_at = Some(self.now);
        // The monotonic clock stood still in sleep, so old samples look
        // fresh but hold the offset from before it.
        for src in self.sources.values_mut() {
            src.filter = SourceFilter::new();
        }
        // Open rounds stay open so their replies still end a wait. Their
        // samples are dropped and a new round follows each one.
        for round in self.rounds.iter_mut().flatten() {
            round.stale = true;
        }
        self.last_round = [None; 3];
        self.recheck = [true; 3];
        self.poll = self.cfg.min_poll;
        self.prev_offset = None;
        // A refusal after the resume is a new episode and is logged.
        self.refusing = None;
    }

    fn on_clock_result(&mut self, result: Result<(), ClockError>, out: &mut Vec<Action>) {
        // Only the result right after a step is its outcome. A later result
        // in the same batch must not clear a failed step. Only a re-enable
        // clears it.
        if self.step == StepState::Awaiting {
            self.step = if result.is_ok() {
                StepState::Idle
            } else {
                StepState::Failed
            };
        }
        let Err(error) = result else {
            return;
        };
        out.push(Action::Log(LogEvent::ClockCommandFailed { error }));
        let gate = Gate {
            failed: true,
            ..self.gate
        };
        self.set_gate(gate, DisableReason::ClockFailed, out);
    }

    fn set_gate(&mut self, gate: Gate, reason: DisableReason, out: &mut Vec<Action>) {
        let was = self.gate.open();
        self.gate = gate;
        match (was, gate.open()) {
            (true, false) => {
                // Ruling R52. After a failed command the OS keeps its last
                // rate, so the history keeps the last slew. Any other close
                // hands the clock over (w32time, domain rule), so the
                // engine no longer knows the rate and records none.
                if reason != DisableReason::ClockFailed {
                    self.set_slew(0.0);
                }
                out.push(Action::Log(LogEvent::AdjustmentDisabled { reason }));
            }
            (false, true) => {
                // The loop did not steer the clock meanwhile. Start from the
                // learned drift, not from a stale phase term.
                let f = self.free_run();
                self.change_frequency(f);
                self.held_since = None;
                if self.step == StepState::Failed {
                    // The step never reached the clock. Allow it again.
                    self.discipline.note_resume();
                    self.step = StepState::Idle;
                }
                self.refusing = None;
                out.push(Action::Log(LogEvent::AdjustmentEnabled));
            }
            _ => {}
        }
    }

    /// Work that follows any event: timeouts, new rounds, holdover, drift
    /// saves, logs and the pending frequency.
    fn maintain(&mut self, out: &mut Vec<Action>) {
        for t in TIERS {
            let expired = self.rounds[slot(t)]
                .as_ref()
                .is_some_and(|r| self.now.saturating_duration_since(r.started) >= ROUND_TIMEOUT);
            if expired {
                self.close_round(t, out);
            }
        }
        self.schedule(out);
        self.check_hold(out);
        self.save_drift(out);
        self.log_single_source(out);
        if self.gate.open() {
            out.extend(self.pending_frequency.take().map(Action::SetFrequency));
        }
    }

    fn note_tier_change(&mut self, before: Option<Tier>, out: &mut Vec<Action>) {
        let after = self.tiers.active();
        if after != before {
            out.push(Action::Log(LogEvent::TierChanged {
                from: before,
                to: after,
            }));
            self.poll = self.cfg.min_poll;
            self.prev_offset = None;
            self.idle_failed = [false; 3];
        }
    }

    /// Pool samples taken since the last frequency change and within
    /// `reprobe_every`. Older ones measured a clock that has moved since.
    fn cross_check(&self, tier: Tier) -> CrossCheck {
        if tier == Tier::Pool {
            return CrossCheck::NotRequired;
        }
        let cap = self.cfg.selection.max_age.min(self.cfg.tier.reprobe_every);
        // Inclusive of the change instant. A reply stamped at that instant
        // measured the clock just as the new frequency took over, so the
        // change has added no phase error to it yet. A coarse Mono (15.6 ms
        // ticks) or a fast LAN pool often gives exactly that stamp. A strict
        // window would drop it and stall a start step.
        //
        // The pool reading may be up to one poll older than the reading it
        // is compared with. While a step is refused the poll is `min_poll`
        // and the clock slews at up to `max_slew` in between. At 500 ppm
        // that is 0.5 ms per second, so with the default 128 ms step
        // threshold the drift between the two readings stays under half the
        // threshold only while `min_poll` is at most 128 s. Task 10 config
        // must enforce that.
        let age = self.freq_changed_at.map_or(cap, |changed| {
            self.now.saturating_duration_since(changed).min(cap)
        });
        // Pool servers that cannot agree give no answer, so the step waits.
        self.select_in(Tier::Pool, age)
            .map_or(CrossCheck::Pending, |s| CrossCheck::Offset(s.offset))
    }

    /// The sample age limit that keeps only samples taken strictly after
    /// `since`, capped at `cap`. `None` when no such sample can exist yet.
    fn window(&self, since: Option<Mono>, cap: Duration) -> Option<Duration> {
        let Some(t) = since else {
            return Some(cap);
        };
        // `best_fresh` keeps ages up to the limit. One nanosecond less keeps
        // a sample taken at `t` out.
        self.now
            .saturating_duration_since(t)
            .checked_sub(Duration::from_nanos(1))
            .map(|age| age.min(cap))
    }

    fn update(&mut self, tier: Tier, sel: &Selection, out: &mut Vec<Action>) {
        // `Discipline` returns `Correction::None` for this. Nothing about it
        // is a measurement.
        if !sel.offset.as_secs().is_finite() {
            return;
        }
        self.adapt_poll(sel);
        self.last_offset = Some(sel.offset);
        self.last_good = Some(self.now);
        self.holdover = false;
        // Measure only. The loop would learn from offsets it never corrects.
        if !self.gate.open() {
            return;
        }
        let cross = self.cross_check(tier);
        match self.discipline.update(sel, cross, self.now) {
            Correction::None => {}
            Correction::SetFrequency(f) => {
                self.refusing = None;
                self.set_frequency(f);
            }
            Correction::Step { offset, frequency } => {
                out.push(Action::Step(offset));
                out.push(Action::Log(LogEvent::StepTaken { offset }));
                self.step = StepState::Awaiting;
                self.refusing = None;
                self.set_frequency(frequency);
                // Every stored sample predates the step and is now wrong by it.
                for src in self.sources.values_mut() {
                    src.filter = SourceFilter::new();
                }
                self.prev_offset = None;
            }
            Correction::RefuseStep { offset, frequency } => {
                if self.refusing.is_none() {
                    out.push(Action::Log(LogEvent::StepRefused { offset }));
                }
                self.refusing = Some(self.now);
                self.set_frequency(frequency);
                // A panic refusal stands whatever the pool says.
                let dcfg = &self.cfg.discipline;
                let panic = offset.as_secs().abs() > dcfg.panic_threshold.as_secs_f64()
                    && !dcfg.allow_panic_step;
                // A missing, stale or disagreeing reading: ask again, so a
                // pool that comes to agree is seen within a poll.
                if cross != CrossCheck::NotRequired && !panic {
                    self.ask_pool_now();
                }
            }
        }
    }

    /// A step waits on the pool. Ask it now rather than at
    /// `reprobe_every`, at most once per poll interval.
    fn ask_pool_now(&mut self) {
        let i = slot(Tier::Pool);
        let recent =
            self.last_round[i].is_some_and(|l| self.now.saturating_duration_since(l) < self.poll);
        if self.tiers.active() != Some(Tier::Pool) && !recent {
            self.recheck[i] = true;
        }
    }

    /// Poll fast while the offset moves more than its error bound explains.
    /// Double the interval while it holds still. The slew the engine applied
    /// since the last reading is expected movement, not jitter.
    fn adapt_poll(&mut self, sel: &Selection) {
        let x = sel.offset.as_secs();
        let big = x.abs() > self.cfg.discipline.step_threshold.as_secs_f64();
        let limit = sel.error_bound.max(JITTER_FLOOR).as_secs_f64();
        // A reading the slew history no longer covers cannot be brought to
        // now, so it says nothing about jitter. The history reaches back at
        // least `max_age` and always to the previous update at the longest
        // poll, whose gap is 1024 s plus the round trip.
        if self
            .prev_offset
            .is_some_and(|(_, at)| !self.steer.covers(at))
        {
            self.prev_offset = None;
        }
        let jumpy = self.prev_offset.is_some_and(|(prev, at)| {
            // A positive slew closes a positive offset.
            let expected = prev.as_secs() - self.steer.since(at, self.now);
            (x - expected).abs() > limit
        });
        if big || jumpy {
            self.poll = self.cfg.min_poll;
        } else if self.prev_offset.is_some() {
            self.poll = self.poll.saturating_mul(2).min(self.cfg.max_poll);
        }
        self.prev_offset = Some((sel.offset, self.now));
    }

    fn change_frequency(&mut self, f: Ppm) {
        self.pending_frequency = Some(f);
        self.freq_changed_at = Some(self.now);
        // The drift part only holds the clock's own error. The rest moves
        // the offset.
        self.set_slew(f.value() - self.discipline.drift().value());
    }

    fn set_frequency(&mut self, f: Ppm) {
        self.change_frequency(f);
        self.held_since = Some(self.now);
    }

    fn free_run(&mut self) -> Ppm {
        match self.discipline.free_run(self.now) {
            Correction::SetFrequency(f) => f,
            _ => self.discipline.drift(),
        }
    }

    fn check_hold(&mut self, out: &mut Vec<Action>) {
        let expired = self
            .held_since
            .is_some_and(|t| self.now.saturating_duration_since(t) >= MAX_HOLD);
        if !self.gate.open() || !expired {
            return;
        }
        let frequency = self.free_run();
        self.change_frequency(frequency);
        self.held_since = None;
        self.holdover = true;
        out.push(Action::Log(LogEvent::HoldoverStarted { frequency }));
    }

    fn save_drift(&mut self, out: &mut Vec<Action>) {
        let drift = self.discipline.drift();
        let too_soon = self
            .saved_at
            .is_some_and(|t| self.now.saturating_duration_since(t) < DRIFT_SAVE_EVERY);
        if drift == self.saved_drift || too_soon {
            return;
        }
        out.push(Action::SaveDrift(drift));
        self.saved_drift = drift;
        self.saved_at = Some(self.now);
    }

    fn log_single_source(&mut self, out: &mut Vec<Action>) {
        let single = self.tiers.active().and_then(|tier| {
            let mut ids = self.sources.values().filter(|s| s.spec.tier == tier);
            match (ids.next(), ids.next()) {
                (Some(only), None) => Some((tier, only.spec.id)),
                _ => None,
            }
        });
        if single != self.single_logged {
            if let Some((tier, source)) = single {
                out.push(Action::Log(LogEvent::SingleSourceTier { tier, source }));
            }
            self.single_logged = single;
        }
    }

    fn log_dhcp_difference(&mut self, out: &mut Vec<Action>) {
        let addrs = |tier: Tier| -> BTreeSet<SocketAddr> {
            self.sources
                .values()
                .filter(|s| s.spec.tier == tier)
                .map(|s| s.spec.addr)
                .collect()
        };
        let (config, dhcp) = (addrs(Tier::Config), addrs(Tier::Dhcp));
        let only = |tier: Tier, other: &BTreeSet<SocketAddr>| -> Vec<SourceId> {
            self.sources
                .values()
                .filter(|s| s.spec.tier == tier && !other.contains(&s.spec.addr))
                .map(|s| s.spec.id)
                .collect()
        };
        // With no config servers there is nothing to differ from.
        let diff = (!config.is_empty() && !dhcp.is_empty() && config != dhcp)
            .then(|| (only(Tier::Dhcp, &config), only(Tier::Config, &dhcp)));
        if diff != self.dhcp_logged {
            if let Some((dhcp_only, config_only)) = diff.clone() {
                out.push(Action::Log(LogEvent::DhcpDiffersFromConfig {
                    dhcp_only,
                    config_only,
                }));
            }
            self.dhcp_logged = diff;
        }
    }
}

mod rounds;
mod steer;

use rounds::Round;
use steer::Steer;

#[cfg(test)]
mod tests;
