//! The engine. A pure state machine that turns events into actions.
//!
//! It owns the tier chooser, one filter per source, the clock discipline and
//! the poll timers. The host performs every action and reports back through
//! events. The engine reads no clock and draws no random numbers, so the
//! simulator can replay it exactly.
//!
//! Host contract. Answer every [`Action::Query`] with exactly one
//! [`Event::Sample`] or [`Event::Failed`]. Report each clock action through
//! [`Event::ClockResult`]. Send [`Event::Tick`] at [`Engine::next_wake`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use crate::discipline::{Correction, CrossCheck, Discipline, DisciplineConfig, MAX_HOLD};
use crate::filter::SourceFilter;
use crate::select::{Selection, SelectionConfig, select};
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
    /// Query one source. `observe_only` marks a probe or a pool cross-check.
    /// Its sample never feeds the clock.
    Query {
        /// The source to query.
        source: SourceId,
        /// True when the source is outside the active tier.
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

/// Fewer writes to the drift store. A lost save costs at most ten minutes of
/// learning.
const DRIFT_SAVE_EVERY: Duration = Duration::from_secs(600);

/// A round still open after this long is closed. A lost reply must not stall
/// its tier, because a tier runs one round at a time.
const ROUND_TIMEOUT: Duration = Duration::from_secs(30);

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
}

impl Source {
    fn new(spec: SourceSpec) -> Self {
        Self {
            spec,
            filter: SourceFilter::new(),
            quiet_until: None,
            rate_floor: Duration::ZERO,
            last_query: None,
        }
    }

    fn may_query(&self, now: Mono) -> bool {
        self.quiet_until.is_none_or(|q| now >= q)
            && self
                .last_query
                .is_none_or(|q| now.saturating_duration_since(q) >= self.rate_floor)
    }
}

/// One poll round of one tier. A tier runs one round at a time, which is
/// the probe dedupe the tier chooser asks for.
#[derive(Debug, Clone)]
struct Round {
    started: Mono,
    waiting: Vec<SourceId>,
    /// A new sample arrived. Without one the round only judges the tier,
    /// or the loop would be fed the same offset twice.
    fresh: bool,
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
    /// Start a round of this tier at the next chance.
    recheck: [bool; 3],
    /// A higher tier that was usable on its last probe and is not active.
    /// It is probed at `min_poll`. `due_probe` stops naming a tier once it is
    /// stable, but the chooser only switches inside `observe`.
    building: [bool; 3],
    /// Latest time seen. It never goes back.
    now: Mono,
    started: bool,
    /// Poll interval of the active tier, or of every tier while none is.
    poll: Duration,
    prev_offset: Option<Offset>,
    allowed: bool,
    /// A frequency the host has not been sent yet.
    pending_frequency: Option<Ppm>,
    /// When the loop last set the frequency. Starts the `MAX_HOLD` window.
    held_since: Option<Mono>,
    holdover: bool,
    last_offset: Option<Offset>,
    last_good: Option<Mono>,
    saved_drift: Ppm,
    saved_at: Option<Mono>,
    resumed_at: Option<Mono>,
    single_logged: Option<(Tier, SourceId)>,
    dhcp_logged: Option<(Vec<SourceId>, Vec<SourceId>)>,
}

impl Engine {
    /// A new engine. `drift` is the saved drift, if any. The first event
    /// sets the clock frequency to it.
    #[must_use]
    pub fn new(mut cfg: EngineConfig, drift: Option<Ppm>) -> Self {
        // A zero poll would query without pause.
        cfg.min_poll = cfg.min_poll.max(Duration::from_secs(1));
        cfg.max_poll = cfg.max_poll.max(cfg.min_poll);
        let discipline = Discipline::new(cfg.discipline, drift);
        let start = discipline.drift();
        Self {
            tiers: TierChooser::new(cfg.tier),
            discipline,
            sources: BTreeMap::new(),
            rounds: [None, None, None],
            last_round: [None; 3],
            recheck: [false; 3],
            building: [false; 3],
            now: Mono::from_nanos(0),
            started: false,
            poll: cfg.min_poll,
            prev_offset: None,
            allowed: true,
            pending_frequency: Some(start),
            held_since: None,
            holdover: false,
            last_offset: None,
            last_good: None,
            saved_drift: start,
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
            Event::Tick(at) => self.advance(at),
            Event::Sample(s) => self.on_sample(s, &mut out),
            Event::Failed(id, why) => self.on_failed(id, why, &mut out),
            Event::SourcesChanged(specs) => self.on_sources(specs, &mut out),
            Event::Resumed(at) => self.on_resumed(at),
            Event::AdjustmentAllowed(yes) => self.on_allowed(yes, &mut out),
            Event::ClockResult(Ok(())) => {}
            Event::ClockResult(Err(error)) => {
                out.push(Action::Log(LogEvent::ClockCommandFailed { error }));
                self.disable(DisableReason::ClockFailed, &mut out);
            }
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
                    let every = if probe == Some(t) || self.building[slot(t)] {
                        self.cfg.min_poll
                    } else {
                        self.cfg.tier.reprobe_every
                    };
                    wake.push(self.due_at(t, every));
                }
                if active != Tier::Pool {
                    wake.push(self.due_at(Tier::Pool, self.cfg.tier.reprobe_every));
                }
            }
        }
        if self.allowed {
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
            adjustment_allowed: self.allowed,
        }
    }

    fn advance(&mut self, at: Mono) {
        self.now = self.now.max(at);
    }

    fn on_sample(&mut self, s: Sample, out: &mut Vec<Action>) {
        self.advance(s.at);
        // A reply measured before a resume holds the suspend error.
        if self.resumed_at.is_some_and(|r| s.at < r) {
            return;
        }
        let Some(src) = self.sources.get_mut(&s.source) else {
            return;
        };
        src.filter.push(s);
        self.answered(s.source, true, out);
    }

    fn on_failed(&mut self, id: SourceId, why: QueryFailure, out: &mut Vec<Action>) {
        let now = self.now;
        let Some(src) = self.sources.get_mut(&id) else {
            return;
        };
        if let QueryFailure::KissOfDeath(code) = why {
            let wait = match code {
                KodCode::Deny | KodCode::Rstr => {
                    src.quiet_until = Some(later(now, KOD_QUIET));
                    KOD_QUIET
                }
                // An unknown code is treated as RATE. Slowing down is the
                // safe answer to a server that complains.
                KodCode::Rate | KodCode::Other => {
                    let doubled = src.rate_floor.max(self.poll).saturating_mul(2);
                    src.rate_floor = doubled.min(self.cfg.max_poll);
                    src.rate_floor
                }
            };
            out.push(Action::Log(LogEvent::KissOfDeath {
                source: id,
                code,
                wait,
            }));
        }
        self.answered(id, false, out);
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
        if self.tiers.active().is_some_and(|a| changed[slot(a)]) {
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
        self.rounds = [None, None, None];
        self.last_round = [None; 3];
        self.recheck = [true; 3];
        self.poll = self.cfg.min_poll;
        self.prev_offset = None;
    }

    fn on_allowed(&mut self, yes: bool, out: &mut Vec<Action>) {
        if yes == self.allowed {
            return;
        }
        if yes {
            self.allowed = true;
            // The loop did not steer the clock meanwhile. Start from the
            // learned drift, not from a stale phase term.
            self.pending_frequency = Some(self.free_run());
            self.held_since = None;
            out.push(Action::Log(LogEvent::AdjustmentEnabled));
        } else {
            self.disable(DisableReason::Host, out);
        }
    }

    fn disable(&mut self, reason: DisableReason, out: &mut Vec<Action>) {
        if self.allowed {
            self.allowed = false;
            out.push(Action::Log(LogEvent::AdjustmentDisabled { reason }));
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
        if self.allowed {
            out.extend(self.pending_frequency.take().map(Action::SetFrequency));
        }
    }

    fn schedule(&mut self, out: &mut Vec<Action>) {
        let Some(active) = self.tiers.active() else {
            for t in TIERS {
                if self.wants(t, self.poll) {
                    self.start_round(t, out);
                }
            }
            return;
        };
        if self.wants(active, self.poll) {
            self.start_round(active, out);
        }
        let probe = self.tiers.due_probe(self.now);
        for t in TIERS.into_iter().filter(|&t| t < active) {
            // A tier building its stable run is probed at the fastest rate.
            // At `reprobe_every` each gap would restart its run.
            let every = if probe == Some(t) || self.building[slot(t)] {
                self.cfg.min_poll
            } else {
                Duration::MAX
            };
            if self.wants(t, every) {
                self.start_round(t, out);
            }
        }
        if active != Tier::Pool && self.wants(Tier::Pool, self.cfg.tier.reprobe_every) {
            self.start_round(Tier::Pool, out);
        }
    }

    fn wants(&self, tier: Tier, every: Duration) -> bool {
        let i = slot(tier);
        self.rounds[i].is_none()
            && (self.recheck[i]
                || self.last_round[i]
                    .is_none_or(|l| self.now.saturating_duration_since(l) >= every))
    }

    fn due_at(&self, tier: Tier, every: Duration) -> Option<Mono> {
        let i = slot(tier);
        if self.rounds[i].is_some() {
            return None;
        }
        self.last_round[i].map_or(Some(self.now), |l| l.checked_add(every))
    }

    fn start_round(&mut self, tier: Tier, out: &mut Vec<Action>) {
        let now = self.now;
        let i = slot(tier);
        self.last_round[i] = Some(now);
        self.recheck[i] = false;
        let observe_only = self.tiers.active() != Some(tier);
        let mut waiting = Vec::new();
        for src in self.sources.values_mut() {
            if src.spec.tier == tier && src.may_query(now) {
                src.last_query = Some(now);
                waiting.push(src.spec.id);
                out.push(Action::Query {
                    source: src.spec.id,
                    observe_only,
                });
            }
        }
        // A tier with nothing to ask is judged at once. No sources means
        // unusable.
        let empty = waiting.is_empty();
        self.rounds[i] = Some(Round {
            started: now,
            waiting,
            fresh: false,
        });
        if empty {
            self.close_round(tier, out);
        }
    }

    fn answered(&mut self, id: SourceId, fresh: bool, out: &mut Vec<Action>) {
        for t in TIERS {
            let Some(round) = self.rounds[slot(t)].as_mut() else {
                continue;
            };
            let Some(pos) = round.waiting.iter().position(|&w| w == id) else {
                continue;
            };
            round.waiting.swap_remove(pos);
            round.fresh |= fresh;
            if round.waiting.is_empty() {
                self.close_round(t, out);
            }
            return;
        }
    }

    fn close_round(&mut self, tier: Tier, out: &mut Vec<Action>) {
        let Some(round) = self.rounds[slot(tier)].take() else {
            return;
        };
        let sel = self.select_tier(tier);
        let before = self.tiers.active();
        // Lower tiers are never observed. The pool cross-check is such a
        // tier. Its samples only veto steps.
        if before.is_none_or(|a| tier <= a) {
            self.tiers.observe(tier, sel.is_some(), self.now);
            let after = self.tiers.active();
            self.building[slot(tier)] = sel.is_some() && after != Some(tier);
            if after != before {
                out.push(Action::Log(LogEvent::TierChanged {
                    from: before,
                    to: after,
                }));
                self.poll = self.cfg.min_poll;
                self.prev_offset = None;
            }
        }
        if round.fresh
            && self.tiers.active() == Some(tier)
            && let Some(sel) = sel
        {
            self.update(tier, &sel, out);
        }
    }

    /// Selection inside one tier only. Tiers are never mixed.
    fn select_tier(&self, tier: Tier) -> Option<Selection> {
        let max_age = self.cfg.selection.max_age;
        let samples: Vec<Sample> = self
            .sources
            .values()
            .filter(|s| s.spec.tier == tier)
            .filter_map(|s| s.filter.best_fresh(self.now, max_age))
            .collect();
        select(&samples, self.now, &self.cfg.selection)
    }

    fn cross_check(&self, tier: Tier) -> CrossCheck {
        if tier == Tier::Pool {
            return CrossCheck::NotRequired;
        }
        // Pool servers that cannot agree give no answer, so the step waits.
        self.select_tier(Tier::Pool)
            .map_or(CrossCheck::Pending, |s| CrossCheck::Offset(s.offset))
    }

    fn update(&mut self, tier: Tier, sel: &Selection, out: &mut Vec<Action>) {
        self.adapt_poll(sel);
        self.last_offset = Some(sel.offset);
        self.last_good = Some(self.now);
        self.holdover = false;
        // Measure only. The loop would learn from offsets it never corrects.
        if !self.allowed {
            return;
        }
        let cross = self.cross_check(tier);
        match self.discipline.update(sel, cross, self.now) {
            Correction::None => {}
            Correction::SetFrequency(f) => self.set_frequency(f),
            Correction::Step { offset, frequency } => {
                out.push(Action::Step(offset));
                out.push(Action::Log(LogEvent::StepTaken { offset }));
                self.set_frequency(frequency);
                // Every stored sample predates the step and is now wrong by it.
                for src in self.sources.values_mut() {
                    src.filter = SourceFilter::new();
                }
                self.prev_offset = None;
            }
            Correction::RefuseStep { offset, frequency } => {
                out.push(Action::Log(LogEvent::StepRefused { offset }));
                self.set_frequency(frequency);
            }
        }
    }

    /// Poll fast while the offset moves more than its error bound explains.
    /// Double the interval while it holds still.
    fn adapt_poll(&mut self, sel: &Selection) {
        let x = sel.offset.as_secs();
        let big = x.abs() > self.cfg.discipline.step_threshold.as_secs_f64();
        let jumpy = self
            .prev_offset
            .is_some_and(|p| (x - p.as_secs()).abs() > sel.error_bound.as_secs_f64());
        if big || jumpy {
            self.poll = self.cfg.min_poll;
        } else if self.prev_offset.is_some() {
            self.poll = self.poll.saturating_mul(2).min(self.cfg.max_poll);
        }
        self.prev_offset = Some(sel.offset);
    }

    fn set_frequency(&mut self, f: Ppm) {
        self.pending_frequency = Some(f);
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
        if !self.allowed || !expired {
            return;
        }
        let frequency = self.free_run();
        self.pending_frequency = Some(frequency);
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
        let diff = (!dhcp.is_empty() && config != dhcp)
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

#[cfg(test)]
mod tests {
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
}
