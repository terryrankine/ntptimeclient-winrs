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
mod tests;
