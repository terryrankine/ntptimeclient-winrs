//! Clock discipline. Turns one [`Selection`] into one [`Correction`].
//!
//! The loop is a type 2 phase locked loop. Each update sets the frequency to
//! the learned drift plus a phase term. The phase term removes the offset
//! over a fixed time constant. The drift term integrates the offset, so a
//! steady frequency error ends with zero steady offset.
//!
//! Sign rules. A positive [`Offset`] means the local clock is behind. A
//! positive [`Ppm`] makes the local clock run faster. A clock that needs
//! +20 ppm to keep true time has a drift of +20 ppm.
//!
//! The loop is pure and deterministic. It reads no clock. Time comes in as
//! [`Mono`] so the simulator can drive it.

use std::time::Duration;

use crate::select::Selection;
use crate::{Mono, Offset, Ppm};

/// Time over which the phase term removes an offset.
///
/// Twice the longest poll of 1024 s. One poll then removes at most half the
/// offset, so the phase term alone can never push the clock past zero. It
/// also keeps the linear range gentle: a 128 ms offset asks for 62.5 ppm.
const PHASE_TIME_CONSTANT_SECS: f64 = 2048.0;

/// Longest time a frequency from this loop stays valid without a new update.
///
/// Equal to the phase time constant. A held phase term removes the offset
/// at a fixed rate, so it reaches zero after one phase constant. Holding it
/// longer pushes the clock past zero. In steady state the drift taught on
/// the same round adds `gap * MAX_HOLD / T_i^2 = gap / 8192` of the offset.
/// The learning gap is capped at 1280 s, so the overshoot within this window
/// is at most 1280 / 8192 = 15.6 % of the offset. The engine must call
/// [`Discipline::free_run`] if no update arrives within this window.
pub const MAX_HOLD: Duration = Duration::from_secs(2048);

/// Time constant of the drift integrator.
///
/// Twice the phase constant gives a damping ratio of 1. That is the fastest
/// loop that does not ring. The damping does not depend on the poll, because
/// both gains are set in seconds, not in polls.
const DRIFT_TIME_CONSTANT_SECS: f64 = 2.0 * PHASE_TIME_CONSTANT_SECS;

/// Longest gap between updates that still teaches the drift.
///
/// 1.25 times the longest poll of 1024 s. Real gaps at that poll run a little
/// over 1024 s from round-trip time and scheduling jitter, and must still
/// learn. The cap is inclusive: a gap of exactly 1280 s learns. It also
/// bounds the [`MAX_HOLD`] overshoot, which is `gap / 8192` of the offset:
/// at most 15.6 % here, where 2048 s would give 25 %. A longer gap means a
/// missed poll or an outage. It still corrects the phase.
const MAX_LEARN_INTERVAL_SECS: f64 = 1280.0;

const PPM_PER_UNIT: f64 = 1e6;

/// Tuning for [`Discipline`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DisciplineConfig {
    /// Offsets above this may be stepped. Offsets at or below it are always
    /// slewed. Default 128 ms.
    pub step_threshold: Duration,
    /// A step above this is refused unless `allow_panic_step` is set.
    /// Default 1000 s.
    pub panic_threshold: Duration,
    /// Allows a step above `panic_threshold`. Default false.
    pub allow_panic_step: bool,
    /// Largest frequency correction either way, drift included. A saved
    /// drift outside it is ignored. Default 500 ppm.
    pub max_slew: Ppm,
}

impl Default for DisciplineConfig {
    fn default() -> Self {
        Self {
            step_threshold: Duration::from_millis(128),
            panic_threshold: Duration::from_secs(1000),
            allow_panic_step: false,
            max_slew: Ppm::new(500.0),
        }
    }
}

/// State of the pool cross-check for a single-source tier.
///
/// The cross-check only vetoes steps. Its offset is never slewed to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CrossCheck {
    /// The active tier does not need a cross-check. Never blocks a step.
    NotRequired,
    /// A cross-check is needed and the pool has not answered yet.
    Pending,
    /// The pool's offset, observed only.
    Offset(Offset),
}

/// What the host must do to the clock after one update.
///
/// Every variant except `None` carries a frequency. It is absolute from
/// nominal, includes the learned drift and is clamped to `max_slew`. The
/// host applies it and the platform quantises it. A frequency is valid for
/// at most [`MAX_HOLD`]. If no update arrives within that window the engine
/// must call [`Discipline::free_run`] and apply its frequency.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Correction {
    /// Nothing to apply. Returned when the selected offset is not finite.
    /// The engine keeps the last frequency, within [`MAX_HOLD`].
    None,
    /// Set the frequency. Valid for at most [`MAX_HOLD`].
    SetFrequency(Ppm),
    /// Move the clock by `offset`, then set `frequency`. A positive offset
    /// moves the clock forward. The frequency is the learned drift alone,
    /// because the step removes the phase.
    Step {
        /// Amount to move the clock.
        offset: Offset,
        /// Frequency to set after the step.
        frequency: Ppm,
    },
    /// A step was needed but is not safe. Do not move the clock. Set
    /// `frequency`.
    ///
    /// Panic refusal: the offset is above the panic threshold. The loop
    /// changes no state. `frequency` is the learned drift alone, so the
    /// clock is not slewed toward a source that may be badly wrong.
    ///
    /// Cross-check veto: the pool is pending or disagrees. `frequency` is
    /// the normal slew toward the selected offset. The step stays
    /// available, so a later round with an agreeing pool may still step.
    /// The drift is not taught, because the offset is above the threshold.
    RefuseStep {
        /// The offset that was not stepped.
        offset: Offset,
        /// Frequency to set on this round.
        frequency: Ppm,
    },
}

/// Phase and frequency locked loop for one clock.
#[derive(Debug, Clone)]
pub struct Discipline {
    cfg: DisciplineConfig,
    /// Learned drift in ppm. Always within `max_slew`.
    drift_ppm: f64,
    /// One step is allowed after start and after each resume.
    step_allowed: bool,
    /// Time of the last accepted or vetoed round, set even when that round
    /// did not teach the drift. It gives the next round its gap. A panic
    /// refusal leaves it alone. `None` after start, resume and free run, so
    /// the first sample after those does not teach the drift.
    last_update: Option<Mono>,
}

impl Discipline {
    /// A new loop. `initial_drift` is the saved drift, if any. A value
    /// outside `max_slew` is ignored, as the design asks.
    #[must_use]
    pub fn new(cfg: DisciplineConfig, initial_drift: Option<Ppm>) -> Self {
        let limit = cfg.max_slew.value().abs();
        let drift_ppm = initial_drift
            .map(Ppm::value)
            .filter(|d| d.abs() <= limit)
            .unwrap_or(0.0);
        Self {
            cfg,
            drift_ppm,
            step_allowed: true,
            last_update: None,
        }
    }

    /// Takes one selected offset and returns the correction to apply.
    ///
    /// The first sync after start or resume may step if the offset is above
    /// `step_threshold`. Any accepted round uses up that step. After it every
    /// offset is slewed through the frequency, clamped to `max_slew`.
    pub fn update(&mut self, sel: &Selection, cross_check: CrossCheck, now: Mono) -> Correction {
        let x = sel.offset.as_secs();
        // `Offset` asserts finiteness in debug builds only. A release build
        // must still never feed NaN or infinity into the loop state.
        if !x.is_finite() {
            return Correction::None;
        }
        let threshold = self.cfg.step_threshold.as_secs_f64();

        if self.step_allowed && x.abs() > threshold {
            if self.panics(x) {
                return Correction::RefuseStep {
                    offset: sel.offset,
                    frequency: self.clamp(self.drift_ppm),
                };
            }
            if self.pool_vetoes(x, cross_check) {
                // Slew while the pool decides. The step stays allowed.
                self.last_update = Some(now);
                return Correction::RefuseStep {
                    offset: sel.offset,
                    frequency: self.slew(x),
                };
            }
            self.step_allowed = false;
            self.last_update = Some(now);
            return Correction::Step {
                offset: sel.offset,
                frequency: self.clamp(self.drift_ppm),
            };
        }
        self.step_allowed = false;

        // Only offsets in the linear range teach the drift. A large offset
        // is slewed at the clamp, and teaching from it would wind up the
        // integrator and overshoot later.
        if x.abs() <= threshold {
            self.learn(x, now);
        }
        self.last_update = Some(now);

        // A large offset after the first sync uses the same law. This is the
        // spec's "slewed at a capped rate", not a flat `max_slew`. The clamp
        // gives full rate above about 1 s. The phase constant keeps it from
        // overshooting below that.
        //
        // An offset above the panic threshold is slewed here too. That is
        // the spec's reading. It is inconsistent with the refusal at start,
        // which never acts on such an offset. The owner must decide.
        Correction::SetFrequency(self.slew(x))
    }

    /// Normal slew law: drift plus phase term, clamped.
    fn slew(&self, x: f64) -> Ppm {
        let phase_ppm = x / PHASE_TIME_CONSTANT_SECS * PPM_PER_UNIT;
        self.clamp(self.drift_ppm + phase_ppm)
    }

    /// No source is usable. Keeps the clock at its learned rate.
    pub fn free_run(&mut self, now: Mono) -> Correction {
        // The offset built up while free running mixes the residual phase
        // with a long gap. Teaching from it would give a wrong drift. `now`
        // stays in the call so the engine passes time the same way to both.
        let _ = now;
        self.last_update = None;
        Correction::SetFrequency(Ppm::new(self.drift_ppm))
    }

    /// The machine resumed from sleep. Allows one more step.
    pub fn note_resume(&mut self) {
        self.step_allowed = true;
        // The first offset after resume holds the suspend error, not drift.
        self.last_update = None;
    }

    /// The learned drift, ready to save.
    #[must_use]
    pub fn drift(&self) -> Ppm {
        Ppm::new(self.drift_ppm)
    }

    fn panics(&self, x: f64) -> bool {
        x.abs() > self.cfg.panic_threshold.as_secs_f64() && !self.cfg.allow_panic_step
    }

    fn pool_vetoes(&self, x: f64, cross_check: CrossCheck) -> bool {
        let threshold = self.cfg.step_threshold.as_secs_f64();
        match cross_check {
            CrossCheck::NotRequired => false,
            CrossCheck::Pending => true,
            // A difference exactly at the threshold agrees, as offsets
            // exactly at the threshold slew rather than step.
            CrossCheck::Offset(o) => (o.as_secs() - x).abs() > threshold,
        }
    }

    /// Teaches the drift from one offset in the linear range.
    ///
    /// `error_bound` is not used. A wide-bound sample teaches at full gain.
    /// Accepted for v1: selection already drops falsetickers. One sample at
    /// the 128 ms threshold moves the drift by 0.5 ppm at a 64 s gap. The
    /// worst case is 9.8 ppm at the 1280 s gap cap. The loop pulls it back.
    fn learn(&mut self, x: f64, now: Mono) {
        let Some(last) = self.last_update else {
            return;
        };
        let gap = now.saturating_duration_since(last).as_secs_f64();
        if gap <= 0.0 || gap > MAX_LEARN_INTERVAL_SECS {
            return;
        }
        // Integral term of the loop: offset times gap over the square of the
        // drift constant, in ppm.
        let gain = gap / (DRIFT_TIME_CONSTANT_SECS * DRIFT_TIME_CONSTANT_SECS);
        let limit = self.cfg.max_slew.value().abs();
        self.drift_ppm = (self.drift_ppm + x * gain * PPM_PER_UNIT).clamp(-limit, limit);
    }

    fn clamp(&self, ppm: f64) -> Ppm {
        let limit = self.cfg.max_slew.value().abs();
        Ppm::new(ppm.clamp(-limit, limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceId;

    const POLL: u64 = 64;

    fn sel(offset: f64) -> Selection {
        Selection {
            offset: Offset::from_secs(offset),
            error_bound: Duration::from_millis(1),
            survivors: vec![SourceId::new(1)],
        }
    }

    fn at(secs: u64) -> Mono {
        Mono::from_nanos(secs * 1_000_000_000)
    }

    fn freq(c: Correction) -> f64 {
        match c {
            Correction::SetFrequency(p) => p.value(),
            other => panic!("expected SetFrequency, got {other:?}"),
        }
    }

    /// Offset and frequency of a `Step`.
    fn step(c: Correction) -> (f64, f64) {
        match c {
            Correction::Step { offset, frequency } => (offset.as_secs(), frequency.value()),
            other => panic!("expected Step, got {other:?}"),
        }
    }

    /// Offset and frequency of a `RefuseStep`.
    fn refused(c: Correction) -> (f64, f64) {
        match c {
            Correction::RefuseStep { offset, frequency } => (offset.as_secs(), frequency.value()),
            other => panic!("expected RefuseStep, got {other:?}"),
        }
    }

    fn fresh() -> Discipline {
        Discipline::new(DisciplineConfig::default(), None)
    }

    /// Phase term the loop asks for, in ppm.
    fn phase_ppm(x: f64) -> f64 {
        x / PHASE_TIME_CONSTANT_SECS * PPM_PER_UNIT
    }

    /// A clock that needs `need_ppm` of correction to keep true time,
    /// measured with uniform jitter. Deterministic: the jitter comes from a
    /// fixed-seed xorshift generator.
    struct Sim {
        /// True offset, remote minus local, in seconds.
        phase: f64,
        /// Correction that would hold the clock at the true rate.
        need_ppm: f64,
        /// Frequency the host last applied.
        freq_ppm: f64,
        /// Monotonic time in seconds.
        now: u64,
        /// Half-width of the measurement jitter, in seconds.
        jitter: f64,
        rng: u64,
        steps: u32,
    }

    impl Sim {
        fn new(phase: f64, need_ppm: f64, jitter: f64) -> Self {
            Self {
                phase,
                need_ppm,
                freq_ppm: 0.0,
                now: 0,
                jitter,
                rng: 0x9E37_79B9_7F4A_7C15,
                steps: 0,
            }
        }

        fn noise(&mut self) -> f64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            #[allow(clippy::cast_precision_loss)]
            let unit = (self.rng >> 11) as f64 / (1u64 << 53) as f64;
            (unit * 2.0 - 1.0) * self.jitter
        }

        /// Measures, applies the correction, then lets `poll` seconds pass.
        fn poll(&mut self, d: &mut Discipline, poll: u64) -> Correction {
            let measured = self.phase + self.noise();
            let c = d.update(&sel(measured), CrossCheck::NotRequired, at(self.now));
            match c {
                Correction::Step { offset, frequency } => {
                    self.phase -= offset.as_secs();
                    self.freq_ppm = frequency.value();
                    self.steps += 1;
                }
                Correction::SetFrequency(p) | Correction::RefuseStep { frequency: p, .. } => {
                    self.freq_ppm = p.value();
                }
                Correction::None => {}
            }
            #[allow(clippy::cast_precision_loss)]
            let secs = poll as f64;
            self.phase += (self.need_ppm - self.freq_ppm) * 1e-6 * secs;
            self.now += poll;
            c
        }
    }

    /// Poll ladder a real engine walks: start fast, back off to 1024 s.
    fn ladder() -> Vec<u64> {
        let mut v = Vec::new();
        for poll in [64, 128, 256, 512] {
            v.extend(std::iter::repeat_n(poll, 32));
        }
        v.extend(std::iter::repeat_n(1024, 60));
        v
    }

    #[test]
    fn small_offset_sets_frequency_not_step() {
        let mut d = fresh();
        let f = freq(d.update(&sel(0.010), CrossCheck::NotRequired, at(0)));
        assert!(f > 0.0 && f <= 500.0, "frequency {f}");
    }

    #[test]
    fn first_large_offset_steps_once_then_slews() {
        let mut d = fresh();
        let (s, _) = step(d.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
        assert!((s - 0.5).abs() < 1e-12);
        let f = freq(d.update(&sel(0.5), CrossCheck::NotRequired, at(POLL)));
        assert!(f > 0.0, "slews forward, got {f}");
    }

    #[test]
    fn step_carries_drift_as_frequency() {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(7.0)));
        let (_, f) = step(d.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
        assert!((f - 7.0).abs() < 1e-12, "got {f}");
    }

    #[test]
    fn step_threshold_is_configurable() {
        let cfg = DisciplineConfig {
            step_threshold: Duration::from_secs(1),
            ..DisciplineConfig::default()
        };
        let mut wide = Discipline::new(cfg, None);
        freq(wide.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
        let mut normal = fresh();
        step(normal.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
    }

    #[test]
    fn offset_exactly_at_step_threshold_slews() {
        let mut d = fresh();
        freq(d.update(&sel(0.128), CrossCheck::NotRequired, at(0)));
        let mut d = fresh();
        freq(d.update(&sel(-0.128), CrossCheck::NotRequired, at(0)));
    }

    #[test]
    fn negative_offset_steps_then_slews_backwards() {
        let mut d = fresh();
        let (s, _) = step(d.update(&sel(-0.7), CrossCheck::NotRequired, at(0)));
        assert!((s + 0.7).abs() < 1e-12);
        let f = freq(d.update(&sel(-0.05), CrossCheck::NotRequired, at(POLL)));
        assert!(f < 0.0, "slows the clock, got {f}");
        let f = freq(d.update(&sel(-10.0), CrossCheck::NotRequired, at(2 * POLL)));
        assert!((f + 500.0).abs() < 1e-9, "full slew backwards, got {f}");
    }

    #[test]
    fn learns_drift_from_stable_samples() {
        // The clock needs +20 ppm to keep true time. Start 300 ms off so the
        // first update steps, then walk the poll ladder with 0.5 ms jitter.
        let mut sim = Sim::new(0.3, 20.0, 0.0005);
        let mut d = fresh();
        for poll in ladder() {
            sim.poll(&mut d, poll);
        }
        assert_eq!(sim.steps, 1, "one step at start, then slew only");
        let learned = d.drift().value();
        assert!((learned - 20.0).abs() < 2.0, "learned {learned} ppm");
    }

    #[test]
    fn loop_does_not_oscillate_after_settling() {
        for (poll, jitter) in [(64, 0.0005), (1024, 0.0005), (64, 0.0), (1024, 0.0)] {
            let mut sim = Sim::new(0.0, 20.0, jitter);
            let mut d = fresh();
            // Settle for 48 hours.
            for _ in 0..(48 * 3600 / poll) {
                sim.poll(&mut d, poll);
            }
            let (mut lo, mut hi, mut worst) = (f64::MAX, f64::MIN, 0.0_f64);
            for _ in 0..(12 * 3600 / poll) {
                sim.poll(&mut d, poll);
                lo = lo.min(sim.freq_ppm);
                hi = hi.max(sim.freq_ppm);
                worst = worst.max(sim.phase.abs());
            }
            assert!(worst < 0.002, "poll {poll}: offset {worst} s");
            assert!(hi - lo < 2.0, "poll {poll}: band {lo}..{hi} ppm");
            assert!((lo - 20.0).abs() < 2.0 && (hi - 20.0).abs() < 2.0);
        }
    }

    #[test]
    fn drift_error_settles_without_overshoot() {
        // No jitter. The clock starts on time but the loop starts 20 ppm
        // wrong. A loop that rings would push the offset through zero.
        for poll in [64, 256, 1024] {
            let mut sim = Sim::new(0.0, 20.0, 0.0);
            let mut d = fresh();
            let mut crossings = 0;
            let mut last = 0.0_f64;
            for _ in 0..(72 * 3600 / poll) {
                sim.poll(&mut d, poll);
                if sim.phase.abs() > 1e-6 {
                    if last != 0.0 && sim.phase.signum() != last.signum() {
                        crossings += 1;
                    }
                    last = sim.phase;
                }
            }
            assert_eq!(crossings, 0, "poll {poll}: offset crossed zero");
            let learned = d.drift().value();
            assert!(
                (learned - 20.0).abs() < 0.1,
                "poll {poll}: learned {learned}"
            );
        }
    }

    #[test]
    fn max_hold_equals_phase_time_constant() {
        assert!((MAX_HOLD.as_secs_f64() - PHASE_TIME_CONSTANT_SECS).abs() < 1e-12);
    }

    /// Overshoot bound after a held round: `MAX_LEARN_INTERVAL_SECS / 8192`.
    fn hold_bound() -> f64 {
        MAX_LEARN_INTERVAL_SECS * MAX_HOLD.as_secs_f64()
            / (DRIFT_TIME_CONSTANT_SECS * DRIFT_TIME_CONSTANT_SECS)
    }

    /// True phase after one frequency is held for `hold` seconds. The drift
    /// is right, so the only error is the phase. `prior_gap` adds an update
    /// that many seconds before, which uses up the start step and lets a
    /// linear offset teach the drift on the held round.
    fn held(x0: f64, prior_gap: Option<u64>, hold: u64) -> f64 {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(20.0)));
        let mut sim = Sim::new(x0, 20.0, 0.0);
        sim.freq_ppm = 20.0;
        if let Some(gap) = prior_gap {
            freq(d.update(&sel(0.0), CrossCheck::NotRequired, at(0)));
            sim.now = gap;
        }
        sim.poll(&mut d, hold);
        sim.phase
    }

    #[test]
    fn hold_bound_is_15_6_percent() {
        assert!((hold_bound() - 0.156_25).abs() < 1e-12);
    }

    #[test]
    fn skipped_poll_within_max_hold_does_not_cross_zero() {
        // A 1024 s poll is skipped, so one frequency is held for MAX_HOLD.
        let hold = MAX_HOLD.as_secs();

        // Phase term alone: a first sync in the linear range, or a large
        // offset after the first sync. Neither teaches the drift.
        for (x0, prior) in [
            (0.01, None),
            (0.128, None),
            (-0.1, None),
            (0.5, Some(1024)),
            (5.0, Some(1024)),
            (-5.0, Some(1024)),
        ] {
            let p = held(x0, prior, hold);
            assert!(p * x0.signum() >= -1e-12, "x0 {x0}: crossed to {p}");
        }

        // Steady state: the integral term adds gap / 8192 of the offset on
        // top of the phase term. At the 1280 s cap that is 15.6 %.
        for gap in [1024, 1280] {
            for x0 in [0.01, 0.1, 0.128, -0.1] {
                let p = held(x0, Some(gap), hold);
                assert!(
                    p * x0.signum() >= -0.156_25 * x0.abs() - 1e-12,
                    "gap {gap} x0 {x0}: overshot to {p}"
                );
            }
        }

        // Holding twice as long crosses far. The window is what matters.
        let p = held(0.1, None, 2 * hold);
        assert!(p < -0.05, "expected a crossing, got {p}");
    }

    /// Drift taught by one 0.1 s offset after a gap in nanoseconds, in ppm.
    fn taught(gap_ns: u64) -> f64 {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(20.0)));
        freq(d.update(&sel(0.0), CrossCheck::NotRequired, at(0)));
        freq(d.update(&sel(0.1), CrossCheck::NotRequired, Mono::from_nanos(gap_ns)));
        d.drift().value() - 20.0
    }

    /// The integral teach for a 0.1 s offset after `gap` seconds, in ppm.
    fn integral(gap: f64) -> f64 {
        0.1 * gap / (DRIFT_TIME_CONSTANT_SECS * DRIFT_TIME_CONSTANT_SECS) * 1e6
    }

    const NS: u64 = 1_000_000_000;

    #[test]
    fn learning_gap_exactly_at_cap_learns() {
        let got = taught(1280 * NS);
        let want = integral(1280.0);
        assert!((got - want).abs() < 1e-9, "taught {got}, want {want}");
        assert!(got > 7.0);
    }

    #[test]
    fn learning_gap_of_max_poll_plus_jitter_learns() {
        // 1024 s poll plus 0.5 s of round trip and scheduling jitter.
        let got = taught(1024 * NS + NS / 2);
        let want = integral(1024.5);
        assert!((got - want).abs() < 1e-9, "taught {got}, want {want}");
    }

    #[test]
    fn learning_gap_above_cap_is_skipped_and_hold_stays_bounded() {
        assert!(taught(1280 * NS + 1).abs() < 1e-12);
        assert!(taught(1281 * NS).abs() < 1e-12);
        assert!(taught(2048 * NS).abs() < 1e-12);
        // A 2048 s gap, then the round is held for MAX_HOLD. Without the cap
        // the integral term would add 1/4 of the offset. With it, nothing.
        for x0 in [0.01, 0.1, 0.128, -0.1] {
            let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(20.0)));
            freq(d.update(&sel(0.0), CrossCheck::NotRequired, at(0)));
            let mut sim = Sim::new(x0, 20.0, 0.0);
            sim.freq_ppm = 20.0;
            sim.now = 2048;
            sim.poll(&mut d, MAX_HOLD.as_secs());
            assert!((d.drift().value() - 20.0).abs() < 1e-12, "x0 {x0}: learned");
            let p = sim.phase;
            assert!(
                p * x0.signum() >= -0.156_25 * x0.abs() - 1e-12,
                "x0 {x0}: overshot to {p}"
            );
        }
    }

    #[test]
    fn veto_round_records_update_time() {
        // The veto round sets `last_update`. The small round after it then
        // has a gap and teaches the drift. Without the record it would not.
        let mut d = fresh();
        refused(d.update(&sel(0.5), CrossCheck::Pending, at(0)));
        freq(d.update(&sel(0.01), CrossCheck::Pending, at(POLL)));
        #[allow(clippy::cast_precision_loss)]
        let gap = POLL as f64;
        let expected = 0.01 * gap / (DRIFT_TIME_CONSTANT_SECS * DRIFT_TIME_CONSTANT_SECS) * 1e6;
        let got = d.drift().value();
        assert!(got > 0.0 && (got - expected).abs() < 1e-12, "got {got}");
    }

    #[test]
    fn free_run_uses_saved_drift() {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(12.5)));
        assert!((d.drift().value() - 12.5).abs() < 1e-12);
        let f = freq(d.free_run(at(0)));
        assert!((f - 12.5).abs() < 1e-12);
    }

    #[test]
    fn free_run_after_learning_keeps_learned_rate() {
        let mut sim = Sim::new(0.0, -35.0, 0.0);
        let mut d = fresh();
        for _ in 0..(24 * 3600 / 256) {
            sim.poll(&mut d, 256);
        }
        let f = freq(d.free_run(at(sim.now)));
        assert!((f - d.drift().value()).abs() < 1e-12);
        assert!((f + 35.0).abs() < 1.0, "free run at {f}");
    }

    #[test]
    fn initial_drift_outside_max_slew_is_ignored() {
        let d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(600.0)));
        assert!(d.drift().value().abs() < 1e-12);
        let d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(-500.0)));
        assert!((d.drift().value() + 500.0).abs() < 1e-12);
    }

    #[test]
    fn resume_allows_one_step_only() {
        let mut d = fresh();
        step(d.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
        freq(d.update(&sel(0.5), CrossCheck::NotRequired, at(POLL)));
        d.note_resume();
        step(d.update(&sel(2.0), CrossCheck::NotRequired, at(2 * POLL)));
        freq(d.update(&sel(2.0), CrossCheck::NotRequired, at(3 * POLL)));
        freq(d.update(&sel(2.0), CrossCheck::NotRequired, at(4 * POLL)));
    }

    #[test]
    fn note_resume_after_first_sync_allows_one_step() {
        let mut d = fresh();
        // The first sync is small. It uses up the start step.
        freq(d.update(&sel(0.01), CrossCheck::NotRequired, at(0)));
        freq(d.update(&sel(0.5), CrossCheck::NotRequired, at(POLL)));
        d.note_resume();
        step(d.update(&sel(0.5), CrossCheck::NotRequired, at(2 * POLL)));
        freq(d.update(&sel(0.5), CrossCheck::NotRequired, at(3 * POLL)));
    }

    #[test]
    fn large_offset_during_normal_operation_slews_at_max_rate() {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(3.0)));
        freq(d.update(&sel(0.001), CrossCheck::NotRequired, at(0)));
        let drift = d.drift().value();
        // The spec's "capped rate" is the clamped slew law, not a flat
        // max_slew. 0.2 s asks for about 97.7 ppm on top of the drift.
        let f = freq(d.update(&sel(0.2), CrossCheck::NotRequired, at(POLL)));
        assert!((f - (drift + phase_ppm(0.2))).abs() < 1e-9, "got {f}");
        assert!((phase_ppm(0.2) - 97.656_25).abs() < 1e-9 && f < 500.0);
        let f = freq(d.update(&sel(10.0), CrossCheck::NotRequired, at(2 * POLL)));
        assert!((f - 500.0).abs() < 1e-9, "got {f}");
        let f = freq(d.update(&sel(-10.0), CrossCheck::NotRequired, at(3 * POLL)));
        assert!((f + 500.0).abs() < 1e-9, "got {f}");
    }

    #[test]
    fn large_offset_does_not_teach_drift() {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(3.0)));
        freq(d.update(&sel(0.001), CrossCheck::NotRequired, at(0)));
        let before = d.drift().value();
        for i in 1..=10 {
            freq(d.update(&sel(5.0), CrossCheck::NotRequired, at(i * POLL)));
        }
        assert!((d.drift().value() - before).abs() < 1e-12);
    }

    #[test]
    fn step_above_panic_threshold_is_refused() {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(4.0)));
        let (r, f) = refused(d.update(&sel(2000.0), CrossCheck::NotRequired, at(0)));
        assert!((r - 2000.0).abs() < 1e-9);
        // Hold the learned rate. Do not slew toward a panic offset.
        assert!((f - 4.0).abs() < 1e-12, "got {f}");
        // The refusal does not use up the step.
        refused(d.update(&sel(-1500.0), CrossCheck::NotRequired, at(POLL)));
        step(d.update(&sel(-0.5), CrossCheck::NotRequired, at(2 * POLL)));
    }

    #[test]
    fn panic_step_is_allowed_when_configured() {
        let cfg = DisciplineConfig {
            allow_panic_step: true,
            ..DisciplineConfig::default()
        };
        let mut d = Discipline::new(cfg, None);
        step(d.update(&sel(2000.0), CrossCheck::NotRequired, at(0)));
    }

    #[test]
    fn refused_round_keeps_step_and_drift() {
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(7.0)));
        let (_, f) = refused(d.update(&sel(0.5), CrossCheck::Pending, at(0)));
        assert!((f - (7.0 + phase_ppm(0.5))).abs() < 1e-9, "got {f}");
        assert!((d.drift().value() - 7.0).abs() < 1e-12);
        step(d.update(&sel(0.5), CrossCheck::NotRequired, at(POLL)));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn non_finite_offset_returns_none() {
        // Release only: a debug build asserts in `Offset::from_secs`.
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(5.0)));
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                d.update(&sel(bad), CrossCheck::NotRequired, at(0)),
                Correction::None
            );
        }
        assert!((d.drift().value() - 5.0).abs() < 1e-12);
        // No state changed, so the start step is still there.
        step(d.update(&sel(0.5), CrossCheck::NotRequired, at(POLL)));
    }

    #[test]
    fn frequency_is_clamped_to_max_slew() {
        let cfg = DisciplineConfig {
            max_slew: Ppm::new(100.0),
            ..DisciplineConfig::default()
        };
        let mut d = Discipline::new(cfg, Some(Ppm::new(90.0)));
        let f = freq(d.update(&sel(0.1), CrossCheck::NotRequired, at(0)));
        assert!((f - 100.0).abs() < 1e-9, "got {f}");
        let f = freq(d.update(&sel(-5.0), CrossCheck::NotRequired, at(POLL)));
        assert!((f + 100.0).abs() < 1e-9, "got {f}");
    }

    #[test]
    fn drift_is_clamped_to_max_slew() {
        // The clock needs 520 ppm, past the 500 ppm limit. The offset grows
        // slowly enough to stay in the linear range, so the drift is taught.
        // It must climb to the limit and stop there.
        let mut sim = Sim::new(0.0, 520.0, 0.0);
        let mut d = Discipline::new(DisciplineConfig::default(), Some(Ppm::new(495.0)));
        for _ in 0..100 {
            sim.poll(&mut d, 64);
            assert!(d.drift().value().abs() <= 500.0);
            assert!(sim.freq_ppm.abs() <= 500.0);
        }
        assert!(
            (d.drift().value() - 500.0).abs() < f64::EPSILON,
            "got {}",
            d.drift().value()
        );
    }

    #[test]
    fn pending_cross_check_refuses_step() {
        let mut d = fresh();
        let (r, _) = refused(d.update(&sel(0.5), CrossCheck::Pending, at(0)));
        assert!((r - 0.5).abs() < 1e-12);
    }

    #[test]
    fn disagreeing_cross_check_refuses_step() {
        let mut d = fresh();
        let pool = CrossCheck::Offset(Offset::from_secs(0.0));
        refused(d.update(&sel(0.5), pool, at(0)));
    }

    #[test]
    fn agreeing_cross_check_allows_step() {
        let mut d = fresh();
        let pool = CrossCheck::Offset(Offset::from_secs(0.45));
        step(d.update(&sel(0.5), pool, at(0)));
    }

    #[test]
    fn cross_check_difference_exactly_at_threshold_agrees() {
        // 0.125 s, 0.375 s and 0.5 s are exact in binary, so the difference
        // is exactly the threshold.
        let cfg = DisciplineConfig {
            step_threshold: Duration::from_millis(125),
            ..DisciplineConfig::default()
        };
        let mut d = Discipline::new(cfg, None);
        step(d.update(
            &sel(0.5),
            CrossCheck::Offset(Offset::from_secs(0.375)),
            at(0),
        ));
        let mut d = Discipline::new(cfg, None);
        refused(d.update(
            &sel(0.5),
            CrossCheck::Offset(Offset::from_secs(0.374)),
            at(0),
        ));
    }

    #[test]
    fn not_required_cross_check_allows_step() {
        let mut d = fresh();
        step(d.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
    }

    #[test]
    fn pending_veto_slews_at_full_rate_and_keeps_step() {
        let mut d = fresh();
        let (r, f) = refused(d.update(&sel(10.0), CrossCheck::Pending, at(0)));
        assert!((r - 10.0).abs() < 1e-12);
        assert!((f - 500.0).abs() < 1e-9, "got {f}");
        let pool = CrossCheck::Offset(Offset::from_secs(9.95));
        let (s, _) = step(d.update(&sel(9.9), pool, at(POLL)));
        assert!((s - 9.9).abs() < 1e-12);
    }

    #[test]
    fn cross_check_never_blocks_slew() {
        let mut d = fresh();
        // Step allowed, pool pending: the veto round still slews.
        let (_, f) = refused(d.update(&sel(0.5), CrossCheck::Pending, at(0)));
        assert!((f - phase_ppm(0.5)).abs() < 1e-9 && f > 0.0, "got {f}");
        // A small offset never needs a step, so the pending pool is moot.
        freq(d.update(&sel(0.05), CrossCheck::Pending, at(POLL)));
        // After the first sync a disagreeing pool cannot stop a slew.
        let pool = CrossCheck::Offset(Offset::from_secs(-3.0));
        let f = freq(d.update(&sel(5.0), pool, at(2 * POLL)));
        assert!((f - 500.0).abs() < 1e-9);
    }
}
