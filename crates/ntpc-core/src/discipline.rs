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

/// Time constant of the drift integrator.
///
/// Twice the phase constant gives a damping ratio of 1. That is the fastest
/// loop that does not ring. The damping does not depend on the poll, because
/// both gains are set in seconds, not in polls.
const DRIFT_TIME_CONSTANT_SECS: f64 = 2.0 * PHASE_TIME_CONSTANT_SECS;

/// Longest gap between updates that still teaches the drift.
///
/// The drift gain grows with the square of the gap. Above 2048 s the
/// discrete loop loses its margin and a gap after an outage would teach a
/// wrong drift. A longer gap still corrects the phase.
const MAX_LEARN_INTERVAL_SECS: f64 = 2048.0;

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
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Correction {
    /// Nothing to apply. The loop never returns it today. The engine may use
    /// it for rounds that do not reach the loop.
    None,
    /// Set the frequency, absolute from nominal. It already includes the
    /// learned drift. The host applies it and the platform quantises it.
    SetFrequency(Ppm),
    /// Move the clock by this offset. A positive offset moves it forward.
    /// The frequency stays as it was until the next update.
    Step(Offset),
    /// A step was needed but is not safe. Either the offset is above the
    /// panic threshold or the pool cross-check is pending or disagrees.
    ///
    /// The engine must not touch the clock. It should log the refusal and
    /// keep the last frequency. The loop changes no state on this round:
    /// the step stays available, the drift is not taught and the update
    /// time is not recorded. The next round with a safe answer may step.
    RefuseStep(Offset),
}

/// Phase and frequency locked loop for one clock.
#[derive(Debug, Clone)]
pub struct Discipline {
    cfg: DisciplineConfig,
    /// Learned drift in ppm. Always within `max_slew`.
    drift_ppm: f64,
    /// One step is allowed after start and after each resume.
    step_allowed: bool,
    /// Time of the last update that taught the loop. `None` after start,
    /// resume and free run, so the next sample does not teach the drift.
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
        let threshold = self.cfg.step_threshold.as_secs_f64();

        if self.step_allowed && x.abs() > threshold {
            if self.step_unsafe(x, cross_check) {
                return Correction::RefuseStep(sel.offset);
            }
            self.step_allowed = false;
            self.last_update = Some(now);
            return Correction::Step(sel.offset);
        }
        self.step_allowed = false;

        // Only offsets in the linear range teach the drift. A large offset
        // is slewed at the clamp, and teaching from it would wind up the
        // integrator and overshoot later.
        if x.abs() <= threshold {
            self.learn(x, now);
        }
        self.last_update = Some(now);

        // A large offset uses the same law. The clamp turns it into a full
        // rate slew above about 1 s, and the phase constant keeps it from
        // overshooting below that.
        let phase_ppm = x / PHASE_TIME_CONSTANT_SECS * PPM_PER_UNIT;
        Correction::SetFrequency(self.clamp(self.drift_ppm + phase_ppm))
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

    fn step_unsafe(&self, x: f64, cross_check: CrossCheck) -> bool {
        let panic = x.abs() > self.cfg.panic_threshold.as_secs_f64() && !self.cfg.allow_panic_step;
        let threshold = self.cfg.step_threshold.as_secs_f64();
        let pool_vetoes = match cross_check {
            CrossCheck::NotRequired => false,
            CrossCheck::Pending => true,
            CrossCheck::Offset(o) => (o.as_secs() - x).abs() > threshold,
        };
        panic || pool_vetoes
    }

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

    fn step(c: Correction) -> f64 {
        match c {
            Correction::Step(o) => o.as_secs(),
            other => panic!("expected Step, got {other:?}"),
        }
    }

    fn refused(c: Correction) -> f64 {
        match c {
            Correction::RefuseStep(o) => o.as_secs(),
            other => panic!("expected RefuseStep, got {other:?}"),
        }
    }

    fn fresh() -> Discipline {
        Discipline::new(DisciplineConfig::default(), None)
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
                Correction::Step(o) => {
                    self.phase -= o.as_secs();
                    self.steps += 1;
                }
                Correction::SetFrequency(p) => self.freq_ppm = p.value(),
                Correction::None | Correction::RefuseStep(_) => {}
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
        let s = step(d.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
        assert!((s - 0.5).abs() < 1e-12);
        let f = freq(d.update(&sel(0.5), CrossCheck::NotRequired, at(POLL)));
        assert!(f > 0.0, "slews forward, got {f}");
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
        let s = step(d.update(&sel(-0.7), CrossCheck::NotRequired, at(0)));
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
        let mut d = fresh();
        freq(d.update(&sel(0.001), CrossCheck::NotRequired, at(0)));
        let f = freq(d.update(&sel(10.0), CrossCheck::NotRequired, at(POLL)));
        assert!((f - 500.0).abs() < 1e-9, "got {f}");
        let f = freq(d.update(&sel(-10.0), CrossCheck::NotRequired, at(2 * POLL)));
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
        let mut d = fresh();
        let r = refused(d.update(&sel(2000.0), CrossCheck::NotRequired, at(0)));
        assert!((r - 2000.0).abs() < 1e-9);
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
        refused(d.update(&sel(0.5), CrossCheck::Pending, at(0)));
        assert!((d.drift().value() - 7.0).abs() < 1e-12);
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
        // The oscillator is worse than the loop can correct.
        let mut sim = Sim::new(0.0, 800.0, 0.0);
        let mut d = fresh();
        for _ in 0..500 {
            sim.poll(&mut d, 64);
            assert!(d.drift().value().abs() <= 500.0);
            assert!(sim.freq_ppm.abs() <= 500.0);
        }
    }

    #[test]
    fn pending_cross_check_refuses_step() {
        let mut d = fresh();
        let r = refused(d.update(&sel(0.5), CrossCheck::Pending, at(0)));
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
    fn not_required_cross_check_allows_step() {
        let mut d = fresh();
        step(d.update(&sel(0.5), CrossCheck::NotRequired, at(0)));
    }

    #[test]
    fn cross_check_never_blocks_slew() {
        let mut d = fresh();
        freq(d.update(&sel(0.05), CrossCheck::Pending, at(0)));
        let pool = CrossCheck::Offset(Offset::from_secs(-3.0));
        let f = freq(d.update(&sel(5.0), pool, at(POLL)));
        assert!((f - 500.0).abs() < 1e-9);
    }
}
