//! The phase the engine's own slew has removed over time (ruling R50).
//!
//! The slew is the applied frequency minus the learned drift (R36). The
//! drift part only holds the clock's own error, so the slew alone moves
//! the offsets the sources report. A positive slew closes a positive
//! offset. A stored sample therefore reads now as its offset minus the
//! slew integrated from its time to now.
//!
//! A step is not corrected for. Every filter is cleared on a step, so no
//! stored sample spans one.

use std::collections::VecDeque;
use std::time::Duration;

use super::{Engine, PPM_PER_UNIT};
use crate::{Mono, Offset, Sample};

/// Slew history, one mark per change. The slew between two marks is
/// constant, so the integral is exact.
#[derive(Debug, Clone, Default)]
pub(super) struct Steer {
    /// When the slew changed, the phase removed by then in seconds, and
    /// the slew from then on in ppm.
    marks: VecDeque<(Mono, f64, f64)>,
}

impl Steer {
    /// Phase removed by `t`, in seconds. Before the first mark the clock
    /// was not steered.
    fn phase_at(&self, t: Mono) -> f64 {
        let Some(&(at, phase, ppm)) = self.marks.iter().rev().find(|m| m.0 <= t) else {
            return 0.0;
        };
        phase + ppm * PPM_PER_UNIT * t.saturating_duration_since(at).as_secs_f64()
    }

    /// The slew in effect now, in ppm.
    #[cfg(test)]
    pub(super) fn ppm(&self) -> f64 {
        self.marks.back().map_or(0.0, |m| m.2)
    }

    /// The slew changes to `ppm` at `now`. Marks older than `keep` are
    /// dropped, except the one that still covers that age.
    pub(super) fn set(&mut self, now: Mono, ppm: f64, keep: Duration) {
        let phase = self.phase_at(now);
        self.marks.push_back((now, phase, ppm));
        let cutoff = Mono::from_nanos(
            now.as_nanos()
                .saturating_sub(u64::try_from(keep.as_nanos()).unwrap_or(u64::MAX)),
        );
        while self.marks.len() > 1 && self.marks[1].0 <= cutoff {
            self.marks.pop_front();
        }
    }

    /// True when the history reaches back to `t`.
    pub(super) fn covers(&self, t: Mono) -> bool {
        self.marks.front().is_none_or(|m| t >= m.0)
    }

    /// Phase the slew removed between `at` and `now`, in seconds.
    ///
    /// A time before the oldest kept mark is read as that mark. The slew
    /// before it is pruned and unknown, so the correction covers at most
    /// the kept window. No caller needs more: stored samples and the jitter
    /// reading are no older than `max_age`.
    pub(super) fn since(&self, at: Mono, now: Mono) -> f64 {
        let at = self.marks.front().map_or(at, |m| at.max(m.0));
        if at >= now {
            return 0.0;
        }
        self.phase_at(now) - self.phase_at(at)
    }
}

impl Engine {
    /// The slew changes now. The one place that records it.
    pub(super) fn set_slew(&mut self, ppm: f64) {
        self.steer.set(self.now, ppm, self.cfg.selection.max_age);
    }

    /// A stored sample as it would read now.
    pub(super) fn corrected(&self, mut s: Sample) -> Sample {
        let removed = self.steer.since(s.at, self.now);
        s.offset = Offset::from_secs(s.offset.as_secs() - removed);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Action, EngineConfig, Event};
    use crate::{Delay, Ppm, SourceId, SourceSpec, Tier};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const NS: u64 = 1_000_000_000;

    fn at(secs: u64) -> Mono {
        Mono::from_nanos(secs * NS)
    }

    fn sample(offset: f64, t: Mono) -> Sample {
        Sample {
            source: SourceId::new(1),
            offset: Offset::from_secs(offset),
            delay: Delay::from_secs(0.010),
            stratum: 2,
            unsynchronised: false,
            leap_alarm: false,
            at: t,
        }
    }

    /// An engine with adjustment on, a saved drift of 20 ppm and one pool
    /// source.
    fn engine() -> Engine {
        let mut e = Engine::new(EngineConfig::default(), Some(Ppm::new(20.0)));
        let _ = e.handle(Event::AdjustmentAllowed(true));
        let _ = e.handle(Event::SourcesChanged(vec![SourceSpec {
            id: SourceId::new(1),
            tier: Tier::Pool,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 123),
            label: "s1".into(),
        }]));
        e
    }

    #[test]
    fn sample_before_a_frequency_change_reads_corrected_after_reads_raw() {
        let mut e = engine();
        // Slew 100 ppm from 0 s to 100 s, then none.
        e.change_frequency(Ppm::new(120.0));
        let before = sample(0.5, at(0));
        e.now = at(100);
        e.change_frequency(Ppm::new(20.0));
        let after = sample(0.5, at(100));
        e.now = at(200);
        // 100 ppm for 100 s removed 10 ms from the older reading.
        let c = e.corrected(before).offset.as_secs();
        assert!((c - 0.490).abs() < 1e-12, "{c}");
        assert!((e.corrected(after).offset.as_secs() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn correction_integrates_each_slew_over_its_own_span() {
        let mut s = Steer::default();
        let keep = Duration::from_secs(1024);
        s.set(at(0), 100.0, keep);
        s.set(at(10), -50.0, keep);
        // 100 ppm for 10 s, then -50 ppm for 20 s.
        let got = s.since(at(0), at(30));
        assert!((got - (1e-3 - 1e-3)).abs() < 1e-15, "{got}");
        assert!((s.since(at(5), at(10)) - 5e-4).abs() < 1e-15);
        assert!(s.since(at(30), at(30)).abs() < f64::EPSILON);
        assert!((s.ppm() + 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn old_marks_are_pruned_but_cover_the_kept_window() {
        let mut s = Steer::default();
        let keep = Duration::from_secs(100);
        for i in 0..50 {
            s.set(at(i * 10), 10.0, keep);
        }
        assert!(s.marks.len() <= 12, "{}", s.marks.len());
        // A sample 100 s old is still fully corrected.
        assert!((s.since(at(390), at(490)) - 1e-3).abs() < 1e-15);
    }

    #[test]
    fn step_clears_the_filters_so_nothing_spans_it() {
        let mut e = engine();
        // The first round runs while no tier is active, so it only makes
        // the pool active. The second round feeds the loop.
        let _ = e.handle(Event::Sample(sample(5.0, at(1))));
        let _ = e.handle(Event::Tick(at(64)));
        let acts = e.handle(Event::Sample(sample(5.0, at(65))));
        assert!(acts.iter().any(|a| matches!(a, Action::Step(_))));
        assert!(e.sources.values().all(|s| s.filter.best().is_none()));
        // After the step the clock runs at the drift, so no slew.
        assert!(e.steer.ppm().abs() < 1e-12);
    }

    #[test]
    fn no_correction_while_the_gate_is_closed() {
        let mut e = engine();
        e.change_frequency(Ppm::new(120.0));
        e.now = at(50);
        let _ = e.handle(Event::AdjustmentAllowed(false));
        let s = sample(0.5, at(50));
        e.now = at(500);
        // The engine no longer steers, so a reading from the close on
        // reads raw. One from before reads the 50 s of slew.
        assert!((e.corrected(s).offset.as_secs() - 0.5).abs() < 1e-12);
        let old = e.corrected(sample(0.5, at(0))).offset.as_secs();
        assert!((old - 0.495).abs() < 1e-12, "{old}");
    }

    #[test]
    fn clock_failure_keeps_the_last_slew() {
        // Ruling R52: after a failed command the OS keeps its last rate,
        // so the clock goes on slewing and stored readings still move.
        let mut e = engine();
        e.change_frequency(Ppm::new(120.0));
        let s = sample(0.5, at(0));
        e.now = at(50);
        let _ = e.handle(Event::ClockResult(Err(crate::ClockError::Unavailable)));
        assert!(!e.status().adjustment_allowed);
        assert!((e.steer.ppm() - 100.0).abs() < 1e-12);
        e.now = at(100);
        // 100 ppm for 100 s, the failure did not stop it.
        let c = e.corrected(s).offset.as_secs();
        assert!((c - 0.490).abs() < 1e-12, "{c}");
        // The re-arm sets the learned drift, so the slew is zero again. A
        // host close records zero (`no_correction_while_the_gate_is_closed`).
        let _ = e.handle(Event::AdjustmentAllowed(false));
        let _ = e.handle(Event::AdjustmentAllowed(true));
        assert!(e.status().adjustment_allowed);
        assert!(e.steer.ppm().abs() < 1e-12);
    }

    /// 100 ppm for 10 000 s (1 s of phase), then no slew, re-marked every
    /// 2000 s so the early marks are pruned.
    fn long_history() -> Steer {
        let mut s = Steer::default();
        let keep = Duration::from_secs(1024);
        s.set(at(0), 100.0, keep);
        for t in (10_000..=20_000).step_by(2000) {
            s.set(at(t), 0.0, keep);
        }
        s
    }

    #[test]
    fn time_before_the_oldest_kept_mark_is_clamped_to_it() {
        let s = long_history();
        let first = s.marks.front().expect("kept").0;
        assert!(first > at(10_000), "early marks pruned");
        // Unclamped, the pruned time would read the whole 1 s of history.
        // The kept window holds no slew, so the correction is zero.
        assert!(s.since(at(5000), at(20_000)).abs() < 1e-12);
        let a = s.since(at(5000), at(20_000));
        let b = s.since(first, at(20_000));
        assert!((a - b).abs() < 1e-15);
    }

    #[test]
    fn reading_older_than_the_slew_history_is_not_compared_for_jitter() {
        use crate::select::Selection;
        let mut e = engine();
        e.steer = long_history();
        e.now = at(20_000);
        e.poll = Duration::from_secs(256);
        // A reading from before a long outage.
        e.prev_offset = Some((Offset::from_secs(0.0), at(0)));
        e.adapt_poll(&Selection {
            offset: Offset::from_secs(0.0),
            error_bound: Duration::from_millis(15),
            survivors: vec![SourceId::new(1)],
        });
        assert_eq!(e.poll, Duration::from_secs(256), "no spurious reset");
        assert_eq!(e.prev_offset, Some((Offset::from_secs(0.0), at(20_000))));
    }
}
