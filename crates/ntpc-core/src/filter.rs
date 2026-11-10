//! Per-source sample window.
//!
//! A short delay means the reply crossed the network with less queuing, so
//! its offset is less likely to be skewed by asymmetric paths. NTP practice
//! is to trust the lowest-delay sample of the last eight.

use std::collections::VecDeque;

use std::time::Duration;

use crate::{Mono, Sample};

const WINDOW: usize = 8;

/// Keeps the last eight samples of one source.
#[derive(Debug, Clone, Default)]
pub struct SourceFilter {
    window: VecDeque<Sample>,
}

impl SourceFilter {
    /// An empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a sample and drops the oldest one when the window is full.
    ///
    /// A negative delay is impossible on a real path. Such a sample is
    /// ignored so it can never win as the lowest delay.
    pub fn push(&mut self, s: Sample) {
        if s.delay.as_secs() < 0.0 {
            return;
        }
        if self.window.len() == WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(s);
    }

    /// The sample with the lowest delay, however old it is.
    ///
    /// A tie goes to the newest sample. Callers that feed [`crate::select::select`]
    /// should use [`SourceFilter::best_fresh`]. The lowest-delay sample may be
    /// older than `max_age`, and `select` would then drop a healthy source.
    #[must_use]
    pub fn best(&self) -> Option<Sample> {
        lowest_delay(self.window.iter().copied())
    }

    /// The lowest-delay sample that is not older than `max_age`.
    ///
    /// A tie goes to the newest sample. Returns `None` if every sample is stale.
    #[must_use]
    pub fn best_fresh(&self, now: Mono, max_age: Duration) -> Option<Sample> {
        lowest_delay(
            self.window
                .iter()
                .copied()
                .filter(|s| now.saturating_duration_since(s.at) <= max_age),
        )
    }
}

/// Lowest delay wins. On a tie the later `at` wins, then the later in order.
fn lowest_delay(samples: impl Iterator<Item = Sample>) -> Option<Sample> {
    samples.reduce(|a, b| {
        if b.delay < a.delay || (b.delay == a.delay && b.at >= a.at) {
            b
        } else {
            a
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Delay, Mono, Offset, SourceId};

    fn sample(offset: f64, delay: f64, at: u64) -> Sample {
        Sample {
            source: SourceId::new(1),
            offset: Offset::from_secs(offset),
            delay: Delay::from_secs(delay),
            stratum: 2,
            unsynchronised: false,
            leap_alarm: false,
            at: Mono::from_nanos(at),
        }
    }

    #[test]
    fn filter_prefers_lowest_delay_sample() {
        let mut f = SourceFilter::new();
        f.push(sample(0.010, 0.050, 1));
        f.push(sample(0.002, 0.010, 2));
        f.push(sample(0.020, 0.080, 3));
        let best = f.best().expect("has samples");
        assert!((best.delay.as_secs() - 0.010).abs() < 1e-12);
        assert!((best.offset.as_secs() - 0.002).abs() < 1e-12);
    }

    #[test]
    fn filter_is_empty_until_pushed() {
        assert!(SourceFilter::new().best().is_none());
    }

    #[test]
    fn filter_forgets_samples_beyond_eight() {
        let mut f = SourceFilter::new();
        f.push(sample(0.0, 0.001, 0));
        for i in 1..=8 {
            f.push(sample(0.0, 0.100, i));
        }
        let best = f.best().expect("has samples");
        assert!((best.delay.as_secs() - 0.100).abs() < 1e-12);
    }

    #[test]
    fn best_fresh_skips_stale_low_delay_sample() {
        let mut f = SourceFilter::new();
        f.push(sample(0.001, 0.005, 1_000_000_000));
        f.push(sample(0.002, 0.050, 9_000_000_000));
        let now = Mono::from_nanos(10_000_000_000);
        let max_age = Duration::from_secs(5);
        let fresh = f.best_fresh(now, max_age).expect("fresh sample");
        assert!((fresh.delay.as_secs() - 0.050).abs() < 1e-12);
        let stale = f.best().expect("has samples");
        assert!((stale.delay.as_secs() - 0.005).abs() < 1e-12);
        assert!(f.best_fresh(now, Duration::from_millis(1)).is_none());
    }

    #[test]
    fn filter_ignores_negative_delay() {
        let mut f = SourceFilter::new();
        f.push(sample(0.0, -1.0, 1));
        assert!(f.best().is_none());
        f.push(sample(0.0, 0.020, 2));
        let best = f.best().expect("has samples");
        assert!((best.delay.as_secs() - 0.020).abs() < 1e-12);
    }

    #[test]
    fn filter_tie_prefers_newest_sample() {
        let mut f = SourceFilter::new();
        f.push(sample(0.001, 0.020, 5));
        f.push(sample(0.002, 0.020, 9));
        f.push(sample(0.003, 0.020, 7));
        assert_eq!(f.best().expect("has samples").at, Mono::from_nanos(9));
    }
}
