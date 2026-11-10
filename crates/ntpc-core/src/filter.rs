//! Per-source sample window.
//!
//! A short delay means the reply crossed the network with less queuing, so
//! its offset is less likely to be skewed by asymmetric paths. NTP practice
//! is to trust the lowest-delay sample of the last eight.

use std::collections::VecDeque;

use crate::Sample;

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
    pub fn push(&mut self, s: Sample) {
        if self.window.len() == WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(s);
    }

    /// The sample with the lowest delay. A tie goes to the newest sample.
    #[must_use]
    pub fn best(&self) -> Option<Sample> {
        self.window
            .iter()
            .copied()
            .reduce(|a, b| if b.delay <= a.delay { b } else { a })
    }
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
}
