//! Source selection by the largest agreeing cluster.
//!
//! Each source claims its offset is right within a bound. The bound is half
//! the round-trip delay, because the true offset cannot be further off than
//! the path allows. Sources whose intervals overlap agree. A falseticker
//! sits alone, so the largest overlap is the truth. This is the Marzullo
//! idea that NTP selection uses.

use std::time::Duration;

use crate::{Delay, Mono, Offset, Sample, SourceId};

/// Tuning for [`select`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionConfig {
    /// Fewest agreeing sources that make a result. Default 1.
    pub min_survivors: usize,
    /// Highest stratum accepted. Default 15.
    pub max_stratum: u8,
    /// Oldest sample accepted, measured from `now`.
    pub max_age: Duration,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            min_survivors: 1,
            max_stratum: 15,
            max_age: Duration::from_secs(1024),
        }
    }
}

/// The agreed time offset and the sources that agree on it.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// Combined offset of the survivors.
    pub offset: Offset,
    /// Combined error bound of the survivors.
    pub error_bound: Duration,
    /// Survivors, in ascending id order.
    pub survivors: Vec<SourceId>,
}

/// Delay floor so a zero delay does not give an infinite weight.
const MIN_DELAY_SECS: f64 = 1e-6;

/// Cap on the reported error bound. Far beyond any real path.
const MAX_ERROR_BOUND: Duration = Duration::from_secs(86_400);

fn usable(s: &Sample, now: Mono, cfg: &SelectionConfig) -> bool {
    // Stratum 0 is a kiss-of-death or unspecified.
    s.stratum >= 1
        && s.stratum <= cfg.max_stratum
        && !s.unsynchronised
        && !s.leap_alarm
        // A negative delay is impossible and would get the largest weight.
        && s.delay.as_secs() >= 0.0
        && now.saturating_duration_since(s.at) <= cfg.max_age
}

fn bound(delay: Delay) -> f64 {
    delay.as_secs().max(0.0) / 2.0
}

/// Picks the sources that agree and combines their offsets.
///
/// Returns `None` when no cluster holds a strict majority of the usable
/// sources, or when it holds fewer than `min_survivors`. If a source has
/// several samples, only its lowest-delay one counts.
#[must_use]
pub fn select(samples: &[Sample], now: Mono, cfg: &SelectionConfig) -> Option<Selection> {
    // One vote per source, or a chatty source could outvote the rest.
    let mut cands: Vec<Sample> = Vec::new();
    for s in samples.iter().filter(|s| usable(s, now, cfg)) {
        match cands.iter_mut().find(|c| c.source == s.source) {
            // On a delay tie the newest sample wins, as in `SourceFilter`.
            Some(c) if s.delay < c.delay || (s.delay == c.delay && s.at > c.at) => *c = *s,
            Some(_) => {}
            None => cands.push(*s),
        }
    }
    if cands.is_empty() {
        return None;
    }

    // Sweep the interval edges. Lower edges sort before upper edges at a tie
    // so that touching intervals count as overlapping.
    let mut edges: Vec<(f64, i32)> = Vec::with_capacity(cands.len() * 2);
    for c in &cands {
        let (o, b) = (c.offset.as_secs(), bound(c.delay));
        edges.push((o - b, 1));
        edges.push((o + b, -1));
    }
    edges.sort_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)));

    let (mut depth, mut best_depth, mut point) = (0, 0, 0.0);
    for (x, kind) in edges {
        depth += kind;
        if depth > best_depth {
            best_depth = depth;
            point = x;
        }
    }

    let mut survivors: Vec<Sample> = cands
        .iter()
        .copied()
        .filter(|c| {
            let (o, b) = (c.offset.as_secs(), bound(c.delay));
            o - b <= point && point <= o + b
        })
        .collect();
    let n = survivors.len();
    // A lone cluster must hold a majority, or two disagreeing sources would
    // pick a winner by chance.
    if n < cfg.min_survivors.max(1) || n * 2 <= cands.len() {
        return None;
    }
    survivors.sort_by_key(|s| s.source);

    let weights: Vec<f64> = survivors
        .iter()
        .map(|s| 1.0 / s.delay.as_secs().max(MIN_DELAY_SECS))
        .collect();
    let total: f64 = weights.iter().sum();
    let (mut offset, mut err) = (0.0, 0.0);
    for (s, w) in survivors.iter().zip(&weights) {
        offset += s.offset.as_secs() * w / total;
        err += bound(s.delay) * w / total;
    }

    Some(Selection {
        offset: Offset::from_secs(offset),
        error_bound: Duration::try_from_secs_f64(err)
            .map_or(MAX_ERROR_BOUND, |d| d.min(MAX_ERROR_BOUND)),
        survivors: survivors.iter().map(|s| s.source).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 10_000_000_000;

    fn s(id: u32, offset: f64, delay: f64) -> Sample {
        Sample {
            source: SourceId::new(id),
            offset: Offset::from_secs(offset),
            delay: Delay::from_secs(delay),
            stratum: 2,
            unsynchronised: false,
            leap_alarm: false,
            at: Mono::from_nanos(NOW),
        }
    }

    fn now() -> Mono {
        Mono::from_nanos(NOW)
    }

    #[test]
    fn rejects_falseticker_when_majority_agrees() {
        let v = [s(1, 0.001, 0.020), s(2, 0.002, 0.020), s(3, 5.0, 0.020)];
        let sel = select(&v, now(), &SelectionConfig::default()).expect("selected");
        assert_eq!(sel.survivors, vec![SourceId::new(1), SourceId::new(2)]);
        assert!(sel.offset.as_secs() < 0.01);
    }

    #[test]
    fn single_source_is_selected_without_cross_check() {
        let v = [s(1, 0.5, 0.040)];
        let sel = select(&v, now(), &SelectionConfig::default()).expect("selected");
        assert_eq!(sel.survivors, vec![SourceId::new(1)]);
        assert!((sel.offset.as_secs() - 0.5).abs() < 1e-12);
        assert!((sel.error_bound.as_secs_f64() - 0.020).abs() < 1e-12);
    }

    #[test]
    fn ignores_stratum_zero_unsynchronised_and_leap_alarm() {
        let cfg = SelectionConfig::default();
        let mut zero = s(1, 0.0, 0.01);
        zero.stratum = 0;
        let mut unsync = s(2, 0.0, 0.01);
        unsync.unsynchronised = true;
        let mut alarm = s(3, 0.0, 0.01);
        alarm.leap_alarm = true;
        let mut high = s(4, 0.0, 0.01);
        high.stratum = 16;
        assert!(select(&[zero, unsync, alarm, high], now(), &cfg).is_none());
        let good = s(5, 0.3, 0.01);
        let sel = select(&[zero, unsync, alarm, high, good], now(), &cfg).expect("selected");
        assert_eq!(sel.survivors, vec![SourceId::new(5)]);
    }

    #[test]
    fn drops_samples_older_than_max_age() {
        let mut old = s(1, 0.0, 0.01);
        old.at = Mono::from_nanos(NOW - 2_000_000_000);
        let cfg = SelectionConfig {
            max_age: Duration::from_secs(1),
            ..SelectionConfig::default()
        };
        assert!(select(&[old], now(), &cfg).is_none());
        let fresh = s(2, 0.0, 0.01);
        let sel = select(&[old, fresh], now(), &cfg).expect("selected");
        assert_eq!(sel.survivors, vec![SourceId::new(2)]);
    }

    #[test]
    fn prefers_low_delay_among_agreeing_sources() {
        let v = [s(1, 0.010, 0.100), s(2, 0.000, 0.002)];
        let sel = select(&v, now(), &SelectionConfig::default()).expect("selected");
        assert_eq!(sel.survivors.len(), 2);
        // Weight 1/delay pulls the result to the low-delay source.
        assert!(sel.offset.as_secs() < 0.001);
    }

    #[test]
    fn min_survivors_two_rejects_single_source() {
        let cfg = SelectionConfig {
            min_survivors: 2,
            ..SelectionConfig::default()
        };
        assert!(select(&[s(1, 0.0, 0.01)], now(), &cfg).is_none());
        assert!(select(&[s(1, 0.0, 0.01), s(2, 0.001, 0.01)], now(), &cfg).is_some());
    }

    #[test]
    fn two_disagreeing_sources_give_none() {
        let v = [s(1, 0.0, 0.01), s(2, 1.0, 0.01)];
        assert!(select(&v, now(), &SelectionConfig::default()).is_none());
    }

    #[test]
    fn two_of_four_split_gives_none() {
        let v = [
            s(1, 0.0, 0.01),
            s(2, 0.001, 0.01),
            s(3, 2.0, 0.01),
            s(4, 2.001, 0.01),
        ];
        assert!(select(&v, now(), &SelectionConfig::default()).is_none());
    }

    #[test]
    fn touching_intervals_agree() {
        // Bounds are 0.5 s each, so the intervals meet at exactly 0.5.
        let v = [s(1, 0.0, 1.0), s(2, 1.0, 1.0)];
        let sel = select(&v, now(), &SelectionConfig::default()).expect("selected");
        assert_eq!(sel.survivors.len(), 2);
    }

    #[test]
    fn zero_delay_sources_sweep_and_weight() {
        let v = [s(1, 0.25, 0.0), s(2, 0.25, 0.0), s(3, 9.0, 0.0)];
        let sel = select(&v, now(), &SelectionConfig::default()).expect("selected");
        assert_eq!(sel.survivors, vec![SourceId::new(1), SourceId::new(2)]);
        assert!((sel.offset.as_secs() - 0.25).abs() < 1e-12);
        assert_eq!(sel.error_bound, Duration::ZERO);
    }

    #[test]
    fn negative_delay_is_never_selected() {
        let cfg = SelectionConfig::default();
        assert!(select(&[s(1, 0.0, -0.5)], now(), &cfg).is_none());
        let sel = select(&[s(1, 7.0, -0.5), s(2, 0.1, 0.02)], now(), &cfg).expect("selected");
        assert_eq!(sel.survivors, vec![SourceId::new(2)]);
    }

    #[test]
    fn delay_tie_prefers_newest_sample_of_a_source() {
        let mut older = s(1, 0.1, 0.02);
        older.at = Mono::from_nanos(NOW - 5);
        let newer = s(1, 0.2, 0.02);
        for v in [[older, newer], [newer, older]] {
            let sel = select(&v, now(), &SelectionConfig::default()).expect("selected");
            assert!((sel.offset.as_secs() - 0.2).abs() < 1e-12);
        }
    }

    #[test]
    fn huge_delay_clamps_error_bound() {
        let sel =
            select(&[s(1, 0.0, 1e300)], now(), &SelectionConfig::default()).expect("selected");
        assert_eq!(sel.error_bound, MAX_ERROR_BOUND);
    }
}
