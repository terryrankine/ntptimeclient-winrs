//! Choice of the active source tier.
//!
//! Tiers have a strict priority: config, then DHCP, then the global pool.
//! Exactly one tier is active. The engine selects inside it and never mixes
//! samples across tiers, so a flaky operator server cannot be averaged with
//! a pool server.
//!
//! The engine decides per poll round whether a tier was usable. A tier is
//! usable when it produced a selection from fresh samples. It reports that
//! through [`TierChooser::observe`]. Probing a higher tier feeds `observe`
//! only. Those samples never reach selection.

use std::time::Duration;

use crate::{Mono, Tier};

/// Highest priority first. The index of a tier in this list is its rank.
const TIERS: [Tier; 3] = [Tier::Config, Tier::Dhcp, Tier::Pool];

/// Tuning for [`TierChooser`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierConfig {
    /// Consecutive unusable rounds that make the active tier give way.
    /// Default 3.
    pub failures_before_fallback: u32,
    /// How long a higher tier must stay usable before it takes over again.
    /// Default 10 minutes.
    pub stable_before_return: Duration,
    /// How long a higher tier may go unobserved before it is due a probe.
    /// Default 15 minutes.
    pub reprobe_every: Duration,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            failures_before_fallback: 3,
            stable_before_return: Duration::from_secs(10 * 60),
            reprobe_every: Duration::from_secs(15 * 60),
        }
    }
}

/// What the chooser remembers about one tier.
#[derive(Debug, Clone, Copy, Default)]
struct TierState {
    /// Rounds in a row that were unusable.
    failures: u32,
    /// Start of the current unbroken run of usable rounds.
    usable_since: Option<Mono>,
    /// Time of the latest observation of any kind.
    last_observed: Option<Mono>,
}

/// Decides which tier is active.
#[derive(Debug, Clone)]
pub struct TierChooser {
    cfg: TierConfig,
    states: [TierState; 3],
    active: Option<Tier>,
}

fn rank(tier: Tier) -> usize {
    TIERS.iter().position(|&t| t == tier).unwrap_or(TIERS.len())
}

impl TierChooser {
    /// A chooser with no active tier. A tier never observed is unusable.
    #[must_use]
    pub fn new(cfg: TierConfig) -> Self {
        Self {
            cfg,
            states: [TierState::default(); 3],
            active: None,
        }
    }

    /// Records the result of one poll round for `tier`.
    ///
    /// Call it for the active tier and for probed higher tiers. A tier with
    /// no sources reports `usable = false`.
    pub fn observe(&mut self, tier: Tier, usable: bool, now: Mono) {
        let state = &mut self.states[rank(tier)];
        state.last_observed = Some(now);
        if usable {
            state.failures = 0;
            // Keep the run start. Only an unusable round resets it.
            state.usable_since.get_or_insert(now);
        } else {
            state.failures = state.failures.saturating_add(1);
            state.usable_since = None;
        }
        self.reevaluate(now);
    }

    /// The tier selection must stay inside, if any tier is working.
    #[must_use]
    pub fn active(&self) -> Option<Tier> {
        self.active
    }

    /// The highest tier above the active one that is due a probe.
    ///
    /// A tier is due when it was never observed or when `reprobe_every` has
    /// passed. With no active tier every tier counts as above it. Returns
    /// `None` when the active tier is already the highest.
    #[must_use]
    pub fn due_probe(&self, now: Mono) -> Option<Tier> {
        let above = self.active.map_or(TIERS.len(), rank);
        TIERS[..above].iter().copied().find(|&tier| {
            self.states[rank(tier)]
                .last_observed
                .is_none_or(|seen| now.saturating_duration_since(seen) >= self.cfg.reprobe_every)
        })
    }

    fn is_working(&self, tier: Tier) -> bool {
        self.states[rank(tier)].usable_since.is_some()
    }

    fn is_stable(&self, tier: Tier, now: Mono) -> bool {
        self.states[rank(tier)].usable_since.is_some_and(|since| {
            now.saturating_duration_since(since) >= self.cfg.stable_before_return
        })
    }

    fn reevaluate(&mut self, now: Mono) {
        let Some(active) = self.active else {
            // Nothing is active, so any working tier beats none. No wait for
            // stability, because there is nothing to flap away from.
            self.active = TIERS.iter().copied().find(|&t| self.is_working(t));
            return;
        };
        if self.states[rank(active)].failures >= self.cfg.failures_before_fallback {
            // Only lower tiers are fallbacks. A higher tier must earn its
            // way back through the stable period.
            self.active = TIERS[rank(active) + 1..]
                .iter()
                .copied()
                .find(|&t| self.is_working(t));
            return;
        }
        if let Some(higher) = TIERS[..rank(active)]
            .iter()
            .copied()
            .find(|&t| self.is_stable(t, now))
        {
            self.active = Some(higher);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> Mono {
        Mono::from_nanos(secs * 1_000_000_000)
    }

    fn chooser() -> TierChooser {
        TierChooser::new(TierConfig::default())
    }

    /// Fails a tier three rounds in a row.
    fn fail(c: &mut TierChooser, tier: Tier, from: u64) {
        for i in 0..3 {
            c.observe(tier, false, at(from + i));
        }
    }

    #[test]
    fn uses_config_tier_when_usable() {
        let mut c = chooser();
        assert_eq!(c.active(), None);
        c.observe(Tier::Config, true, at(0));
        c.observe(Tier::Dhcp, true, at(0));
        c.observe(Tier::Pool, true, at(0));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn falls_to_dhcp_after_n_failures() {
        let mut c = chooser();
        c.observe(Tier::Config, true, at(0));
        c.observe(Tier::Dhcp, true, at(0));
        c.observe(Tier::Config, false, at(10));
        c.observe(Tier::Config, false, at(20));
        assert_eq!(c.active(), Some(Tier::Config));
        c.observe(Tier::Config, false, at(30));
        assert_eq!(c.active(), Some(Tier::Dhcp));
    }

    #[test]
    fn falls_to_none_when_every_tier_failed() {
        let mut c = chooser();
        c.observe(Tier::Config, true, at(0));
        fail(&mut c, Tier::Config, 10);
        assert_eq!(c.active(), None);
    }

    #[test]
    fn selection_never_mixes_tiers() {
        let mut c = chooser();
        c.observe(Tier::Dhcp, true, at(0));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        // Config is usable but has not been stable long enough.
        c.observe(Tier::Config, true, at(60));
        c.observe(Tier::Config, true, at(300));
        c.observe(Tier::Config, true, at(659));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(660));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn does_not_flap() {
        let mut c = chooser();
        c.observe(Tier::Dhcp, true, at(0));
        // Config comes and goes. Each break restarts the stable clock.
        c.observe(Tier::Config, true, at(100));
        c.observe(Tier::Config, true, at(500));
        c.observe(Tier::Config, false, at(600));
        c.observe(Tier::Config, true, at(700));
        c.observe(Tier::Config, true, at(1000));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(1300));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn returns_to_higher_tier_only_after_stable_period() {
        let mut c = chooser();
        c.observe(Tier::Config, true, at(0));
        c.observe(Tier::Dhcp, true, at(0));
        fail(&mut c, Tier::Config, 10);
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(1000));
        c.observe(Tier::Config, true, at(1599));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(1600));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn tier_with_no_sources_is_unusable() {
        let mut c = chooser();
        // The engine reports a tier with no sources as unusable.
        c.observe(Tier::Config, false, at(0));
        assert_eq!(c.active(), None);
        c.observe(Tier::Pool, true, at(1));
        assert_eq!(c.active(), Some(Tier::Pool));
        c.observe(Tier::Config, false, at(2));
        c.observe(Tier::Config, false, at(3));
        c.observe(Tier::Config, false, at(4000));
        assert_eq!(c.active(), Some(Tier::Pool));
    }

    #[test]
    fn due_probe_returns_higher_tier_on_schedule() {
        let mut c = chooser();
        c.observe(Tier::Pool, true, at(0));
        // A tier never observed is due. The highest due tier wins.
        assert_eq!(c.due_probe(at(1)), Some(Tier::Config));
        c.observe(Tier::Config, false, at(1));
        c.observe(Tier::Dhcp, false, at(1));
        assert_eq!(c.due_probe(at(2)), None);
        assert_eq!(c.due_probe(at(1 + 899)), None);
        assert_eq!(c.due_probe(at(1 + 900)), Some(Tier::Config));
        c.observe(Tier::Config, false, at(901));
        assert_eq!(c.due_probe(at(902)), Some(Tier::Dhcp));
    }

    #[test]
    fn due_probe_is_none_when_active_is_highest() {
        let mut c = chooser();
        c.observe(Tier::Config, true, at(0));
        assert_eq!(c.due_probe(at(100_000)), None);
    }
}
