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
//!
//! Lower tiers are never probed. A lower tier with no observation inside
//! `reprobe_every` is not trusted as a fallback. If the active tier fails
//! and nothing fresh is working, [`TierChooser::active`] is `None`.

use std::time::Duration;

use crate::{Mono, Tier};

/// Highest priority first. The index of a tier in this list is its rank.
const TIERS: [Tier; 3] = [Tier::Config, Tier::Dhcp, Tier::Pool];

/// Tuning for [`TierChooser`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierConfig {
    /// Consecutive unusable rounds that make the active tier give way.
    /// Default 3. A value of 0 is treated as 1.
    pub failures_before_fallback: u32,
    /// How long a higher tier must stay usable before it takes over again.
    /// Default 10 minutes.
    pub stable_before_return: Duration,
    /// How long an observation stays fresh. A tier unobserved for this long
    /// is due a probe and is not trusted. Default 15 minutes.
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
    /// When the current active tier took over.
    active_since: Option<Mono>,
    /// True at start and whenever no tier is active. A usable higher tier
    /// then replaces the active one at once, so the order of first
    /// observations cannot pin the chooser to a low tier. Ends once the
    /// active tier has held for `stable_before_return`.
    bootstrapping: bool,
}

fn rank(tier: Tier) -> usize {
    TIERS.iter().position(|&t| t == tier).unwrap_or(TIERS.len())
}

impl TierChooser {
    /// A chooser with no active tier. A tier never observed is unusable.
    #[must_use]
    pub fn new(mut cfg: TierConfig) -> Self {
        // Zero would make every observation, even a usable one, a failure.
        cfg.failures_before_fallback = cfg.failures_before_fallback.max(1);
        Self {
            cfg,
            states: [TierState::default(); 3],
            active: None,
            active_since: None,
            bootstrapping: true,
        }
    }

    /// Records the result of one poll round for `tier`.
    ///
    /// Call it for the active tier and for probed higher tiers. A tier with
    /// no sources reports `usable = false`.
    pub fn observe(&mut self, tier: Tier, usable: bool, now: Mono) {
        let reprobe = self.cfg.reprobe_every;
        let state = &mut self.states[rank(tier)];
        let gap_too_long = state
            .last_observed
            .is_some_and(|prev| now.saturating_duration_since(prev) >= reprobe);
        state.last_observed = Some(now);
        if usable {
            state.failures = 0;
            // Probes a full reprobe interval apart prove nothing about the
            // time between them. The run starts again.
            if gap_too_long {
                state.usable_since = Some(now);
            } else {
                state.usable_since.get_or_insert(now);
            }
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
    /// A tier that is usable but not yet stable is due on every call, so the
    /// engine can build its stable run at the normal poll rate. Any other
    /// tier is due when it was never observed or `reprobe_every` has passed.
    /// With no active tier every tier counts as above it. Returns `None`
    /// when the active tier is already the highest.
    ///
    /// The chooser keeps no in-flight marker. The engine must not start a
    /// second probe of a tier while one is running.
    /// While `active()` is `None` the engine polls all tiers at the normal
    /// poll rate.
    #[must_use]
    pub fn due_probe(&self, now: Mono) -> Option<Tier> {
        let above = self.active.map_or(TIERS.len(), rank);
        TIERS[..above].iter().copied().find(|&tier| {
            let building = self.is_working(tier, now) && !self.is_stable(tier, now);
            let overdue = self.states[rank(tier)]
                .last_observed
                .is_none_or(|seen| now.saturating_duration_since(seen) >= self.cfg.reprobe_every);
            building || overdue
        })
    }

    /// Observed inside `reprobe_every`. Time going backwards counts as fresh.
    fn is_fresh(&self, tier: Tier, now: Mono) -> bool {
        self.states[rank(tier)]
            .last_observed
            .is_some_and(|seen| now.saturating_duration_since(seen) < self.cfg.reprobe_every)
    }

    fn is_working(&self, tier: Tier, now: Mono) -> bool {
        self.states[rank(tier)].usable_since.is_some() && self.is_fresh(tier, now)
    }

    fn is_stable(&self, tier: Tier, now: Mono) -> bool {
        self.is_working(tier, now)
            && self.states[rank(tier)].usable_since.is_some_and(|since| {
                now.saturating_duration_since(since) >= self.cfg.stable_before_return
            })
    }

    fn set_active(&mut self, tier: Option<Tier>, now: Mono) {
        if tier != self.active {
            self.active_since = tier.map(|_| now);
        }
        if tier.is_none() {
            self.bootstrapping = true;
        }
        self.active = tier;
    }

    fn reevaluate(&mut self, now: Mono) {
        let Some(active) = self.active else {
            // Nothing is active, so any working tier beats none.
            let best = TIERS.iter().copied().find(|&t| self.is_working(t, now));
            self.set_active(best, now);
            return;
        };
        if self.bootstrapping
            && self.active_since.is_some_and(|since| {
                now.saturating_duration_since(since) >= self.cfg.stable_before_return
            })
        {
            self.bootstrapping = false;
        }
        if self.states[rank(active)].failures >= self.cfg.failures_before_fallback {
            // Prefer a fresh lower tier. A higher one that has not earned its
            // return is a last resort, better than no time source at all.
            let next = TIERS[rank(active) + 1..]
                .iter()
                .copied()
                .find(|&t| self.is_working(t, now))
                .or_else(|| {
                    TIERS[..rank(active)]
                        .iter()
                        .copied()
                        .find(|&t| self.is_working(t, now))
                });
            self.set_active(next, now);
            return;
        }
        let higher = TIERS[..rank(active)].iter().copied().find(|&t| {
            if self.bootstrapping {
                self.is_working(t, now)
            } else {
                self.is_stable(t, now)
            }
        });
        if higher.is_some() {
            self.set_active(higher, now);
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

    /// Dhcp active and past bootstrap at 600 s.
    fn settled_dhcp() -> TierChooser {
        let mut c = chooser();
        c.observe(Tier::Dhcp, true, at(0));
        c.observe(Tier::Dhcp, true, at(600));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c
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
    fn stale_lower_tier_is_not_a_fallback() {
        let mut c = chooser();
        c.observe(Tier::Config, true, at(0));
        c.observe(Tier::Dhcp, true, at(0));
        // Dhcp is never probed while Config is active, so it goes stale.
        fail(&mut c, Tier::Config, 2000);
        assert_eq!(c.active(), None);
    }

    #[test]
    fn fresh_unstable_higher_tier_is_last_resort() {
        let mut c = settled_dhcp();
        c.observe(Tier::Config, true, at(700));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        fail(&mut c, Tier::Dhcp, 710);
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn higher_tier_waits_for_stable_period() {
        let mut c = settled_dhcp();
        c.observe(Tier::Config, true, at(660));
        c.observe(Tier::Config, true, at(900));
        c.observe(Tier::Config, true, at(1259));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(1260));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn does_not_flap() {
        let mut c = settled_dhcp();
        // Config comes and goes. Each break restarts the stable clock.
        c.observe(Tier::Config, true, at(700));
        c.observe(Tier::Config, true, at(1100));
        c.observe(Tier::Config, false, at(1200));
        c.observe(Tier::Config, true, at(1300));
        c.observe(Tier::Config, true, at(1700));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(1900));
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
    fn stale_run_does_not_count_as_stable() {
        let mut c = settled_dhcp();
        c.observe(Tier::Config, true, at(601));
        // Config was not seen for 999 s. The old run proves nothing.
        c.observe(Tier::Dhcp, true, at(1600));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(1601));
        assert_eq!(c.active(), Some(Tier::Dhcp));
    }

    #[test]
    fn probes_a_reprobe_interval_apart_are_not_stable() {
        let mut c = settled_dhcp();
        c.observe(Tier::Config, true, at(700));
        c.observe(Tier::Config, true, at(1600));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        c.observe(Tier::Config, true, at(2500));
        assert_eq!(c.active(), Some(Tier::Dhcp));
    }

    #[test]
    fn higher_tier_seen_later_wins_while_bootstrapping() {
        let mut c = chooser();
        c.observe(Tier::Pool, true, at(0));
        assert_eq!(c.active(), Some(Tier::Pool));
        c.observe(Tier::Config, true, at(1));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn bootstrap_restarts_when_active_becomes_none() {
        let mut c = settled_dhcp();
        fail(&mut c, Tier::Dhcp, 700);
        assert_eq!(c.active(), None);
        c.observe(Tier::Pool, true, at(800));
        c.observe(Tier::Config, true, at(801));
        assert_eq!(c.active(), Some(Tier::Config));
    }

    #[test]
    fn tier_with_no_sources_is_unusable() {
        let mut c = chooser();
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
    fn failed_tier_differs_from_unobserved_tier() {
        let mut c = chooser();
        c.observe(Tier::Config, false, at(0));
        c.observe(Tier::Pool, true, at(0));
        // Dhcp was never observed, so it is due. Config failed just now.
        assert_eq!(c.due_probe(at(1)), Some(Tier::Dhcp));
        c.observe(Tier::Dhcp, false, at(1));
        assert_eq!(c.due_probe(at(2)), None);
        assert_eq!(c.due_probe(at(900)), Some(Tier::Config));
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
        assert_eq!(c.due_probe(at(900)), None);
        assert_eq!(c.due_probe(at(901)), Some(Tier::Config));
        c.observe(Tier::Config, false, at(901));
        assert_eq!(c.due_probe(at(902)), Some(Tier::Dhcp));
    }

    #[test]
    fn tier_building_stability_is_due_on_every_call() {
        let mut c = settled_dhcp();
        c.observe(Tier::Config, true, at(700));
        assert_eq!(c.due_probe(at(701)), Some(Tier::Config));
        assert_eq!(c.due_probe(at(702)), Some(Tier::Config));
        assert_eq!(c.due_probe(at(1000)), Some(Tier::Config));
    }

    #[test]
    fn due_probe_is_none_when_active_is_highest() {
        let mut c = chooser();
        c.observe(Tier::Config, true, at(0));
        assert_eq!(c.due_probe(at(100_000)), None);
    }

    #[test]
    fn zero_failure_limit_is_treated_as_one() {
        let mut c = TierChooser::new(TierConfig {
            failures_before_fallback: 0,
            ..TierConfig::default()
        });
        c.observe(Tier::Config, true, at(0));
        c.observe(Tier::Dhcp, true, at(0));
        assert_eq!(c.active(), Some(Tier::Config));
        c.observe(Tier::Config, false, at(1));
        assert_eq!(c.active(), Some(Tier::Dhcp));
    }

    #[test]
    fn time_going_backwards_does_not_panic_or_switch() {
        let mut c = settled_dhcp();
        c.observe(Tier::Config, true, at(1000));
        c.observe(Tier::Config, true, at(500));
        c.observe(Tier::Dhcp, true, at(100));
        assert_eq!(c.active(), Some(Tier::Dhcp));
        let _ = c.due_probe(at(0));
    }
}
