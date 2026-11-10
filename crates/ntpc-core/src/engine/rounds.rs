//! Poll rounds and their schedule. One round per tier at a time.

use std::time::Duration;

use super::Action;
use super::{Engine, POPCORN_FLOOR, POPCORN_RATIO, TIERS, slot};
use crate::select::{Selection, select};
use crate::{Mono, Sample, SourceId, Tier};

/// One poll round of one tier. A tier runs one round at a time, which is
/// the probe dedupe the tier chooser asks for.
#[derive(Debug, Clone)]
pub(super) struct Round {
    pub(super) started: Mono,
    pub(super) waiting: Vec<SourceId>,
    /// Sent while the tier was not active. Such a round may switch the
    /// tier but never feeds the clock.
    pub(super) observe_only: bool,
    /// Sent before a resume. Its replies hold the sleep and are dropped.
    pub(super) stale: bool,
}

impl Engine {
    pub(super) fn round_of(&self, id: SourceId) -> Option<&Round> {
        self.rounds
            .iter()
            .flatten()
            .find(|r| r.waiting.contains(&id))
    }

    pub(super) fn schedule(&mut self, out: &mut Vec<Action>) {
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
            let every = if probe == Some(t) {
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

    pub(super) fn wants(&self, tier: Tier, every: Duration) -> bool {
        let i = slot(tier);
        self.rounds[i].is_none()
            && (self.recheck[i]
                || self.last_round[i]
                    .is_none_or(|l| self.now.saturating_duration_since(l) >= every))
    }

    pub(super) fn due_at(&self, tier: Tier, every: Duration) -> Option<Mono> {
        let i = slot(tier);
        if self.rounds[i].is_some() {
            return None;
        }
        self.last_round[i].map_or(Some(self.now), |l| l.checked_add(every))
    }

    pub(super) fn start_round(&mut self, tier: Tier, out: &mut Vec<Action>) {
        let now = self.now;
        let i = slot(tier);
        self.last_round[i] = Some(now);
        self.recheck[i] = false;
        let observe_only = self.tiers.active() != Some(tier);
        let mut waiting = Vec::new();
        for src in self.sources.values_mut() {
            if src.spec.tier == tier && src.may_query(now) {
                src.prev_query = src.last_query;
                src.last_query = Some(now);
                waiting.push(src.spec.id);
                out.push(Action::Query {
                    source: src.spec.id,
                    observe_only,
                });
            }
        }
        // A tier with nothing to ask is judged at once from its stored
        // fresh samples. With no sources it has none and is unusable. With
        // every source silenced by KoD or held by a RATE floor, its stored
        // samples may still make it usable.
        let empty = waiting.is_empty();
        self.rounds[i] = Some(Round {
            started: now,
            waiting,
            observe_only,
            stale: false,
        });
        if empty {
            self.close_round(tier, out);
        }
    }

    pub(super) fn answered(&mut self, id: SourceId, out: &mut Vec<Action>) {
        for t in TIERS {
            let Some(round) = self.rounds[slot(t)].as_mut() else {
                continue;
            };
            let Some(pos) = round.waiting.iter().position(|&w| w == id) else {
                continue;
            };
            round.waiting.swap_remove(pos);
            if round.waiting.is_empty() {
                self.close_round(t, out);
            }
            return;
        }
    }

    pub(super) fn close_round(&mut self, tier: Tier, out: &mut Vec<Action>) {
        let Some(round) = self.rounds[slot(tier)].take() else {
            return;
        };
        if round.stale {
            // The resume set a recheck, so a fresh round follows.
            return;
        }
        let picked = self.select_now(tier);
        let before = self.tiers.active();
        // Lower tiers are never observed. The pool cross-check is such a
        // tier. Its samples only veto steps.
        if before.is_none_or(|a| tier <= a) {
            self.tiers.observe(tier, picked.is_some(), self.now);
            self.last_observed[slot(tier)] = Some(self.now);
            self.note_tier_change(before, out);
            if before.is_none() && self.tiers.active().is_none() {
                self.back_off_idle(tier, picked.is_some());
            }
        }
        // A switch made by observe-only samples does not feed the clock. The
        // next regular round of the tier does.
        // Only a usable tier feeds the loop.
        if !round.observe_only && self.tiers.active() == Some(tier) && picked.is_some() {
            self.feed_loop(tier, out);
        }
    }

    /// While no tier works, every tier failing in turn doubles the poll, so
    /// an offline machine does not query every minute forever.
    pub(super) fn back_off_idle(&mut self, tier: Tier, usable: bool) {
        if usable {
            self.idle_failed = [false; 3];
            return;
        }
        self.idle_failed[slot(tier)] = true;
        if self.idle_failed.iter().all(|&f| f) {
            self.poll = self.poll.saturating_mul(2).min(self.cfg.max_poll);
            self.idle_failed = [false; 3];
        }
    }

    /// Selection inside one tier only. Tiers are never mixed.
    pub(super) fn select_in(&self, tier: Tier, max_age: Duration) -> Option<Selection> {
        let samples: Vec<Sample> = self
            .sources
            .values()
            .filter(|s| s.spec.tier == tier)
            .filter_map(|s| s.filter.best_fresh(self.now, max_age))
            .collect();
        select(&samples, self.now, &self.cfg.selection)
    }

    /// Selection for tier usability. Like [`Engine::select_in`], but each
    /// stored offset is corrected for the slew applied since it was taken
    /// (ruling R50). Samples from different polls then measure the same
    /// clock, so a fast slew cannot make agreeing sources disagree.
    pub(super) fn select_now(&self, tier: Tier) -> Option<Selection> {
        let max_age = self.cfg.selection.max_age;
        let samples: Vec<Sample> = self
            .sources
            .values()
            .filter(|s| s.spec.tier == tier)
            .filter_map(|s| s.filter.best_fresh(self.now, max_age))
            .map(|s| self.corrected(s))
            .collect();
        select(&samples, self.now, &self.cfg.selection)
    }

    /// Selection that may feed the loop. Per source, the best sample taken
    /// after the last one the loop considered and after the last frequency
    /// change. An older one was already used or measured a clock that has
    /// moved since, so it can neither feed the loop again nor decide a step.
    /// A delay spike is left out (see [`POPCORN_RATIO`]). It still counts
    /// for tier usability. Returns the kept samples and whether any new
    /// sample was dropped as a spike.
    pub(super) fn new_samples(&self, tier: Tier) -> (Vec<Sample>, bool) {
        let max_age = self.cfg.selection.max_age;
        let mut spiked = false;
        let mut kept = Vec::new();
        for s in self.sources.values().filter(|s| s.spec.tier == tier) {
            let Some(age) = self.window(s.fed_until.max(self.freq_changed_at), max_age) else {
                continue;
            };
            let Some(new) = s.filter.best_fresh(self.now, age) else {
                continue;
            };
            // The best of the last eight includes `new`, so a source with
            // one sample, or a path that stays slow for eight samples, is
            // never a spike.
            let best = s.filter.best().map_or(new.delay, |b| b.delay).as_secs();
            let d = new.delay.as_secs();
            if d > POPCORN_RATIO * best && d > POPCORN_FLOOR.as_secs_f64() {
                spiked = true;
            } else {
                kept.push(new);
            }
        }
        (kept, spiked)
    }

    /// Feeds the loop from new samples of the active tier, if any.
    ///
    /// The new samples feed the loop only if every one of their survivors
    /// also survives a vote of the whole tier. In that vote each source
    /// casts its new sample if it has one, else its best fresh sample.
    /// Without the vote, sources with nothing new (lost reply, timeout,
    /// kiss-of-death) would leave a falseticker to win alone. A source's
    /// own new sample is used rather than its best of eight, so a source
    /// that has just turned false cannot vote with an old good sample, and
    /// one that has just turned good is not held back by an old bad one.
    /// When the vote refuses, nothing is fed and the samples stay unused.
    pub(super) fn feed_loop(&mut self, tier: Tier, out: &mut Vec<Action>) {
        let (kept, spiked) = self.new_samples(tier);
        if kept.is_empty() {
            // Every new reading was a spike. Poll fast so a path that has
            // really turned slow is learned in eight short polls, not eight
            // long ones.
            if spiked {
                self.poll = self.cfg.min_poll;
            }
            return;
        }
        let Some(sel) = select(&kept, self.now, &self.cfg.selection) else {
            return;
        };
        let max_age = self.cfg.selection.max_age;
        let vote: Vec<Sample> = self
            .sources
            .values()
            .filter(|s| s.spec.tier == tier)
            .filter_map(|s| {
                kept.iter()
                    .find(|k| k.source == s.spec.id)
                    .copied()
                    .or_else(|| s.filter.best_fresh(self.now, max_age))
            })
            // The vote compares readings from different polls. Bring them
            // to now (ruling R50). The fed selection stays raw.
            .map(|s| self.corrected(s))
            .collect();
        let Some(tier_vote) = select(&vote, self.now, &self.cfg.selection) else {
            return;
        };
        if !sel
            .survivors
            .iter()
            .all(|id| tier_vote.survivors.contains(id))
        {
            return;
        }
        for k in &kept {
            if let Some(src) = self.sources.get_mut(&k.source) {
                src.fed_until = Some(k.at);
            }
        }
        self.update(tier, &sel, out);
    }
}
