//! Name resolution for the loop: when to resolve, the lookup worker, the
//! give-up and the cap on stuck lookups.

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, TryLockError};

use ntpc_core::engine::Event;
use ntpc_core::{Mono, SourceSpec, Tier};

use super::super::startup::resolve_note;
use super::super::{Inner, Msg, OFFLINE_RESOLVE_CAP, RESOLVE_GIVE_UP};
use super::{Host, MAX_ABANDONED_LOOKUPS, RESOLVE_THREAD};
use crate::logging::Level;
use crate::resolver::{ResolveNote, Resolver};

impl Host {
    fn names(&self) -> Vec<(String, Tier)> {
        let mut names: Vec<(String, Tier)> = self
            .cfg
            .servers
            .iter()
            .map(|s| (s.clone(), Tier::Config))
            .collect();
        names.extend(
            self.dhcp_servers
                .iter()
                .map(|ip| (ip.to_string(), Tier::Dhcp)),
        );
        names.push((self.cfg.pool.clone(), Tier::Pool));
        names
    }

    /// Drops the current resolver for a fresh one. Its worker's result, if
    /// it ever comes, is ignored.
    fn fresh_resolver(&mut self) {
        self.generation += 1;
        self.resolver = Arc::new(Mutex::new(Resolver::new(
            self.lookup.clone(),
            self.own.clone(),
        )));
        self.resolving_since = None;
        self.resolve_force = true;
    }

    pub(super) fn maybe_resolve(&mut self, now: Mono) {
        if self.stopping {
            return;
        }
        if let Some(since) = self.resolving_since {
            if now.saturating_duration_since(since) < RESOLVE_GIVE_UP {
                return;
            }
            self.log(
                Level::Warn,
                "resolve_stuck",
                "a name lookup did not return. Starting a fresh resolver",
            );
            self.abandoned.insert(self.generation);
            self.fresh_resolver();
        }
        // Each abandoned worker is a thread stuck in the system resolver.
        // Past the cap, start none until one returns. The engine keeps the
        // last source list meanwhile.
        if self.abandoned.len() >= MAX_ABANDONED_LOOKUPS {
            if !self.lookups_held {
                self.lookups_held = true;
                self.log(
                    Level::Error,
                    "resolve_stuck",
                    &format!(
                        "{MAX_ABANDONED_LOOKUPS} name lookups are stuck. No new lookup starts \
                         until one returns. The last source list is kept"
                    ),
                );
            }
            return;
        }
        let due = match self.resolver.try_lock() {
            Ok(r) => r.due(now),
            // A worker holds it. It reports when done.
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(p)) => p.into_inner().due(now),
        };
        // R66: no back-off longer than the cap while no tier is active.
        let offline = self.engine.status().active_tier.is_none()
            && self
                .last_resolved
                .is_some_and(|t| now.saturating_duration_since(t) >= OFFLINE_RESOLVE_CAP);
        if !(due || self.resolve_force || offline) {
            return;
        }
        self.resolve_force = false;
        self.start_resolve(now);
    }

    fn start_resolve(&mut self, now: Mono) {
        let names = self.names();
        let resolver = Arc::clone(&self.resolver);
        let tx = self.tx.clone();
        let generation = self.generation;
        let job = Box::new(move || {
            let run = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut r = resolver
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let specs = r.expand(now, &names);
                (specs, r.take_notes())
            }));
            let msg = match run {
                Ok((specs, notes)) => Inner::Resolved {
                    generation,
                    specs,
                    notes,
                },
                Err(_) => Inner::ResolveFailed { generation },
            };
            let _ = tx.send(Msg(msg));
        });
        self.resolving_since = Some(now);
        if !self.spawn.spawn(RESOLVE_THREAD, job) {
            self.resolving_since = None;
            self.log(
                Level::Error,
                "spawn",
                "could not start a lookup thread. Retrying at the next check",
            );
        }
    }

    /// An old worker came back. The cap on stuck lookups frees a slot.
    fn note_returned(&mut self, generation: u64) {
        if self.abandoned.remove(&generation) && self.lookups_held {
            self.lookups_held = false;
            self.log(
                Level::Info,
                "resolve_stuck",
                "a stuck name lookup returned. Lookups start again",
            );
        }
    }

    pub(super) fn on_resolve_failed(&mut self, generation: u64) {
        if generation != self.generation {
            self.note_returned(generation);
            return;
        }
        // A panic may have left the resolver half updated, and its mutex
        // is poisoned. Start over at once rather than wait out the give-up.
        self.log(
            Level::Error,
            "resolve_panic",
            "the resolver panicked. Starting a fresh resolver. The last source list is kept",
        );
        self.fresh_resolver();
        let now = self.time.mono();
        self.last_resolved = Some(now);
        // A fresh resolver is due at once. Marking it waits the normal
        // interval, or the 15 min offline cap (R66).
        if let Ok(mut r) = self.resolver.try_lock() {
            r.mark_resolved(now);
        }
        // Not forced again at once: a resolver that panics on every call
        // would otherwise spin. The normal retry timing applies.
        self.resolve_force = false;
    }

    pub(super) fn on_resolved(
        &mut self,
        generation: u64,
        specs: Vec<SourceSpec>,
        notes: Vec<ResolveNote>,
    ) {
        if generation != self.generation {
            self.note_returned(generation);
            return;
        }
        let now = self.time.mono();
        self.resolving_since = None;
        self.last_resolved = Some(now);
        match self.resolver.try_lock() {
            Ok(mut r) => r.mark_resolved(now),
            Err(TryLockError::Poisoned(p)) => p.into_inner().mark_resolved(now),
            Err(TryLockError::WouldBlock) => {}
        }
        for n in notes {
            let (level, msg) = resolve_note(&n);
            self.log(level, "resolve", &msg);
        }
        if specs != self.specs {
            let count = |t: Tier| specs.iter().filter(|s| s.tier == t).count();
            self.log(
                Level::Info,
                "sources",
                &format!(
                    "sources: config {}, dhcp {}, pool {}",
                    count(Tier::Config),
                    count(Tier::Dhcp),
                    count(Tier::Pool)
                ),
            );
            self.addrs = specs
                .iter()
                .map(|s| (s.id, (s.addr, s.label.clone())))
                .collect();
            self.specs.clone_from(&specs);
            self.feed(Event::SourcesChanged(specs));
        }
    }
}
