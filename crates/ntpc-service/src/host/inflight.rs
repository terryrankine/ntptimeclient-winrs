//! Queries the host waits for. One per source (R15).
//!
//! The engine runs one round per tier, so it rarely asks twice for one
//! source. If it does while the first query runs, the second is not sent:
//! the first answer serves both. Each query carries a ticket, so an answer
//! that arrives after the watchdog gave up on it is dropped, and the
//! engine never gets two answers for one query.

use std::collections::BTreeMap;
use std::time::Duration;

use ntpc_core::{Mono, SourceId};

#[derive(Debug, Clone, Copy)]
struct Entry {
    ticket: u64,
    started: Mono,
}

#[derive(Debug, Default)]
pub(super) struct InFlight {
    map: BTreeMap<SourceId, Entry>,
    next_ticket: u64,
}

impl InFlight {
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    /// A ticket for a new query, or `None` if one for `source` runs.
    pub(super) fn begin(&mut self, source: SourceId, now: Mono) -> Option<u64> {
        if self.map.contains_key(&source) {
            return None;
        }
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1);
        self.map.insert(
            source,
            Entry {
                ticket,
                started: now,
            },
        );
        Some(ticket)
    }

    /// Ends a query. False if the answer is stale and must be dropped.
    pub(super) fn finish(&mut self, source: SourceId, ticket: u64) -> bool {
        if self.map.get(&source).is_some_and(|e| e.ticket == ticket) {
            self.map.remove(&source);
            true
        } else {
            false
        }
    }

    /// Forgets a query without an answer.
    pub(super) fn abandon(&mut self, source: SourceId) {
        self.map.remove(&source);
    }

    /// Queries running for at least `limit`. They are removed.
    pub(super) fn take_expired(&mut self, now: Mono, limit: Duration) -> Vec<SourceId> {
        let late: Vec<SourceId> = self
            .map
            .iter()
            .filter(|(_, e)| now.saturating_duration_since(e.started) >= limit)
            .map(|(id, _)| *id)
            .collect();
        for id in &late {
            self.map.remove(id);
        }
        late
    }

    /// When the next query reaches `limit`.
    pub(super) fn next_expiry(&self, limit: Duration) -> Option<Mono> {
        self.map
            .values()
            .filter_map(|e| e.started.checked_add(limit))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SourceId {
        SourceId::new(1)
    }

    fn at(s: u64) -> Mono {
        Mono::from_nanos(s * 1_000_000_000)
    }

    #[test]
    fn second_query_for_a_running_source_is_not_sent() {
        let mut f = InFlight::default();
        let t = f.begin(src(), at(0)).expect("first");
        assert_eq!(f.begin(src(), at(1)), None, "deduped");
        assert!(f.begin(SourceId::new(2), at(1)).is_some(), "other source");
        assert!(f.finish(src(), t));
        assert!(f.begin(src(), at(2)).is_some(), "free again");
    }

    #[test]
    fn answer_after_the_watchdog_is_dropped() {
        let mut f = InFlight::default();
        let old = f.begin(src(), at(0)).expect("first");
        assert_eq!(f.next_expiry(Duration::from_secs(15)), Some(at(15)));
        assert_eq!(f.take_expired(at(15), Duration::from_secs(15)), vec![src()]);
        let new = f.begin(src(), at(20)).expect("new query");
        assert!(!f.finish(src(), old), "stale answer dropped");
        assert!(f.finish(src(), new));
        assert_eq!(f.len(), 0);
    }
}
