//! When the DHCP reader may read (ruling R82).
//!
//! A read sends a DHCPINFORM per leased adapter and can block for minutes,
//! so reads are rare and one at a time:
//! - One read at start, without waiting.
//! - After a network signal, wait [`DHCP_SETTLE`] so a lease that is still
//!   being set up has settled. Signals that arrive before the read starts
//!   are absorbed into it, so a storm of signals gives one read.
//! - Never start a read within [`DHCP_MIN_INTERVAL`] of the last start.
//! - Read again every [`DHCP_REREAD`] even without a signal. That read also
//!   clears the negative cache.
//! - Negative cache: an adapter that offered no option 42 is skipped until
//!   its lease changes (a new key) or the timer read clears the cache.

use std::collections::BTreeSet;
use std::time::Duration;

use ntpc_core::Mono;

use super::{AdapterKey, DhcpRead, DhcpReadError};

/// Wait after a network signal before reading. A guess: a new lease is
/// usually complete within a few seconds of the address change.
pub const DHCP_SETTLE: Duration = Duration::from_secs(10);

/// Shortest gap between two read starts. Each read may put a DHCPINFORM on
/// every leased adapter. Ten minutes keeps that rare on a flapping link.
pub const DHCP_MIN_INTERVAL: Duration = Duration::from_secs(600);

/// Read again this long after the last timer read, signal or not. Catches a
/// lease change the watcher missed. Four hours is a guess well under a
/// typical one-day lease.
pub const DHCP_REREAD: Duration = Duration::from_secs(4 * 3600);

fn later(at: Mono, by: Duration) -> Mono {
    at.checked_add(by).unwrap_or(Mono::from_nanos(u64::MAX))
}

#[derive(Debug, Clone)]
pub(super) struct DhcpSchedule {
    busy: bool,
    boot_pending: bool,
    last_start: Option<Mono>,
    signal_at: Option<Mono>,
    timer_from: Mono,
    negative: BTreeSet<AdapterKey>,
}

impl DhcpSchedule {
    pub(super) fn new(now: Mono) -> Self {
        Self {
            busy: false,
            boot_pending: true,
            last_start: None,
            signal_at: None,
            timer_from: now,
            negative: BTreeSet::new(),
        }
    }

    pub(super) fn busy(&self) -> bool {
        self.busy
    }

    /// The network changed.
    pub(super) fn on_signal(&mut self, now: Mono) {
        self.signal_at.get_or_insert(now);
    }

    /// When the next read may start. `None` while a read runs.
    pub(super) fn due_at(&self) -> Option<Mono> {
        if self.busy {
            return None;
        }
        let timer = later(self.timer_from, DHCP_REREAD);
        let want = if self.boot_pending {
            self.timer_from
        } else {
            self.signal_at
                .map_or(timer, |s| later(s, DHCP_SETTLE).min(timer))
        };
        Some(match self.last_start {
            Some(l) => want.max(later(l, DHCP_MIN_INTERVAL)),
            None => want,
        })
    }

    /// Starts a read now. Returns the adapters to skip.
    pub(super) fn start(&mut self, now: Mono) -> BTreeSet<AdapterKey> {
        if now >= later(self.timer_from, DHCP_REREAD) {
            self.negative.clear();
            self.timer_from = now;
        }
        self.busy = true;
        self.boot_pending = false;
        self.last_start = Some(now);
        self.signal_at = None;
        self.negative.clone()
    }

    /// A read finished.
    pub(super) fn finish(&mut self, result: &Result<DhcpRead, DhcpReadError>) {
        self.busy = false;
        if let Ok(r) = result {
            // An adapter whose key is gone has a new lease or is gone.
            let seen: BTreeSet<&AdapterKey> = r.adapters.iter().collect();
            self.negative.retain(|k| seen.contains(k));
            self.negative.extend(r.without_option.iter().cloned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: u64) -> Mono {
        Mono::from_nanos(s * 1_000_000_000)
    }

    fn key(s: &str) -> AdapterKey {
        AdapterKey(s.to_owned())
    }

    #[test]
    fn boot_read_is_at_once_then_signal_waits_to_settle() {
        let mut d = DhcpSchedule::new(at(0));
        assert_eq!(d.due_at(), Some(at(0)));
        let _ = d.start(at(0));
        assert_eq!(d.due_at(), None, "busy");
        d.finish(&Ok(DhcpRead::default()));
        // No signal: the long timer.
        assert_eq!(d.due_at(), Some(at(4 * 3600)));
        d.on_signal(at(1000));
        assert_eq!(d.due_at(), Some(at(1010)));
    }

    #[test]
    fn minimum_interval_holds_a_signal_back() {
        let mut d = DhcpSchedule::new(at(0));
        let _ = d.start(at(0));
        d.finish(&Ok(DhcpRead::default()));
        d.on_signal(at(5));
        assert_eq!(d.due_at(), Some(at(600)));
    }

    #[test]
    fn storm_of_signals_gives_one_read() {
        let mut d = DhcpSchedule::new(at(0));
        let _ = d.start(at(0));
        d.finish(&Ok(DhcpRead::default()));
        for i in 0..100 {
            d.on_signal(at(700 + i));
        }
        assert_eq!(d.due_at(), Some(at(710)));
        let _ = d.start(at(710));
        d.finish(&Ok(DhcpRead::default()));
        // Absorbed: next is the timer.
        assert_eq!(d.due_at(), Some(at(4 * 3600)));
    }

    #[test]
    fn negative_cache_skips_until_lease_changes_or_timer() {
        let mut d = DhcpSchedule::new(at(0));
        let _ = d.start(at(0));
        d.finish(&Ok(DhcpRead {
            servers: vec![],
            adapters: vec![key("a/1"), key("b/1")],
            without_option: vec![key("a/1")],
        }));
        d.on_signal(at(1000));
        assert_eq!(d.start(at(1010)), BTreeSet::from([key("a/1")]));
        // Adapter a has a new lease server, so a new key.
        d.finish(&Ok(DhcpRead {
            servers: vec![],
            adapters: vec![key("a/2"), key("b/1")],
            without_option: vec![],
        }));
        d.on_signal(at(2000));
        assert!(d.start(at(2010)).is_empty(), "old key forgotten");
        d.finish(&Ok(DhcpRead {
            servers: vec![],
            adapters: vec![key("a/2")],
            without_option: vec![key("a/2")],
        }));
        // The timer read clears it.
        assert!(d.start(at(4 * 3600)).is_empty());
    }

    #[test]
    fn failed_read_keeps_the_cache() {
        let mut d = DhcpSchedule::new(at(0));
        let _ = d.start(at(0));
        d.finish(&Ok(DhcpRead {
            servers: vec![],
            adapters: vec![key("a")],
            without_option: vec![key("a")],
        }));
        d.on_signal(at(1000));
        let _ = d.start(at(1010));
        d.finish(&Err(DhcpReadError("boom".into())));
        d.on_signal(at(2000));
        assert_eq!(d.start(at(2010)), BTreeSet::from([key("a")]));
    }
}
