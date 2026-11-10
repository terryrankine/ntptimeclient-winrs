//! Turns configured names into the sources the engine polls.
//!
//! The resolver owns [`SourceId`] allocation. The same address keeps the
//! same id from one resolution to the next, so the engine keeps its filter
//! history for a server that is still there.
//!
//! Rules for one [`Resolver::expand`] call:
//! - A name that is an IP literal is used as is. No lookup.
//! - Addresses that are loopback, link-local (`169.254/16`, `fe80::/10`),
//!   multicast, broadcast, unspecified or one of this machine's own are
//!   dropped. An `IPv4`-mapped `IPv6` address (`::ffff:a.b.c.d`) is first turned
//!   into plain `IPv4`, so a mapped loopback is still loopback.
//! - At most [`MAX_PER_NAME`] addresses per name and [`MAX_PER_TIER`] per
//!   tier. Earlier names win. Within a name, addresses that already have an
//!   id come first, so DNS rotation does not churn working sources.
//! - An address claimed by an earlier name or a higher tier is not listed
//!   twice. Tiers are processed in priority order whatever the input order.
//! - The result is sorted by tier then address.
//!
//! Freed ids: an address that is absent from one resolution is forgotten.
//! Its id is never given to another address. If the address returns later it
//! gets a new id, because the engine may still hold state under the old one.
//! Ids count up from 0 and a `u32` will not run out in practice.
//!
//! Timeouts: `std` has no lookup timeout. [`SystemLookup`] blocks in the
//! system resolver, which can take tens of seconds. This module spawns no
//! thread. The host (Task 14) must run [`Resolver::expand`] off the engine
//! loop, for example on a worker thread that hands the `Resolver` back with
//! the result, and stop waiting after its own deadline. Meanwhile the engine
//! keeps polling its current sources.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use ntpc_core::{Mono, SourceId, SourceSpec, Tier};

/// NTP port. Not configurable.
pub const PORT: u16 = 123;
/// Most addresses kept for one name.
pub const MAX_PER_NAME: usize = 4;
/// Most addresses kept for one tier.
pub const MAX_PER_TIER: usize = 8;
/// How often to resolve again. A fixed constant, not a config key, because
/// the spec has no such setting. One hour is slow enough to be polite to
/// the pool and fast enough to follow a changed address.
pub const RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(3600);
/// How soon to try again when the last resolution gave no sources, or any
/// name failed or gave no usable address.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// How long a name keeps its cached addresses after lookups start to fail.
/// This is the only expiry. `Mono` counts awake time only and stands still
/// during sleep, so the limit is 24 h of running time. A restart loses the
/// cache, because it lives in memory only.
pub const MAX_KEEP_PREVIOUS: Duration = Duration::from_secs(24 * 3600);

/// Looks a name up. Blocking.
pub trait NameLookup {
    /// All addresses for `name`, in the order the system returned them.
    ///
    /// # Errors
    /// Any I/O error from the lookup.
    fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}

/// The addresses assigned to this machine.
///
/// The real list needs a Windows API and comes from the platform crate
/// (Task 11). Until then [`NoOwnAddresses`] stands in, which means a server
/// name that resolves to this machine is not caught.
pub trait OwnAddresses {
    /// Every unicast address of every adapter.
    fn own_addresses(&self) -> Vec<IpAddr>;
}

/// The system resolver through [`ToSocketAddrs`]. See the module note on
/// timeouts.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLookup;

impl NameLookup for SystemLookup {
    fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        Ok((name, PORT)
            .to_socket_addrs()?
            .map(|a: SocketAddr| a.ip())
            .collect())
    }
}

/// Stand-in that reports no own addresses. Replace it with the platform
/// adapter in Task 14.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOwnAddresses;

impl OwnAddresses for NoOwnAddresses {
    fn own_addresses(&self) -> Vec<IpAddr> {
        Vec::new()
    }
}

/// Something worth logging that happened during [`Resolver::expand`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveNote {
    /// The lookup failed.
    LookupFailed {
        /// The name.
        name: String,
        /// What the system said. On Windows most DNS failures are
        /// `Uncategorized`, so log `code` as well.
        kind: io::ErrorKind,
        /// The raw OS error code, for example 11001 for a name that is not
        /// found or a network that is down. Windows uses one code for both.
        code: Option<i32>,
    },
    /// After a failed lookup the cached addresses are still used.
    KeptPrevious {
        /// The name.
        name: String,
    },
    /// The answer held no address that can be used.
    NoUsableAddresses {
        /// The name.
        name: String,
    },
    /// More than [`MAX_PER_NAME`] usable addresses. The rest were dropped.
    NameCapped {
        /// The name.
        name: String,
        /// How many were dropped.
        dropped: usize,
    },
    /// More than [`MAX_PER_TIER`] addresses in a tier. The rest were dropped.
    TierCapped {
        /// The tier.
        tier: Tier,
        /// How many were dropped.
        dropped: usize,
    },
    /// The lookup kept failing for longer than [`MAX_KEEP_PREVIOUS`]. The old
    /// addresses were dropped.
    PreviousExpired {
        /// The name.
        name: String,
    },
    /// The id counter ran out. Addresses after this point were skipped.
    IdsExhausted,
}

/// True if `ip` may be polled. Mapped IPv4 is judged as IPv4.
#[must_use]
pub fn is_usable_address(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => {
            // 0.0.0.0/8 is "this network", never a server.
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.octets()[0] == 0)
        }
        IpAddr::V6(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_unicast_link_local())
        }
    }
}

/// A cached lookup answer.
#[derive(Debug, Clone)]
struct Cached {
    /// Usable addresses as the lookup returned them, never empty.
    addrs: Vec<IpAddr>,
    /// When the lookup last worked.
    good_at: Mono,
}

type NameKey = (Tier, String);

/// Expands names into sources with stable ids.
#[derive(Debug)]
pub struct Resolver<L, O> {
    lookup: L,
    own: O,
    /// Ids of the addresses in the latest result only.
    ids: BTreeMap<IpAddr, SourceId>,
    next_id: Option<u32>,
    /// Latest good answer per name. Kept for a failed lookup and reused on a
    /// retry pass. Empty answers are never stored.
    cache: BTreeMap<NameKey, Cached>,
    /// Names that failed or gave nothing usable and had no cache to fall back
    /// on. The next retry pass looks up only these.
    retry_names: BTreeSet<NameKey>,
    /// Every name of the latest call. A different list forces a full pass.
    last_names: BTreeSet<NameKey>,
    /// Start of the latest full pass.
    last_full_at: Option<Mono>,
    /// Wait before the next pass while failures persist. `None` when healthy.
    retry_interval: Option<Duration>,
    notes: Vec<ResolveNote>,
    resolved_at: Option<Mono>,
}

impl<L: NameLookup, O: OwnAddresses> Resolver<L, O> {
    /// A resolver with no history.
    pub fn new(lookup: L, own: O) -> Self {
        Self {
            lookup,
            own,
            ids: BTreeMap::new(),
            next_id: Some(0),
            cache: BTreeMap::new(),
            retry_names: BTreeSet::new(),
            last_names: BTreeSet::new(),
            last_full_at: None,
            retry_interval: None,
            notes: Vec::new(),
            resolved_at: None,
        }
    }

    /// The lookup, for adapters that need to be changed or inspected.
    pub fn lookup_mut(&mut self) -> &mut L {
        &mut self.lookup
    }

    /// Resolves names and returns the sources, sorted by tier then address.
    /// Blocks. See the module note on timeouts.
    ///
    /// `now` dates the answers. A failed lookup keeps that name's cached
    /// addresses for at most [`MAX_KEEP_PREVIOUS`].
    ///
    /// Retry pass: while some names keep failing, a call within an hour of
    /// the last full pass, with the same names, looks up only the failing
    /// names. The other names reuse their cached answers, so their ids stay
    /// the same and a rotating pool name is not asked again. Any other call
    /// is a full pass.
    ///
    /// The call never fails as a whole. Look at [`Resolver::take_notes`] for
    /// what happened.
    pub fn expand(&mut self, now: Mono, names: &[(String, Tier)]) -> Vec<SourceSpec> {
        self.notes.clear();
        let own: BTreeSet<IpAddr> = self
            .own
            .own_addresses()
            .into_iter()
            .map(|a| a.to_canonical())
            .collect();

        let name_set: BTreeSet<NameKey> = names.iter().map(|(n, t)| (*t, n.clone())).collect();
        let retry_pass = !self.retry_names.is_empty()
            && name_set == self.last_names
            && self
                .last_full_at
                .is_some_and(|at| now.saturating_duration_since(at) < RE_RESOLVE_INTERVAL);
        if !retry_pass {
            self.last_full_at = Some(now);
        }

        // Priority order first, so a higher tier claims a shared address.
        let mut ordered: Vec<&(String, Tier)> = names.iter().collect();
        ordered.sort_by_key(|(_, tier)| *tier);

        let mut claimed: BTreeSet<IpAddr> = BTreeSet::new();
        let mut per_tier: BTreeMap<Tier, usize> = BTreeMap::new();
        let mut tier_dropped: BTreeMap<Tier, usize> = BTreeMap::new();
        let mut next_cache = BTreeMap::new();
        let mut next_retry = BTreeSet::new();
        // (tier, address, label) in assignment order.
        let mut chosen: Vec<(Tier, IpAddr, &str)> = Vec::new();

        for (name, tier) in ordered {
            let key = (*tier, name.clone());
            let ask = !retry_pass || self.retry_names.contains(&key);
            let found = self.candidates(now, &key, ask, &own, &claimed);
            if found.retry {
                next_retry.insert(key.clone());
            }
            if let Some(c) = found.cache {
                next_cache.insert(key, c);
            }
            let candidates = found.list;
            let room = MAX_PER_TIER - per_tier.get(tier).copied().unwrap_or(0);
            let mut keep = candidates.len();
            if keep > MAX_PER_NAME {
                self.notes.push(ResolveNote::NameCapped {
                    name: name.clone(),
                    dropped: keep - MAX_PER_NAME,
                });
                keep = MAX_PER_NAME;
            }
            if keep > room {
                *tier_dropped.entry(*tier).or_default() += keep - room;
                keep = room;
            }
            let kept = &candidates[..keep];
            *per_tier.entry(*tier).or_default() += kept.len();
            claimed.extend(kept.iter().copied());
            chosen.extend(kept.iter().map(|ip| (*tier, *ip, name.as_str())));
        }
        for (tier, dropped) in tier_dropped {
            self.notes.push(ResolveNote::TierCapped { tier, dropped });
        }
        self.cache = next_cache;
        self.last_names = name_set;
        // Wait 60 s, then 120 s, doubling up to an hour while any name keeps
        // failing. One clean pass resets it.
        self.retry_interval = if next_retry.is_empty() {
            None
        } else {
            Some(
                self.retry_interval
                    .map_or(RETRY_INTERVAL, |p| (p * 2).min(RE_RESOLVE_INTERVAL)),
            )
        };
        self.retry_names = next_retry;

        let mut ids = BTreeMap::new();
        let mut out = Vec::with_capacity(chosen.len());
        for (tier, ip, label) in chosen {
            let Some(id) = self.id_for(ip) else {
                self.notes.push(ResolveNote::IdsExhausted);
                continue;
            };
            ids.insert(ip, id);
            out.push(SourceSpec {
                id,
                tier,
                addr: SocketAddr::new(ip, PORT),
                label: label.to_owned(),
            });
        }
        // Only addresses in this result keep an id. See the module note on
        // freed ids.
        self.ids = ids;
        out.sort_by_key(|s| (s.tier, s.addr.ip()));
        out
    }

    /// Usable, unclaimed addresses for one name. Known addresses first.
    /// With `ask` false the cached answer is used and no lookup is made.
    fn candidates(
        &mut self,
        now: Mono,
        key: &NameKey,
        ask: bool,
        own: &BTreeSet<IpAddr>,
        claimed: &BTreeSet<IpAddr>,
    ) -> Candidates {
        let name = key.1.as_str();
        let mut cache: Option<Cached> = None;
        let mut retry = false;
        let raw: Vec<IpAddr> = if let Ok(literal) = name.parse::<IpAddr>() {
            vec![literal]
        } else if !ask {
            cache = self.cache.get(key).cloned();
            cache.as_ref().map(|c| c.addrs.clone()).unwrap_or_default()
        } else {
            match self.lookup.lookup(name) {
                Ok(list) => {
                    // An address claimed by an earlier name does not count
                    // here. A pool that repeats a config server is not a fault.
                    let list = dedup_usable(list, own);
                    if list.is_empty() {
                        self.notes.push(ResolveNote::NoUsableAddresses {
                            name: name.to_owned(),
                        });
                        retry = true;
                    } else {
                        cache = Some(Cached {
                            addrs: list.clone(),
                            good_at: now,
                        });
                    }
                    list
                }
                Err(e) => {
                    self.notes.push(ResolveNote::LookupFailed {
                        name: name.to_owned(),
                        kind: e.kind(),
                        code: e.raw_os_error(),
                    });
                    // Windows reports a missing name and a lost network with
                    // the same code, so a failure never drops the cache at
                    // once. Only age does.
                    let old = self.cache.get(key);
                    let fresh = old
                        .filter(|c| now.saturating_duration_since(c.good_at) <= MAX_KEEP_PREVIOUS);
                    if let Some(c) = fresh {
                        self.notes.push(ResolveNote::KeptPrevious {
                            name: name.to_owned(),
                        });
                        cache = Some(c.clone());
                    } else {
                        if old.is_some() {
                            self.notes.push(ResolveNote::PreviousExpired {
                                name: name.to_owned(),
                            });
                        }
                        retry = true;
                    }
                    cache.as_ref().map(|c| c.addrs.clone()).unwrap_or_default()
                }
            }
        };
        let mut list: Vec<IpAddr> = dedup_usable(raw, own)
            .into_iter()
            .filter(|a| !claimed.contains(a))
            .collect();
        // Stable sort, so lookup order survives inside each group.
        list.sort_by_key(|a| !self.ids.contains_key(a));
        Candidates { list, cache, retry }
    }

    fn id_for(&mut self, ip: IpAddr) -> Option<SourceId> {
        if let Some(id) = self.ids.get(&ip) {
            return Some(*id);
        }
        let n = self.next_id?;
        self.next_id = n.checked_add(1);
        Some(SourceId::new(n))
    }

    /// True when it is time to call [`Resolver::expand`] again. Always true
    /// before the first [`Resolver::mark_resolved`].
    ///
    /// While names fail the wait is 60 s, then doubles each pass up to an
    /// hour. Otherwise it is [`RE_RESOLVE_INTERVAL`].
    #[must_use]
    pub fn due(&self, now: Mono) -> bool {
        let interval = self.retry_interval.unwrap_or(RE_RESOLVE_INTERVAL);
        self.resolved_at
            .is_none_or(|at| now.saturating_duration_since(at) >= interval)
    }

    /// Records that a resolution finished at `now`. The host calls it, so
    /// the time includes any wait for a slow lookup.
    pub fn mark_resolved(&mut self, now: Mono) {
        self.resolved_at = Some(now);
    }

    /// What happened in the latest [`Resolver::expand`]. Empties the list.
    pub fn take_notes(&mut self) -> Vec<ResolveNote> {
        std::mem::take(&mut self.notes)
    }
}

/// Result of looking one name up.
struct Candidates {
    list: Vec<IpAddr>,
    /// What to remember for next time.
    cache: Option<Cached>,
    /// The name failed or gave nothing usable, so ask again soon.
    retry: bool,
}

/// Canonical, usable, own-free addresses with duplicates removed. Order kept.
fn dedup_usable(list: Vec<IpAddr>, own: &BTreeSet<IpAddr>) -> Vec<IpAddr> {
    let mut seen = BTreeSet::new();
    list.into_iter()
        .map(|a| a.to_canonical())
        .filter(|a| is_usable_address(*a) && !own.contains(a) && seen.insert(*a))
        .collect()
}

#[cfg(test)]
mod tests;
