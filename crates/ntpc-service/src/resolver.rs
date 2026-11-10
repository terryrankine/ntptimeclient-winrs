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

/// How long a name keeps its previous addresses after lookups start to fail.
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
        /// What the system said.
        kind: io::ErrorKind,
    },
    /// After a failed lookup the previous addresses are still used.
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

/// Expands names into sources with stable ids.
#[derive(Debug)]
pub struct Resolver<L, O> {
    lookup: L,
    own: O,
    /// Ids of the addresses in the latest result only.
    ids: BTreeMap<IpAddr, SourceId>,
    next_id: Option<u32>,
    /// Latest good answer per name and tier, kept for a failed lookup.
    /// The `Mono` is when the answer was last good.
    previous: BTreeMap<(Tier, String), (Vec<IpAddr>, Mono)>,
    notes: Vec<ResolveNote>,
    resolved_at: Option<Mono>,
    retry_soon: bool,
}

impl<L: NameLookup, O: OwnAddresses> Resolver<L, O> {
    /// A resolver with no history.
    pub fn new(lookup: L, own: O) -> Self {
        Self {
            lookup,
            own,
            ids: BTreeMap::new(),
            next_id: Some(0),
            previous: BTreeMap::new(),
            notes: Vec::new(),
            resolved_at: None,
            retry_soon: false,
        }
    }

    /// The lookup, for adapters that need to be changed or inspected.
    pub fn lookup_mut(&mut self) -> &mut L {
        &mut self.lookup
    }

    /// Resolves every name and returns the sources, sorted by tier then
    /// address. Blocks. See the module note on timeouts.
    ///
    /// `now` dates the answers, so a failed lookup can keep a name's previous
    /// addresses for at most [`MAX_KEEP_PREVIOUS`]. A name that is not found
    /// loses them at once. The call never fails as a whole. Look at [`Resolver::take_notes`] for what happened.
    pub fn expand(&mut self, now: Mono, names: &[(String, Tier)]) -> Vec<SourceSpec> {
        self.notes.clear();
        let own: BTreeSet<IpAddr> = self
            .own
            .own_addresses()
            .into_iter()
            .map(|a| a.to_canonical())
            .collect();

        // Priority order first, so a higher tier claims a shared address.
        let mut ordered: Vec<&(String, Tier)> = names.iter().collect();
        ordered.sort_by_key(|(_, tier)| *tier);

        let mut claimed: BTreeSet<IpAddr> = BTreeSet::new();
        let mut per_tier: BTreeMap<Tier, usize> = BTreeMap::new();
        let mut tier_dropped: BTreeMap<Tier, usize> = BTreeMap::new();
        let mut next_previous = BTreeMap::new();
        let mut retry = false;
        // (tier, address, label) in assignment order.
        let mut chosen: Vec<(Tier, IpAddr, &str)> = Vec::new();

        for (name, tier) in ordered {
            let found = self.candidates(now, name, *tier, &own, &claimed);
            retry |= found.retry;
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
            next_previous.insert((*tier, name.clone()), (kept.to_vec(), found.good_at));
        }
        for (tier, dropped) in tier_dropped {
            self.notes.push(ResolveNote::TierCapped { tier, dropped });
        }
        self.previous = next_previous;

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
        self.retry_soon = retry || out.is_empty();
        out
    }

    /// Usable, unclaimed addresses for one name. Known addresses first.
    fn candidates(
        &mut self,
        now: Mono,
        name: &str,
        tier: Tier,
        own: &BTreeSet<IpAddr>,
        claimed: &BTreeSet<IpAddr>,
    ) -> Candidates {
        let mut good_at = now;
        let mut retry = false;
        let raw: Vec<IpAddr> = if let Ok(literal) = name.parse::<IpAddr>() {
            vec![literal]
        } else {
            match self.lookup.lookup(name) {
                Ok(list) => {
                    // An address claimed by an earlier name does not count
                    // here. A pool that repeats a config server is not a fault.
                    if !list.iter().any(|a| usable(*a, own)) {
                        self.notes.push(ResolveNote::NoUsableAddresses {
                            name: name.to_owned(),
                        });
                        retry = true;
                    }
                    list
                }
                Err(e) => {
                    self.notes.push(ResolveNote::LookupFailed {
                        name: name.to_owned(),
                        kind: e.kind(),
                    });
                    let old = self.previous.get(&(tier, name.to_owned()));
                    // NotFound means the name does not exist. Old addresses
                    // would be wrong, so they go at once. Any other failure
                    // may be a blip, so they stay for a bounded time.
                    let keep = old.filter(|(_, at)| {
                        e.kind() != io::ErrorKind::NotFound
                            && now.saturating_duration_since(*at) <= MAX_KEEP_PREVIOUS
                    });
                    if let Some((addrs, at)) = keep {
                        good_at = *at;
                        self.notes.push(ResolveNote::KeptPrevious {
                            name: name.to_owned(),
                        });
                        addrs.clone()
                    } else {
                        if old.is_some() && e.kind() != io::ErrorKind::NotFound {
                            self.notes.push(ResolveNote::PreviousExpired {
                                name: name.to_owned(),
                            });
                        }
                        retry = true;
                        Vec::new()
                    }
                }
            }
        };
        let mut seen = BTreeSet::new();
        let mut list: Vec<IpAddr> = raw
            .into_iter()
            .map(|a| a.to_canonical())
            .filter(|a| usable(*a, own) && !claimed.contains(a) && seen.insert(*a))
            .collect();
        // Stable sort, so lookup order survives inside each group.
        list.sort_by_key(|a| !self.ids.contains_key(a));
        Candidates {
            list,
            good_at,
            retry,
        }
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
    #[must_use]
    pub fn due(&self, now: Mono) -> bool {
        let interval = if self.retry_soon {
            RETRY_INTERVAL
        } else {
            RE_RESOLVE_INTERVAL
        };
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
    /// When the answer behind `list` was last good.
    good_at: Mono,
    /// The name failed or gave nothing usable, so ask again soon.
    retry: bool,
}

fn usable(ip: IpAddr, own: &BTreeSet<IpAddr>) -> bool {
    is_usable_address(ip) && !own.contains(&ip.to_canonical())
}

#[cfg(test)]
mod tests;
