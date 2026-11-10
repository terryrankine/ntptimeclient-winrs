use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

/// Answers come from a table. No network, no real DNS.
#[derive(Default)]
struct Fake {
    answers: BTreeMap<String, Result<Vec<IpAddr>, io::ErrorKind>>,
    calls: std::cell::RefCell<Vec<String>>,
}

impl Fake {
    fn with(mut self, name: &str, addrs: &[&str]) -> Self {
        self.set(name, addrs);
        self
    }
    fn set(&mut self, name: &str, addrs: &[&str]) {
        self.answers
            .insert(name.to_owned(), Ok(addrs.iter().map(|a| ip(a)).collect()));
    }
    fn fail(&mut self, name: &str) {
        self.answers
            .insert(name.to_owned(), Err(io::ErrorKind::TimedOut));
    }
}

impl NameLookup for Fake {
    fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        self.calls.borrow_mut().push(name.to_owned());
        match self.answers.get(name) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(k)) => Err(io::Error::from(*k)),
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
}

struct Own(Vec<IpAddr>);
impl OwnAddresses for Own {
    fn own_addresses(&self) -> Vec<IpAddr> {
        self.0.clone()
    }
}

fn t(secs: u64) -> Mono {
    Mono::from_nanos(secs * 1_000_000_000)
}

fn ip(s: &str) -> IpAddr {
    s.parse()
        .unwrap_or_else(|e| panic!("bad test address {s}: {e}"))
}

fn names(list: &[(&str, Tier)]) -> Vec<(String, Tier)> {
    list.iter().map(|(n, t)| ((*n).to_owned(), *t)).collect()
}

fn resolver(fake: Fake) -> Resolver<Fake, Own> {
    Resolver::new(fake, Own(Vec::new()))
}

fn addrs(specs: &[SourceSpec]) -> Vec<IpAddr> {
    specs.iter().map(|s| s.addr.ip()).collect()
}

fn many(prefix: &str, n: u8) -> Vec<String> {
    (1..=n).map(|i| format!("{prefix}{i}")).collect()
}

fn set_many(fake: &mut Fake, name: &str, prefix: &str, n: u8) {
    let v = many(prefix, n);
    let refs: Vec<&str> = v.iter().map(String::as_str).collect();
    fake.set(name, &refs);
}

#[test]
fn resolver_caps_addresses_per_name() {
    let mut f = Fake::default();
    set_many(&mut f, "pool.example", "203.0.113.", 20);
    let mut r = resolver(f);
    let out = r.expand(t(0), &names(&[("pool.example", Tier::Pool)]));
    assert_eq!(out.len(), MAX_PER_NAME);
    assert_eq!(MAX_PER_NAME, 4);
    let notes = r.take_notes();
    assert!(
        notes.contains(&ResolveNote::NameCapped {
            name: "pool.example".into(),
            dropped: 16
        }),
        "{notes:?}"
    );
}

#[test]
fn resolver_drops_loopback_and_own_addresses() {
    let f = Fake::default().with(
        "h",
        &[
            "127.0.0.1",
            "::1",
            "192.0.2.10",
            "198.51.100.5",
            "0.0.0.0",
            "::",
        ],
    );
    let mut r = Resolver::new(f, Own(vec![ip("192.0.2.10")]));
    let out = r.expand(t(0), &names(&[("h", Tier::Config)]));
    assert_eq!(addrs(&out), [ip("198.51.100.5")]);
}

#[test]
fn resolver_gives_stable_ids_for_same_address() {
    let f = Fake::default().with("a", &["192.0.2.1", "192.0.2.2"]);
    let mut r = resolver(f);
    let n = names(&[("a", Tier::Config)]);
    let first = r.expand(t(0), &n);
    let second = r.expand(t(0), &n);
    assert_eq!(first, second);
    assert_ne!(first[0].id, first[1].id);
}

#[test]
fn pool_name_expands_to_several_sources() {
    let f = Fake::default().with(
        "pool.ntp.org",
        &["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"],
    );
    let mut r = resolver(f);
    let out = r.expand(t(0), &names(&[("pool.ntp.org", Tier::Pool)]));
    assert_eq!(out.len(), 4);
    for s in &out {
        assert_eq!(s.tier, Tier::Pool);
        assert_eq!(s.addr.port(), 123);
        assert_eq!(s.label, "pool.ntp.org");
    }
    let ids: std::collections::BTreeSet<_> = out.iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), 4, "ids are distinct");
}

#[test]
fn port_is_123() {
    let f = Fake::default().with("a", &["192.0.2.1", "2001:db8::1"]);
    let mut r = resolver(f);
    let out = r.expand(t(0), &names(&[("a", Tier::Config)]));
    assert!(out.iter().all(|s| s.addr.port() == PORT && PORT == 123));
}

#[test]
fn duplicate_addresses_across_names_are_one_source() {
    let f = Fake::default()
        .with("a", &["192.0.2.1", "192.0.2.2"])
        .with("b", &["192.0.2.2", "192.0.2.3"]);
    let mut r = resolver(f);
    let out = r.expand(t(0), &names(&[("a", Tier::Config), ("b", Tier::Config)]));
    assert_eq!(
        addrs(&out),
        [ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")]
    );
    // First name wins the label.
    assert_eq!(out[1].label, "a");
    assert_eq!(out[2].label, "b");
}

#[test]
fn duplicate_across_tiers_keeps_the_higher_tier() {
    let f = Fake::default()
        .with("pool", &["192.0.2.9", "192.0.2.8"])
        .with("mine", &["192.0.2.9"]);
    let mut r = resolver(f);
    // Pool listed first on purpose. Priority order must not depend on input order.
    let out = r.expand(
        t(0),
        &names(&[("pool", Tier::Pool), ("mine", Tier::Config)]),
    );
    let nine = out
        .iter()
        .find(|s| s.addr.ip() == ip("192.0.2.9"))
        .expect("present once");
    assert_eq!(nine.tier, Tier::Config);
    assert_eq!(
        out.iter()
            .filter(|s| s.addr.ip() == ip("192.0.2.9"))
            .count(),
        1
    );
    assert_eq!(out.len(), 2);
}

#[test]
fn ip_literals_skip_the_lookup() {
    let mut r = resolver(Fake::default());
    let out = r.expand(
        t(0),
        &names(&[("192.0.2.5", Tier::Config), ("2001:db8::5", Tier::Config)]),
    );
    assert_eq!(addrs(&out), [ip("192.0.2.5"), ip("2001:db8::5")]);
    assert!(
        r.lookup_mut().calls.borrow().is_empty(),
        "no lookup for literals"
    );
    assert!(out[1].addr.is_ipv6());
    assert_eq!(out[1].addr, SocketAddr::new(ip("2001:db8::5"), 123));
}

#[test]
fn loopback_literal_is_dropped() {
    let mut r = resolver(Fake::default());
    assert_eq!(
        r.expand(t(0), &names(&[("127.0.0.1", Tier::Config)])).len(),
        0
    );
    assert_eq!(r.expand(t(0), &names(&[("::1", Tier::Config)])).len(), 0);
}

#[test]
fn name_with_zero_usable_addresses_gives_nothing_and_a_note() {
    let f = Fake::default().with("h", &["127.0.0.1", "169.254.1.1", "224.0.0.1"]);
    let mut r = resolver(f);
    let out = r.expand(t(0), &names(&[("h", Tier::Config)]));
    assert_eq!(out.len(), 0);
    assert_eq!(
        r.take_notes(),
        [ResolveNote::NoUsableAddresses { name: "h".into() }]
    );
    assert!(r.take_notes().is_empty(), "notes are taken once");
}

#[test]
fn empty_answer_gives_nothing() {
    let f = Fake::default().with("h", &[]);
    let mut r = resolver(f);
    assert_eq!(r.expand(t(0), &names(&[("h", Tier::Pool)])).len(), 0);
}

#[test]
fn tier_cap_is_eight_across_names() {
    let mut f = Fake::default();
    set_many(&mut f, "a", "192.0.2.", 4);
    set_many(&mut f, "b", "198.51.100.", 4);
    set_many(&mut f, "c", "203.0.113.", 4);
    let mut r = resolver(f);
    let out = r.expand(
        t(0),
        &names(&[
            ("a", Tier::Config),
            ("b", Tier::Config),
            ("c", Tier::Config),
        ]),
    );
    assert_eq!(out.len(), MAX_PER_TIER);
    assert_eq!(MAX_PER_TIER, 8);
    // Earlier names win. The operator listed them in that order.
    assert!(out.iter().all(|s| s.label == "a" || s.label == "b"));
    assert!(r.take_notes().contains(&ResolveNote::TierCapped {
        tier: Tier::Config,
        dropped: 4
    }));
}

#[test]
fn tier_cap_is_per_tier() {
    let mut f = Fake::default();
    set_many(&mut f, "a", "192.0.2.", 4);
    set_many(&mut f, "b", "198.51.100.", 4);
    set_many(&mut f, "c", "203.0.113.", 4);
    let mut r = resolver(f);
    let out = r.expand(
        t(0),
        &names(&[("a", Tier::Config), ("b", Tier::Config), ("c", Tier::Pool)]),
    );
    assert_eq!(out.len(), 12);
}

#[test]
fn result_is_sorted_by_tier_then_address() {
    let f = Fake::default()
        .with("pool", &["203.0.113.9", "203.0.113.1"])
        .with("mine", &["198.51.100.7", "192.0.2.200", "2001:db8::1"])
        .with("dhcp", &["10.0.0.5"]);
    let mut r = resolver(f);
    let out = r.expand(
        t(0),
        &names(&[
            ("pool", Tier::Pool),
            ("dhcp", Tier::Dhcp),
            ("mine", Tier::Config),
        ]),
    );
    let keys: Vec<(Tier, IpAddr)> = out.iter().map(|s| (s.tier, s.addr.ip())).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert_eq!(out[0].tier, Tier::Config);
    assert_eq!(out.last().map(|s| s.tier), Some(Tier::Pool));
}

#[test]
fn same_input_gives_same_output_every_time() {
    let mk = || {
        let mut f = Fake::default();
        set_many(&mut f, "p", "203.0.113.", 12);
        set_many(&mut f, "q", "198.51.100.", 3);
        resolver(f)
    };
    let n = names(&[("p", Tier::Pool), ("q", Tier::Config)]);
    assert_eq!(mk().expand(t(0), &n), mk().expand(t(0), &n));
}

#[test]
fn ids_stay_stable_when_one_address_goes_and_a_new_one_arrives() {
    let mut r = resolver(Fake::default().with("a", &["192.0.2.1", "192.0.2.2", "192.0.2.3"]));
    let n = names(&[("a", Tier::Config)]);
    let first = r.expand(t(0), &n);
    let id_of =
        |specs: &[SourceSpec], a: &str| specs.iter().find(|s| s.addr.ip() == ip(a)).map(|s| s.id);
    let id1 = id_of(&first, "192.0.2.1").expect("id1");
    let id2 = id_of(&first, "192.0.2.2").expect("id2");
    let id3 = id_of(&first, "192.0.2.3").expect("id3");

    // .2 disappears and .4 appears.
    r.lookup_mut()
        .set("a", &["192.0.2.1", "192.0.2.3", "192.0.2.4"]);
    let second = r.expand(t(0), &n);
    assert_eq!(id_of(&second, "192.0.2.1"), Some(id1));
    assert_eq!(id_of(&second, "192.0.2.3"), Some(id3));
    assert_eq!(id_of(&second, "192.0.2.2"), None);
    let id4 = id_of(&second, "192.0.2.4").expect("id4");
    let all = [id1, id2, id3];
    assert!(!all.contains(&id4), "a freed id is never reused");

    // .2 comes back. It gets a fresh id, not its old one, because the
    // engine may still hold state under the old id.
    r.lookup_mut()
        .set("a", &["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]);
    let third = r.expand(t(0), &n);
    let id2b = id_of(&third, "192.0.2.2").expect("id2b");
    assert!(![id1, id2, id3, id4].contains(&id2b));
    assert_eq!(id_of(&third, "192.0.2.4"), Some(id4));
}

#[test]
fn ids_are_stable_across_tiers_and_names() {
    let f = Fake::default()
        .with("a", &["192.0.2.1"])
        .with("b", &["192.0.2.1", "192.0.2.2"]);
    let mut r = resolver(f);
    let one = r.expand(t(0), &names(&[("a", Tier::Config)]));
    let two = r.expand(t(0), &names(&[("b", Tier::Pool)]));
    let id_a = one[0].id;
    let id_b = two
        .iter()
        .find(|s| s.addr.ip() == ip("192.0.2.1"))
        .map(|s| s.id);
    assert_eq!(Some(id_a), id_b);
}

#[test]
fn known_addresses_are_kept_when_the_cap_bites() {
    // DNS rotation must not churn sources that already work.
    let mut f = Fake::default();
    f.set(
        "p",
        &["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"],
    );
    let mut r = resolver(f);
    let n = names(&[("p", Tier::Pool)]);
    let first = r.expand(t(0), &n);
    r.lookup_mut().set(
        "p",
        &[
            "203.0.113.50",
            "203.0.113.51",
            "203.0.113.4",
            "203.0.113.3",
            "203.0.113.52",
        ],
    );
    let second = r.expand(t(0), &n);
    let known: Vec<IpAddr> = vec![ip("203.0.113.3"), ip("203.0.113.4")];
    for k in &known {
        assert!(addrs(&second).contains(k), "{k} kept");
    }
    assert_eq!(second.len(), 4);
    let id3 = first.iter().find(|s| s.addr.ip() == known[0]).map(|s| s.id);
    assert_eq!(
        second
            .iter()
            .find(|s| s.addr.ip() == known[0])
            .map(|s| s.id),
        id3
    );
}

#[test]
fn failed_lookup_keeps_the_previous_addresses_and_ids() {
    let mut r = resolver(Fake::default().with("a", &["192.0.2.1", "192.0.2.2"]));
    let n = names(&[("a", Tier::Config)]);
    let first = r.expand(t(0), &n);
    r.take_notes();
    r.lookup_mut().fail("a");
    let second = r.expand(t(0), &n);
    assert_eq!(first, second);
    let notes = r.take_notes();
    assert!(
        notes.contains(&ResolveNote::LookupFailed {
            name: "a".into(),
            kind: io::ErrorKind::TimedOut,
            code: None
        }),
        "{notes:?}"
    );
    assert!(notes.contains(&ResolveNote::KeptPrevious { name: "a".into() }));
}

#[test]
fn failed_first_lookup_gives_nothing() {
    let mut f = Fake::default();
    f.fail("a");
    let mut r = resolver(f);
    assert_eq!(r.expand(t(0), &names(&[("a", Tier::Config)])).len(), 0);
    let notes = r.take_notes();
    assert!(
        matches!(notes[0], ResolveNote::LookupFailed { .. }),
        "{notes:?}"
    );
    assert!(
        !notes
            .iter()
            .any(|n| matches!(n, ResolveNote::KeptPrevious { .. }))
    );
}

#[test]
fn own_address_filter_v4() {
    let f = Fake::default().with("h", &["192.0.2.1", "192.0.2.2"]);
    let mut r = Resolver::new(f, Own(vec![ip("192.0.2.2")]));
    assert_eq!(
        addrs(&r.expand(t(0), &names(&[("h", Tier::Config)]))),
        [ip("192.0.2.1")]
    );
}

#[test]
fn own_address_filter_v6() {
    let f = Fake::default().with("h", &["2001:db8::1", "2001:db8::2"]);
    let mut r = Resolver::new(f, Own(vec![ip("2001:db8::2")]));
    assert_eq!(
        addrs(&r.expand(t(0), &names(&[("h", Tier::Config)]))),
        [ip("2001:db8::1")]
    );
}

#[test]
fn own_address_filter_sees_through_mapped_addresses() {
    // The adapter list says IPv4. The resolver answer says mapped IPv6.
    let f = Fake::default().with("h", &["::ffff:192.0.2.2", "192.0.2.3"]);
    let mut r = Resolver::new(f, Own(vec![ip("192.0.2.2")]));
    assert_eq!(
        addrs(&r.expand(t(0), &names(&[("h", Tier::Config)]))),
        [ip("192.0.2.3")]
    );
    // And the other way round.
    let f = Fake::default().with("h", &["192.0.2.2", "192.0.2.3"]);
    let mut r = Resolver::new(f, Own(vec![ip("::ffff:192.0.2.2")]));
    assert_eq!(
        addrs(&r.expand(t(0), &names(&[("h", Tier::Config)]))),
        [ip("192.0.2.3")]
    );
}

#[test]
fn mapped_address_becomes_plain_v4_source() {
    let f = Fake::default().with("h", &["::ffff:198.51.100.7"]);
    let mut r = resolver(f);
    let out = r.expand(t(0), &names(&[("h", Tier::Config)]));
    assert_eq!(out[0].addr.ip(), ip("198.51.100.7"));
    assert!(out[0].addr.is_ipv4());
}

#[test]
fn mapped_special_addresses_are_dropped() {
    for s in [
        "::ffff:127.0.0.1",
        "::ffff:169.254.1.1",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
        "::ffff:0.0.0.0",
    ] {
        assert!(!is_usable_address(ip(s)), "{s}");
    }
    assert!(is_usable_address(ip("::ffff:198.51.100.7")));
}

#[test]
fn address_classification_table() {
    let bad = [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "127.255.255.254",
        "169.254.0.1",
        "169.254.255.255",
        "224.0.0.1",
        "239.255.255.250",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "febf::1",
        "ff02::1",
        "ff0e::101",
    ];
    for s in bad {
        assert!(!is_usable_address(ip(s)), "{s} must be dropped");
    }
    let good = [
        "1.1.1.1",
        "10.0.0.1",
        "169.253.1.1",
        "169.255.1.1",
        "192.168.1.1",
        "223.255.255.255",
        "2001:db8::1",
        "fec0::1",
        "fd00::1",
    ];
    for s in good {
        assert!(is_usable_address(ip(s)), "{s} must be kept");
    }
    // Sanity on the std constants the table relies on.
    assert!(Ipv4Addr::BROADCAST.is_broadcast());
    assert!(Ipv6Addr::LOCALHOST.is_loopback());
}

#[test]
fn due_is_true_before_the_first_resolve() {
    let r = resolver(Fake::default());
    assert!(r.due(Mono::from_nanos(0)));
}

#[test]
fn due_follows_the_interval() {
    let mut r = resolver(Fake::default().with("a", &["192.0.2.1"]));
    r.expand(t(0), &names(&[("a", Tier::Config)]));
    let t0 = Mono::from_nanos(5_000_000_000);
    r.mark_resolved(t0);
    assert!(!r.due(t0));
    let just_before = t0.checked_add(
        RE_RESOLVE_INTERVAL
            .checked_sub(Duration::from_nanos(1))
            .expect("positive"),
    );
    assert!(!r.due(just_before.expect("fits")));
    let at = t0.checked_add(RE_RESOLVE_INTERVAL).expect("fits");
    assert!(r.due(at));
    // A clock that reads earlier than the mark never panics and is not due.
    assert!(!r.due(Mono::from_nanos(0)));
}

#[test]
fn due_retries_sooner_after_an_empty_result() {
    let mut r = resolver(Fake::default());
    let out = r.expand(t(0), &names(&[("nothing.example", Tier::Pool)]));
    assert_eq!(out.len(), 0);
    let t0 = Mono::from_nanos(1_000_000_000);
    r.mark_resolved(t0);
    assert!(!r.due(t0));
    assert!(r.due(t0.checked_add(RETRY_INTERVAL).expect("fits")));
    assert!(RETRY_INTERVAL < RE_RESOLVE_INTERVAL);
}

#[test]
fn no_names_gives_no_sources() {
    let mut r = resolver(Fake::default());
    assert_eq!(r.expand(t(0), &[]).len(), 0);
}

#[test]
fn system_lookup_resolves_a_literal_without_dns() {
    let got = SystemLookup.lookup("192.0.2.1").expect("literal parses");
    assert_eq!(got, [ip("192.0.2.1")]);
}

#[test]
fn no_own_addresses_stub_is_empty() {
    assert_eq!(NoOwnAddresses.own_addresses().len(), 0);
}

fn lookup_err(fake: &mut Fake, name: &str, kind: io::ErrorKind) {
    fake.answers.insert(name.to_owned(), Err(kind));
}

#[test]
fn a_failed_config_name_is_retried_soon_even_when_the_pool_resolves() {
    let mut f = Fake::default().with("pool", &["203.0.113.1", "203.0.113.2"]);
    f.fail("mine");
    let mut r = resolver(f);
    let n = names(&[("mine", Tier::Config), ("pool", Tier::Pool)]);
    let out = r.expand(t(100), &n);
    assert_eq!(out.len(), 2, "pool only");
    r.mark_resolved(t(100));
    assert!(!r.due(t(100 + 59)));
    assert!(r.due(t(100 + 60)));

    // The config name resolves. The retry flag clears.
    r.lookup_mut().set("mine", &["192.0.2.1"]);
    let out = r.expand(t(160), &n);
    assert_eq!(out.len(), 3);
    r.mark_resolved(t(160));
    assert!(!r.due(t(160 + 60)));
    assert!(r.due(t(160).checked_add(RE_RESOLVE_INTERVAL).expect("fits")));
}

#[test]
fn a_name_with_no_usable_address_is_retried_soon() {
    let f = Fake::default()
        .with("mine", &["127.0.0.1"])
        .with("pool", &["203.0.113.1"]);
    let mut r = resolver(f);
    r.expand(
        t(0),
        &names(&[("mine", Tier::Config), ("pool", Tier::Pool)]),
    );
    r.mark_resolved(t(0));
    assert!(r.due(t(60)));
}

#[test]
fn a_duplicate_of_a_higher_tier_is_not_a_reason_to_retry() {
    let f = Fake::default()
        .with("mine", &["192.0.2.1"])
        .with("pool", &["192.0.2.1"]);
    let mut r = resolver(f);
    r.expand(
        t(0),
        &names(&[("mine", Tier::Config), ("pool", Tier::Pool)]),
    );
    r.mark_resolved(t(0));
    assert!(!r.due(t(60)));
    assert_eq!(r.take_notes().len(), 0);
}

#[test]
fn a_good_answer_restarts_the_24_hour_window() {
    let mut r = resolver(Fake::default().with("a", &["192.0.2.1"]));
    let n = names(&[("a", Tier::Config)]);
    r.expand(t(0), &n);
    r.expand(t(20 * 3600), &n);
    lookup_err(r.lookup_mut(), "a", io::ErrorKind::TimedOut);
    assert_eq!(r.expand(t(40 * 3600), &n).len(), 1);
}

fn pool_calls(r: &Resolver<Fake, Own>) -> usize {
    r.lookup
        .calls
        .borrow()
        .iter()
        .filter(|c| *c == "pool")
        .count()
}

/// One pass the way the host runs it: expand, then mark.
fn pass(r: &mut Resolver<Fake, Own>, at: u64, n: &[(String, Tier)]) -> Vec<SourceSpec> {
    let out = r.expand(t(at), n);
    r.mark_resolved(t(at));
    out
}

#[test]
fn previous_addresses_are_kept_for_24_hours_then_dropped() {
    let mut r = resolver(Fake::default().with("a", &["192.0.2.1"]));
    let n = names(&[("a", Tier::Config)]);
    assert_eq!(pass(&mut r, 0, &n).len(), 1);
    lookup_err(r.lookup_mut(), "a", io::ErrorKind::TimedOut);
    let day = 24 * 3600;
    assert_eq!(pass(&mut r, 3600, &n).len(), 1);
    // A kept answer is not a reason to hurry.
    assert!(!r.due(t(3600 + 60)));
    assert_eq!(pass(&mut r, day, &n).len(), 1, "exactly 24 h is kept");
    r.take_notes();
    assert_eq!(pass(&mut r, day + 1, &n).len(), 0, "past 24 h is dropped");
    assert!(
        r.take_notes()
            .contains(&ResolveNote::PreviousExpired { name: "a".into() })
    );
    // Now the name is failing with nothing cached, so retry at 60 s.
    assert!(!r.due(t(day + 1 + 59)));
    assert!(r.due(t(day + 1 + 60)));
    // Once dropped it stays dropped.
    assert_eq!(pass(&mut r, day + 61, &n).len(), 0);
}

#[test]
fn two_failures_in_a_row_still_retry() {
    let mut f = Fake::default();
    f.fail("a");
    let mut r = resolver(f);
    let n = names(&[("a", Tier::Config)]);
    assert_eq!(pass(&mut r, 0, &n).len(), 0);
    assert!(r.due(t(60)));
    assert_eq!(pass(&mut r, 60, &n).len(), 0);
    assert!(!r.due(t(60 + 119)));
    assert!(r.due(t(60 + 120)), "second failure still retries");
    pass(&mut r, 180, &n);
    assert!(r.due(t(180 + 240)), "third failure still retries");
    // No cache, so nothing is reported as kept.
    assert!(
        !r.take_notes()
            .iter()
            .any(|x| matches!(x, ResolveNote::KeptPrevious { .. }))
    );
}

#[test]
fn a_failure_after_an_empty_answer_still_retries() {
    let mut r = resolver(Fake::default().with("a", &["127.0.0.1"]));
    let n = names(&[("a", Tier::Config)]);
    pass(&mut r, 0, &n);
    assert!(r.due(t(60)));
    r.lookup_mut().fail("a");
    pass(&mut r, 60, &n);
    assert!(r.due(t(60 + 120)));
}

#[test]
fn a_failing_name_does_not_make_the_pool_name_resolve_again() {
    let mut f = Fake::default().with("pool", &["203.0.113.1", "203.0.113.2", "203.0.113.3"]);
    f.fail("mine");
    let mut r = resolver(f);
    let n = names(&[("mine", Tier::Config), ("pool", Tier::Pool)]);
    let first = pass(&mut r, 0, &n);
    assert_eq!(pool_calls(&r), 1);
    // Retry passes inside the hour. The pool answer would rotate if asked.
    r.lookup_mut()
        .set("pool", &["203.0.113.50", "203.0.113.51"]);
    let mut at = 0;
    for wait in [60, 120, 240, 480, 960] {
        at += wait;
        let out = pass(&mut r, at, &n);
        assert_eq!(out, first, "pool ids and addresses stay put at {at}");
    }
    assert!(at < 3600);
    assert_eq!(pool_calls(&r), 1, "the pool name was not asked again");
    let mine_calls = r
        .lookup
        .calls
        .borrow()
        .iter()
        .filter(|c| *c == "mine")
        .count();
    assert_eq!(mine_calls, 6);
}

#[test]
fn a_full_pass_follows_after_an_hour() {
    let mut f = Fake::default().with("pool", &["203.0.113.1"]);
    f.fail("mine");
    let mut r = resolver(f);
    let n = names(&[("mine", Tier::Config), ("pool", Tier::Pool)]);
    pass(&mut r, 0, &n);
    pass(&mut r, 3600, &n);
    assert_eq!(pool_calls(&r), 2);
}

#[test]
fn a_changed_name_list_forces_a_full_pass() {
    let mut f = Fake::default().with("pool", &["203.0.113.1"]);
    f.fail("mine");
    let mut r = resolver(f);
    pass(
        &mut r,
        0,
        &names(&[("mine", Tier::Config), ("pool", Tier::Pool)]),
    );
    pass(
        &mut r,
        60,
        &names(&[
            ("mine", Tier::Config),
            ("pool", Tier::Pool),
            ("x", Tier::Dhcp),
        ]),
    );
    assert_eq!(pool_calls(&r), 2);
}

#[test]
fn retry_interval_doubles_to_an_hour_and_resets_after_success() {
    let mut f = Fake::default().with("pool", &["203.0.113.1"]);
    f.fail("mine");
    let mut r = resolver(f);
    let n = names(&[("mine", Tier::Config), ("pool", Tier::Pool)]);
    let mut at = 0;
    pass(&mut r, at, &n);
    for wait in [60, 120, 240, 480, 960, 1920, 3600, 3600] {
        assert!(!r.due(t(at + wait - 1)), "not due before {wait}");
        assert!(r.due(t(at + wait)), "due at {wait}");
        at += wait;
        pass(&mut r, at, &n);
    }
    // The name comes back. One clean pass resets the wait to an hour.
    r.lookup_mut().set("mine", &["192.0.2.1"]);
    let out = pass(&mut r, at, &n);
    assert_eq!(out.len(), 2);
    assert!(!r.due(t(at + 3599)));
    assert!(r.due(t(at + 3600)));
    // A new failing name with nothing cached starts again at 60 s.
    r.lookup_mut().fail("x");
    at += 3600;
    let n2 = names(&[
        ("mine", Tier::Config),
        ("pool", Tier::Pool),
        ("x", Tier::Dhcp),
    ]);
    pass(&mut r, at, &n2);
    assert!(r.due(t(at + 60)) && !r.due(t(at + 59)));
}

#[test]
fn not_found_does_not_drop_the_cache() {
    // Windows reports NXDOMAIN and an offline network with one code, so only
    // age may drop cached addresses.
    let mut r = resolver(Fake::default().with("a", &["192.0.2.1"]));
    let n = names(&[("a", Tier::Config)]);
    assert_eq!(pass(&mut r, 0, &n).len(), 1);
    lookup_err(r.lookup_mut(), "a", io::ErrorKind::NotFound);
    assert_eq!(pass(&mut r, 1, &n).len(), 1);
    let notes = r.take_notes();
    assert!(notes.contains(&ResolveNote::KeptPrevious { name: "a".into() }));
}

struct RawFail(i32);
impl NameLookup for RawFail {
    fn lookup(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        Err(io::Error::from_raw_os_error(self.0))
    }
}

#[test]
fn lookup_failure_note_carries_the_os_code() {
    let mut r = Resolver::new(RawFail(11001), Own(Vec::new()));
    r.expand(t(0), &names(&[("a.example", Tier::Config)]));
    let notes = r.take_notes();
    assert!(
        notes.iter().any(|n| matches!(
            n,
            ResolveNote::LookupFailed {
                code: Some(11001),
                ..
            }
        )),
        "{notes:?}"
    );
}
