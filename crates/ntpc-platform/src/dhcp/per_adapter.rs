//! Per-adapter DHCP option 42 reads, for the host's negative cache (R82).
//!
//! The host remembers adapters whose lease offered no option 42 and skips
//! them until the lease changes. A skipped adapter is not asked at all, so
//! no DHCPINFORM goes out for it. The key is the adapter GUID plus the lease
//! server: a new lease from another server is a new key, and the host
//! forgets the old one.
//!
//! Privacy: a key holds an adapter GUID and a lease server address. Keys are
//! for the cache only. Never log or print one.

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::Ipv4Addr;

use super::{AdapterInfo, DhcpError, merge_servers, parse_option42, select_adapters};

/// One leased adapter: `<adapter GUID>/<lease server>`. Never logged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdapterKey(pub String);

impl AdapterKey {
    /// The key of an adapter GUID string and its lease server.
    #[must_use]
    pub fn new(guid: &str, lease_server: Ipv4Addr) -> Self {
        Self(format!("{guid}/{lease_server}"))
    }
}

/// What one adapter gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseOptions {
    /// Option 42 servers, deduplicated, at most `MAX_SERVERS`.
    Servers(Vec<Ipv4Addr>),
    /// The lease holds no option 42, or a malformed or empty one. The host
    /// negative-caches the adapter.
    NoOption42,
    /// In the skip set. Not asked, so nothing was sent.
    Skipped,
    /// The request failed with this Win32 code (`-1`: no code). Not a
    /// "no option 42" answer, so the host must not cache it.
    Failed(i32),
}

/// One leased adapter and what it gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterLease {
    /// The adapter and its lease server.
    pub key: AdapterKey,
    /// The option 42 outcome.
    pub options: LeaseOptions,
}

/// The servers of every adapter that gave some, in adapter order, merged,
/// deduplicated and capped at `MAX_SERVERS`.
#[must_use]
pub fn merged_servers(leases: &[AdapterLease]) -> Vec<Ipv4Addr> {
    merge_servers(leases.iter().filter_map(|l| match &l.options {
        LeaseOptions::Servers(s) => Some(s.clone()),
        _ => None,
    }))
}

/// The GUID string of a NUL-terminated wide adapter name. The name passed
/// `adapter_name_wide`, so it is ASCII.
#[cfg_attr(not(windows), allow(dead_code))]
fn guid_of(name: &[u16]) -> String {
    name.iter()
        .take_while(|&&c| c != 0)
        .filter_map(|&c| char::from_u32(u32::from(c)))
        .collect()
}

/// The pure core. `start` opens the DHCP API and runs only if at least one
/// adapter is to be asked. `request` asks one adapter (a wide GUID name)
/// and gives the option bytes, `None` for no option 42, or a Win32 code.
///
/// Adapters: [`select_adapters`] order (metric, then interface index). One
/// without a lease server address is left out: it has no key.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn read_with<A, S: BuildHasher>(
    adapters: Vec<AdapterInfo>,
    skip: &HashSet<AdapterKey, S>,
    start: impl FnOnce() -> Result<A, i32>,
    mut request: impl FnMut(&A, &[u16]) -> Result<Option<Vec<u8>>, i32>,
) -> Result<Vec<AdapterLease>, DhcpError> {
    let keyed: Vec<(AdapterKey, Vec<u16>)> = select_adapters(adapters)
        .into_iter()
        .filter_map(|a| {
            let server = a.lease_server?;
            Some((AdapterKey::new(&guid_of(&a.name), server), a.name))
        })
        .collect();
    let mut api = None;
    if keyed.iter().any(|(k, _)| !skip.contains(k)) {
        api = Some(start().map_err(DhcpError::ApiStart)?);
    }
    let mut out = Vec::with_capacity(keyed.len());
    let (mut asked, mut failed, mut first_error) = (0usize, 0usize, None);
    for (key, name) in keyed {
        let options = match &api {
            Some(api) if !skip.contains(&key) => {
                asked += 1;
                match request(api, &name) {
                    Ok(Some(data)) => {
                        let list = parse_option42(&data);
                        if list.is_empty() {
                            LeaseOptions::NoOption42
                        } else {
                            LeaseOptions::Servers(list)
                        }
                    }
                    Ok(None) => LeaseOptions::NoOption42,
                    Err(code) => {
                        failed += 1;
                        first_error.get_or_insert(code);
                        LeaseOptions::Failed(code)
                    }
                }
            }
            _ => LeaseOptions::Skipped,
        };
        out.push(AdapterLease { key, options });
    }
    match first_error {
        Some(code) if asked > 0 && failed == asked => Err(DhcpError::Request(code)),
        _ => Ok(out),
    }
}

/// Reads option 42 from every leased IPv4 adapter not in `skip`.
///
/// BLOCKING and may touch the NETWORK, like [`super::read_lease_servers`]:
/// an adapter that is asked may get a DHCPINFORM and the call may take up to
/// 2 minutes per adapter. A skipped adapter gets nothing. When every adapter
/// is skipped the DHCP API is not even started.
///
/// Every leased adapter appears once in the result, in metric order, also
/// the skipped ones, so the host can see which keys still exist.
///
/// # Errors
/// [`DhcpError::AdapterList`] or [`DhcpError::ApiStart`] if those fail.
/// [`DhcpError::Request`] if every adapter that was asked failed.
/// [`DhcpError::Unsupported`] off Windows.
#[cfg(windows)]
pub fn read_lease_servers_per_adapter<S: BuildHasher>(
    skip: &HashSet<AdapterKey, S>,
) -> Result<Vec<AdapterLease>, DhcpError> {
    use crate::win32::dhcp::{DhcpApi, list_adapters};
    let code = |e: std::io::Error| e.raw_os_error().unwrap_or(-1);
    let adapters = list_adapters().map_err(|e| DhcpError::AdapterList(code(e)))?;
    read_with(
        adapters,
        skip,
        || DhcpApi::start().map_err(code),
        |api: &DhcpApi, name| api.request_option42(name).map_err(code),
    )
}

/// Off Windows there is no DHCP reader in version one.
///
/// # Errors
/// Always [`DhcpError::Unsupported`].
#[cfg(not(windows))]
pub fn read_lease_servers_per_adapter<S: BuildHasher>(
    _skip: &HashSet<AdapterKey, S>,
) -> Result<Vec<AdapterLease>, DhcpError> {
    Err(DhcpError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::super::adapter_name_wide;
    use super::*;
    use std::cell::RefCell;

    const S1: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 67);
    const S2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 67);
    const N1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const N2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);

    fn adapter(guid: &str, metric: u32, server: Ipv4Addr) -> AdapterInfo {
        AdapterInfo {
            name: adapter_name_wide(guid.as_bytes()).expect("test GUID"),
            if_index: metric,
            metric,
            up: true,
            dhcp_enabled: true,
            if_type: 6,
            has_lease: true,
            lease_server: Some(server),
        }
    }

    fn bytes(list: &[Ipv4Addr]) -> Vec<u8> {
        list.iter().flat_map(Ipv4Addr::octets).collect()
    }

    type Answer = (&'static str, Result<Option<Vec<u8>>, i32>);

    /// A fake API: answers by GUID, logs every adapter asked and whether
    /// the API was started.
    struct Fake {
        answers: Vec<Answer>,
        asked: RefCell<Vec<String>>,
        started: RefCell<u32>,
    }

    impl Fake {
        fn new(answers: Vec<Answer>) -> Self {
            Self {
                answers,
                asked: RefCell::new(Vec::new()),
                started: RefCell::new(0),
            }
        }

        fn run(
            &self,
            adapters: Vec<AdapterInfo>,
            skip: &HashSet<AdapterKey>,
            start_fails: Option<i32>,
        ) -> Result<Vec<AdapterLease>, DhcpError> {
            read_with(
                adapters,
                skip,
                || {
                    *self.started.borrow_mut() += 1;
                    start_fails.map_or(Ok(()), Err)
                },
                |(), name| {
                    let guid = guid_of(name);
                    self.asked.borrow_mut().push(guid.clone());
                    self.answers
                        .iter()
                        .find(|(g, _)| *g == guid)
                        .map_or(Ok(None), |(_, r)| r.clone())
                },
            )
        }
    }

    #[test]
    fn key_is_guid_and_lease_server() {
        assert_eq!(AdapterKey::new("{AB}", S1).0, "{AB}/192.0.2.67");
        assert_ne!(AdapterKey::new("{AB}", S1), AdapterKey::new("{AB}", S2));
    }

    #[test]
    fn maps_servers_no_option_and_failure_per_adapter() {
        let f = Fake::new(vec![
            ("{A1}", Ok(Some(bytes(&[N1, N2])))),
            ("{B2}", Ok(None)),
            ("{C3}", Err(1460)),
            ("{D4}", Ok(Some(vec![1, 2, 3]))),
        ]);
        let got = f
            .run(
                vec![
                    adapter("{C3}", 30, S1),
                    adapter("{A1}", 10, S1),
                    adapter("{D4}", 40, S2),
                    adapter("{B2}", 20, S2),
                ],
                &HashSet::new(),
                None,
            )
            .expect("one adapter answered");
        let opts: Vec<(String, LeaseOptions)> =
            got.into_iter().map(|l| (l.key.0, l.options)).collect();
        assert_eq!(
            opts,
            vec![
                (
                    "{A1}/192.0.2.67".into(),
                    LeaseOptions::Servers(vec![N1, N2])
                ),
                ("{B2}/198.51.100.67".into(), LeaseOptions::NoOption42),
                ("{C3}/192.0.2.67".into(), LeaseOptions::Failed(1460)),
                ("{D4}/198.51.100.67".into(), LeaseOptions::NoOption42,),
            ],
            "metric order, malformed option counts as none"
        );
        assert_eq!(*f.started.borrow(), 1);
    }

    #[test]
    fn a_skipped_adapter_is_never_asked() {
        let f = Fake::new(vec![("{A1}", Ok(Some(bytes(&[N1]))))]);
        let skip = HashSet::from([AdapterKey::new("{B2}", S2)]);
        let got = f
            .run(
                vec![adapter("{A1}", 1, S1), adapter("{B2}", 2, S2)],
                &skip,
                None,
            )
            .unwrap();
        assert_eq!(*f.asked.borrow(), vec!["{A1}".to_owned()]);
        assert_eq!(got[1].options, LeaseOptions::Skipped);
        assert_eq!(got[1].key, AdapterKey::new("{B2}", S2));
    }

    #[test]
    fn a_new_lease_server_is_a_new_key_and_is_asked() {
        let f = Fake::new(vec![]);
        // Cached under the old lease server, now leased from another.
        let skip = HashSet::from([AdapterKey::new("{A1}", S1)]);
        let got = f.run(vec![adapter("{A1}", 1, S2)], &skip, None).unwrap();
        assert_eq!(*f.asked.borrow(), vec!["{A1}".to_owned()]);
        assert_eq!(got[0].options, LeaseOptions::NoOption42);
    }

    #[test]
    fn all_skipped_starts_no_api_and_sends_nothing() {
        let f = Fake::new(vec![]);
        let skip = HashSet::from([AdapterKey::new("{A1}", S1), AdapterKey::new("{B2}", S2)]);
        let got = f
            .run(
                vec![adapter("{A1}", 1, S1), adapter("{B2}", 2, S2)],
                &skip,
                Some(5),
            )
            .expect("no API start, so no start error");
        assert_eq!(*f.started.borrow(), 0);
        assert!(f.asked.borrow().is_empty());
        assert!(got.iter().all(|l| l.options == LeaseOptions::Skipped));
    }

    #[test]
    fn no_leased_adapter_is_an_empty_ok() {
        let f = Fake::new(vec![]);
        let mut no_server = adapter("{A1}", 1, S1);
        no_server.lease_server = None;
        let mut down = adapter("{B2}", 2, S2);
        down.up = false;
        assert_eq!(
            f.run(vec![no_server, down], &HashSet::new(), Some(5)),
            Ok(vec![])
        );
        assert_eq!(*f.started.borrow(), 0);
    }

    #[test]
    fn api_start_failure_is_an_error() {
        let f = Fake::new(vec![]);
        assert_eq!(
            f.run(vec![adapter("{A1}", 1, S1)], &HashSet::new(), Some(5)),
            Err(DhcpError::ApiStart(5))
        );
    }

    #[test]
    fn every_asked_adapter_failing_is_an_error_with_the_first_code() {
        let f = Fake::new(vec![("{A1}", Err(1460)), ("{B2}", Err(87))]);
        let skip = HashSet::from([AdapterKey::new("{C3}", S1)]);
        assert_eq!(
            f.run(
                vec![
                    adapter("{A1}", 1, S1),
                    adapter("{B2}", 2, S2),
                    adapter("{C3}", 3, S1),
                ],
                &skip,
                None
            ),
            Err(DhcpError::Request(1460)),
            "a skipped adapter does not count as an answer"
        );
    }

    #[test]
    fn merged_servers_keeps_adapter_order_and_caps() {
        let leases = vec![
            AdapterLease {
                key: AdapterKey::new("{A1}", S1),
                options: LeaseOptions::Servers(vec![N2, N1]),
            },
            AdapterLease {
                key: AdapterKey::new("{B2}", S1),
                options: LeaseOptions::NoOption42,
            },
            AdapterLease {
                key: AdapterKey::new("{C3}", S1),
                options: LeaseOptions::Servers(vec![N1, S2]),
            },
            AdapterLease {
                key: AdapterKey::new("{D4}", S1),
                options: LeaseOptions::Skipped,
            },
        ];
        assert_eq!(merged_servers(&leases), vec![N2, N1, S2]);
        let many: Vec<AdapterLease> = (0..5u8)
            .map(|n| AdapterLease {
                key: AdapterKey::new("{E5}", S1),
                options: LeaseOptions::Servers(
                    (0..10u8)
                        .map(|i| Ipv4Addr::new(198, 51, 100, n * 10 + i))
                        .collect(),
                ),
            })
            .collect();
        assert_eq!(merged_servers(&many).len(), super::super::MAX_SERVERS);
    }

    #[test]
    fn key_text_holds_only_the_guid_and_server() {
        let k = AdapterKey::new(&guid_of(&adapter_name_wide(b"{0A-1b}").unwrap()), S1);
        assert_eq!(k.0, "{0A-1b}/192.0.2.67");
    }
}
