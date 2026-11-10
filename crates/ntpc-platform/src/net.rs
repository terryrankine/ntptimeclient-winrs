//! This machine's own unicast addresses, IPv4 and IPv6.
//!
//! The resolver drops these from every source list, so a server name that
//! points back at this machine is never queried. The pure parts build
//! everywhere. The OS walk lives in `win32::adapters`.
//!
//! Privacy: the list is for the resolver only. Nothing here logs or prints
//! an address, and error text holds a Win32 code only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Most addresses [`own_addresses`] returns. A real machine has a few dozen
/// at most. The cap keeps a broken or hostile driver list cheap.
pub const MAX_OWN_ADDRESSES: usize = 256;

/// Why the address list could not be read. Holds a Win32 code only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// Not Windows.
    #[error("listing this machine's addresses is not supported on this platform")]
    Unsupported,
    /// `GetAdaptersAddresses` failed.
    #[error("listing this machine's addresses failed (os error {0})")]
    AdapterList(i32),
}

/// `AF_INET` and `AF_INET6` as Windows numbers them.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

/// Reads a `SOCKADDR_IN` or `SOCKADDR_IN6` from raw bytes (little endian
/// family). `None` for any other family, a short buffer or the
/// unspecified address.
#[must_use]
pub(crate) fn parse_sockaddr(sa: &[u8]) -> Option<IpAddr> {
    let family = u16::from_le_bytes([*sa.first()?, *sa.get(1)?]);
    let ip = match family {
        // SOCKADDR_IN: family, port, 4 address bytes, 8 zero bytes.
        AF_INET => {
            let b: [u8; 4] = sa.get(4..8)?.try_into().ok()?;
            if sa.len() < 16 {
                return None;
            }
            IpAddr::V4(Ipv4Addr::from(b))
        }
        // SOCKADDR_IN6: family, port, flow info, 16 address bytes, scope.
        AF_INET6 => {
            let b: [u8; 16] = sa.get(8..24)?.try_into().ok()?;
            if sa.len() < 28 {
                return None;
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    (!ip.is_unspecified()).then_some(ip)
}

/// Sorts, removes duplicates and caps at [`MAX_OWN_ADDRESSES`]. Sorting
/// makes the result the same whatever order the OS lists adapters in.
#[must_use]
pub(crate) fn finish(mut list: Vec<IpAddr>) -> Vec<IpAddr> {
    list.sort_unstable();
    list.dedup();
    list.truncate(MAX_OWN_ADDRESSES);
    list
}

/// Every unicast address of every adapter, IPv4 and IPv6, sorted and
/// deduplicated, at most [`MAX_OWN_ADDRESSES`]. Read only, no packet.
///
/// Adapters that are down are included: the list only removes candidates,
/// so a superset is the safe side.
///
/// # Errors
/// [`NetError::AdapterList`] if `GetAdaptersAddresses` fails.
#[cfg(windows)]
pub fn own_addresses() -> Result<Vec<IpAddr>, NetError> {
    crate::win32::adapters::own_unicast_addresses()
        .map(finish)
        .map_err(|e| NetError::AdapterList(e.raw_os_error().unwrap_or(-1)))
}

/// Off Windows there is no adapter walk in version one.
///
/// # Errors
/// Always [`NetError::Unsupported`].
#[cfg(not(windows))]
pub fn own_addresses() -> Result<Vec<IpAddr>, NetError> {
    Err(NetError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sin(a: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[0] = 2;
        v[2] = 0x00;
        v[3] = 0x7b;
        v[4..8].copy_from_slice(&a);
        v
    }

    fn sin6(a: Ipv6Addr) -> Vec<u8> {
        let mut v = vec![0u8; 28];
        v[0] = 23;
        v[8..24].copy_from_slice(&a.octets());
        v
    }

    const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    #[test]
    fn parses_ipv4_and_ipv6() {
        assert_eq!(
            parse_sockaddr(&sin([192, 0, 2, 1])),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(parse_sockaddr(&sin6(V6)), Some(IpAddr::V6(V6)));
    }

    #[test]
    fn refuses_short_unknown_and_unspecified() {
        assert_eq!(parse_sockaddr(&sin([192, 0, 2, 1])[..15]), None);
        assert_eq!(parse_sockaddr(&sin6(V6)[..27]), None);
        assert_eq!(parse_sockaddr(&[]), None);
        assert_eq!(parse_sockaddr(&[2]), None);
        let mut other = sin([192, 0, 2, 1]);
        other[0] = 17;
        assert_eq!(parse_sockaddr(&other), None);
        assert_eq!(parse_sockaddr(&sin([0, 0, 0, 0])), None);
        assert_eq!(parse_sockaddr(&sin6(Ipv6Addr::UNSPECIFIED)), None);
    }

    #[test]
    fn finish_sorts_dedups_and_caps() {
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let c = IpAddr::V6(V6);
        assert_eq!(finish(vec![c, a, b, a, c]), vec![b, a, c]);
        let many: Vec<IpAddr> = (0..2000u32)
            .map(|i| IpAddr::V6(Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(i))))
            .rev()
            .collect();
        let got = finish(many);
        assert_eq!(got.len(), MAX_OWN_ADDRESSES);
        assert!(got.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn parse_never_panics_on_random_bytes() {
        let mut s = 0x1234_5678_9abc_def0u64;
        for _ in 0..5_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let len = usize::try_from(s % 40).unwrap_or(0);
            let buf: Vec<u8> = (0..len)
                .map(|i| (s >> (i % 8 * 8)).to_le_bytes()[0])
                .collect();
            let _ = parse_sockaddr(&buf);
        }
    }

    #[test]
    fn error_text_holds_no_address() {
        for e in [NetError::Unsupported, NetError::AdapterList(87)] {
            let t = e.to_string();
            // An IPv4 address needs three dots, an IPv6 one a colon.
            assert!(t.matches('.').count() < 3, "{t}");
            assert!(!t.contains(':'), "{t}");
        }
    }

    /// Read only: one `GetAdaptersAddresses` call, no packet. Prints
    /// nothing and checks no value, so no address reaches the test log.
    #[cfg(windows)]
    #[test]
    fn live_own_addresses_returns_cleanly() {
        match own_addresses() {
            Ok(list) => {
                assert!(list.len() <= MAX_OWN_ADDRESSES);
                assert!(list.windows(2).all(|w| w[0] < w[1]), "sorted, unique");
                assert!(list.iter().all(|a| !a.is_unspecified()));
            }
            Err(e) => assert!(matches!(e, NetError::AdapterList(_))),
        }
    }
}
