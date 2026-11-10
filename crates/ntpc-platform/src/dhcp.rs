//! DHCP-supplied NTP servers, IPv4 option 42 only.
//!
//! The pure parts build everywhere so the fuzz job on Linux sees them. The
//! OS calls live in `win32::dhcp`. Method, rules and sources:
//! `docs/architecture.md`, "Platform: DHCP option 42".

use std::net::Ipv4Addr;

/// Most servers one option, or one read across adapters, may yield.
/// RFC 2132 allows up to 63 in one option. The resolver keeps 8 per tier.
pub const MAX_SERVERS: usize = 16;

/// Parses the data of DHCP option 42 (no code or length byte).
///
/// Empty input, or a length that is not a multiple of 4, gives an empty
/// list: a malformed option must not give a half-trusted list. Duplicates
/// are removed, first wins. At most [`MAX_SERVERS`] are returned. Address
/// classes are not filtered here: the resolver owns that rule.
#[must_use]
pub fn parse_option42(bytes: &[u8]) -> Vec<Ipv4Addr> {
    let (chunks, rest) = bytes.as_chunks::<4>();
    if chunks.is_empty() || !rest.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Ipv4Addr> = Vec::with_capacity(MAX_SERVERS);
    for c in chunks {
        // Stopping at the cap keeps a huge input cheap.
        if out.len() == MAX_SERVERS {
            break;
        }
        let a = Ipv4Addr::from(*c);
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Joins server lists in order, drops duplicates (first wins) and caps the
/// result at [`MAX_SERVERS`]. Used across adapters.
#[must_use]
pub fn merge_servers<I>(lists: I) -> Vec<Ipv4Addr>
where
    I: IntoIterator<Item = Vec<Ipv4Addr>>,
{
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for a in lists.into_iter().flatten() {
        if out.len() == MAX_SERVERS {
            break;
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const C: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 200);
    const NONE: Vec<Ipv4Addr> = Vec::new();

    fn bytes(list: &[Ipv4Addr]) -> Vec<u8> {
        list.iter().flat_map(Ipv4Addr::octets).collect()
    }

    #[test]
    fn parses_one_server() {
        assert_eq!(parse_option42(&[192, 0, 2, 1]), vec![A]);
    }

    #[test]
    fn parses_several_servers() {
        assert_eq!(parse_option42(&bytes(&[A, B, C])), vec![A, B, C]);
    }

    #[test]
    fn rejects_length_not_multiple_of_four() {
        for extra in 1..4 {
            let mut b = bytes(&[A, B]);
            b.extend(std::iter::repeat_n(9, extra));
            assert_eq!(parse_option42(&b), NONE, "extra {extra}");
        }
        assert_eq!(parse_option42(&[192, 0, 2]), NONE);
    }

    #[test]
    fn empty_input_gives_empty_vec() {
        assert_eq!(parse_option42(&[]), NONE);
    }

    #[test]
    fn removes_duplicates_first_wins() {
        assert_eq!(parse_option42(&bytes(&[B, A, B, C, A])), vec![B, A, C]);
    }

    #[test]
    fn keeps_address_classes_for_the_resolver() {
        // The resolver drops these. Filtering twice would hide which layer
        // owns the rule, so the parser passes them through.
        let odd = [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 1, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(169, 254, 1, 1),
        ];
        assert_eq!(parse_option42(&bytes(&odd)), odd.to_vec());
    }

    #[test]
    fn caps_at_max_servers() {
        let many: Vec<Ipv4Addr> = (0..40u8).map(|i| Ipv4Addr::new(198, 51, 100, i)).collect();
        let got = parse_option42(&bytes(&many));
        assert_eq!(got, many[..MAX_SERVERS].to_vec());
    }

    #[test]
    fn duplicates_do_not_use_up_the_cap() {
        let mut list = vec![A; 100];
        list.push(B);
        assert_eq!(parse_option42(&bytes(&list)), vec![A, B]);
    }

    #[test]
    fn merge_keeps_order_drops_duplicates_and_caps() {
        assert_eq!(merge_servers(vec![vec![B, A], vec![A, C]]), vec![B, A, C]);
        assert_eq!(merge_servers(Vec::<Vec<Ipv4Addr>>::new()), NONE);
        let many: Vec<Vec<Ipv4Addr>> = (0..3u8)
            .map(|n| {
                (0..10u8)
                    .map(|i| Ipv4Addr::new(203, 0, 113, n * 10 + i))
                    .collect()
            })
            .collect();
        let got = merge_servers(many.clone());
        assert_eq!(got.len(), MAX_SERVERS);
        assert_eq!(got[..10], many[0][..]);
    }

    #[test]
    fn huge_garbage_input_is_bounded() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let big: Vec<u8> = (0..1_048_576)
            .map(|_| next(&mut seed).to_le_bytes()[0])
            .collect();
        assert!(parse_option42(&big).len() <= MAX_SERVERS);
        assert_eq!(parse_option42(&big[..big.len() - 1]), NONE);
    }

    /// xorshift64. Deterministic, no dependency.
    fn next(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    #[test]
    fn fuzz_like_loop_never_panics_and_invents_nothing() {
        let mut seed = 0x0123_4567_89ab_cdefu64;
        for _ in 0..5_000 {
            let len = usize::try_from(next(&mut seed) % 300).unwrap_or(0);
            // Mostly a few distinct values, so duplicates happen often.
            let buf: Vec<u8> = (0..len)
                .map(|_| next(&mut seed).to_le_bytes()[0] % 4)
                .collect();
            let got = parse_option42(&buf);
            assert!(got.len() <= MAX_SERVERS);
            if !len.is_multiple_of(4) {
                assert_eq!(got, NONE);
            }
            let chunks = buf.as_chunks::<4>().0;
            for (i, a) in got.iter().enumerate() {
                assert!(chunks.contains(&a.octets()), "address not in input");
                assert!(!got[..i].contains(a), "duplicate returned");
            }
        }
    }
}
