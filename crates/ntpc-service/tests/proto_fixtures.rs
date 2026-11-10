//! Protocol adapter tests over hand-built reply packets.
//!
//! Every fixture is written by hand from RFC 5905 field layout. No bytes
//! come from a capture or the internet. The origin timestamp (bytes 24 to
//! 31) is left zero in each fixture. The test copies it from the request,
//! as a real server echoes our transmit timestamp.
//!
//! Times are chosen so the expected offset and delay are easy to check:
//! `offset = ((T2 - T1) + (T3 - T4)) / 2` and
//! `delay = (T4 - T1) - (T3 - T2)`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ntpc_core::{KodCode, Mono, QueryFailure, Sample, SourceId};
use ntpc_service::proto::{NtpTime, RequestToken, build_request, parse_response};

/// TEST-NET-1 address, reserved for documentation (RFC 5737).
const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 123);

/// 2026-11-10T00:00:00Z. NTP seconds 0xEE9CDD00, fraction zero.
const T1: u64 = 0xEE9C_DD00_0000_0000;

const SOURCE: u32 = 7;
const AT_NANOS: u64 = 5_000_000_000;

// Fixture A: server 10 s ahead, symmetric 20 ms each way, 1 ms processing.
// T2 = T1 + 10.020 s, T3 = T1 + 10.021 s, T4 = T1 + 0.041 s.
// Offset = (10.020 + 9.980) / 2 = 10.000 s. Delay = 0.041 - 0.001 = 0.040 s.
// Fractions are the decimal value times 2^32, rounded to nearest.
const T4_A: u64 = 0xEE9C_DD00_0A7E_F9DB;
const FIXTURE_A: [u8; 48] = [
    0x24, // LI 0 (no warning), VN 4, mode 4 (server)
    0x02, // stratum 2
    0x06, // poll 2^6 s
    0xEC, // precision 2^-20 s
    0x00, 0x00, 0x01, 0x00, // root delay 1/256 s, 16.16 format
    0x00, 0x00, 0x00, 0x80, // root dispersion 1/512 s
    0xC0, 0x00, 0x02, 0x01, // refid: upstream 192.0.2.1 (TEST-NET-1)
    0xEE, 0x9C, 0xDC, 0xF0, 0x00, 0x00, 0x00, 0x00, // reference time T1 - 16 s
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin, filled per test
    0xEE, 0x9C, 0xDD, 0x0A, 0x05, 0x1E, 0xB8, 0x52, // T2 = T1 + 10.020 s
    0xEE, 0x9C, 0xDD, 0x0A, 0x05, 0x60, 0x41, 0x89, // T3 = T1 + 10.021 s
];

// Fixture B: asymmetric path. Server clock exact. Out 30 ms, back 10 ms,
// 2 ms processing. T2 = T1 + 0.030, T3 = T1 + 0.032, T4 = T1 + 0.042.
// Offset = (0.030 + (0.032 - 0.042)) / 2 = +0.010 s, half the 20 ms
// asymmetry. Delay = 0.042 - 0.002 = 0.040 s.
const T4_B: u64 = 0xEE9C_DD00_0AC0_8312;
const FIXTURE_B: [u8; 48] = [
    0x24, 0x01, 0x06, 0xEC, // LI 0, VN 4, server, stratum 1, poll 6, prec -20
    0x00, 0x00, 0x00, 0x00, // root delay 0, a stratum 1 server
    0x00, 0x00, 0x00, 0x10, // root dispersion 1/4096 s
    b'G', b'P', b'S', 0x00, // refid: reference clock name "GPS"
    0xEE, 0x9C, 0xDC, 0xFF, 0x00, 0x00, 0x00, 0x00, // reference time T1 - 1 s
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin, filled per test
    0xEE, 0x9C, 0xDD, 0x00, 0x07, 0xAE, 0x14, 0x7B, // T2 = T1 + 0.030 s
    0xEE, 0x9C, 0xDD, 0x00, 0x08, 0x31, 0x26, 0xE9, // T3 = T1 + 0.032 s
];

// Fixture C: server 2.5 s behind, symmetric 10 ms each way, no processing.
// T2 = T3 = T1 - 2.490 s, T4 = T1 + 0.020 s.
// Offset = (-2.490 + -2.510) / 2 = -2.500 s. Delay = 0.020 s.
const T4_C: u64 = 0xEE9C_DD00_051E_B852;
const FIXTURE_C: [u8; 48] = [
    0x24, 0x03, 0x06, 0xEC, // LI 0, VN 4, server, stratum 3, poll 6, prec -20
    0x00, 0x00, 0x02, 0x00, // root delay 1/128 s
    0x00, 0x00, 0x01, 0x00, // root dispersion 1/256 s
    0xC0, 0x00, 0x02, 0x02, // refid: upstream 192.0.2.2
    0xEE, 0x9C, 0xDC, 0xF0, 0x00, 0x00, 0x00, 0x00, // reference time
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin, filled per test
    0xEE, 0x9C, 0xDC, 0xFD, 0x82, 0x8F, 0x5C, 0x29, // T2 = T1 - 2.490 s
    0xEE, 0x9C, 0xDC, 0xFD, 0x82, 0x8F, 0x5C, 0x29, // T3 = T2
];

// Era fixture, tight: the request leaves 0.5 s before the era 0 to era 1
// boundary (2036-02-07T06:28:16Z). Binary fractions keep it exact.
// T1 = era 0 second 0xFFFFFFFF + 0.5. Server 1 s ahead, 0.25 s each way,
// 0.25 s processing. T2 = T1 + 1.25 (era 1, 0.75 s), T3 = T1 + 1.5
// (era 1, 1.0 s), T4 = T1 + 0.75 (era 1, 0.25 s).
// Offset = (1.25 + 0.75) / 2 = 1.0 s. Delay = 0.75 - 0.25 = 0.5 s.
const ERA_T1: u64 = 0xFFFF_FFFF_8000_0000;
const ERA_T4: u64 = 0x0000_0000_4000_0000;
const FIXTURE_ERA: [u8; 48] = [
    0x24, 0x02, 0x06, 0xEC, // LI 0, VN 4, server, stratum 2, poll 6
    0x00, 0x00, 0x01, 0x00, // root delay
    0x00, 0x00, 0x00, 0x80, // root dispersion
    0xC0, 0x00, 0x02, 0x01, // refid
    0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, // reference time, era 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin, filled per test
    0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, // T2: era 1, 0.75 s
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // T3: era 1, 1.0 s
];

// Era fixture, wide: request on 2035-12-31T00:00:00Z (era 0 second
// 0xFFCD8C00). The server is wrong and stamps 2036-02-08T00:00:00Z, which is
// era 1 second 0x0000F680. T2 = that + 0.010, T3 = that + 0.011,
// T4 = T1 + 0.030. Offset = 3_369_600 s minus 4.5 ms. Delay = 0.029 s.
const WIDE_T1_UNIX_SECS: i128 = 2_082_672_000;
const WIDE_T1: u64 = 0xFFCD_8C00_0000_0000;
const WIDE_T4: u64 = 0xFFCD_8C00_07AE_147B;
const FIXTURE_WIDE: [u8; 48] = [
    0x24, 0x02, 0x06, 0xEC, // LI 0, VN 4, server, stratum 2, poll 6
    0x00, 0x00, 0x01, 0x00, // root delay
    0x00, 0x00, 0x00, 0x80, // root dispersion
    0xC0, 0x00, 0x02, 0x01, // refid
    0x00, 0x00, 0xF6, 0x70, 0x00, 0x00, 0x00, 0x00, // reference time, era 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin, filled per test
    0x00, 0x00, 0xF6, 0x80, 0x02, 0x8F, 0x5C, 0x29, // T2: era 1 + 0.010 s
    0x00, 0x00, 0xF6, 0x80, 0x02, 0xD0, 0xE5, 0x60, // T3: era 1 + 0.011 s
];

// Kiss-o'-Death template. RFC 5905 section 7.4: LI 3, stratum 0, the kiss
// code in the refid, timestamps may be zero. The test writes the code.
const FIXTURE_KOD: [u8; 48] = [
    0xE4, // LI 3 (alarm), VN 4, mode 4
    0x00, // stratum 0 marks a kiss
    0x06, 0xEC, // poll 6, precision -20
    0x00, 0x00, 0x00, 0x00, // root delay
    0x00, 0x00, 0x00, 0x00, // root dispersion
    0x00, 0x00, 0x00, 0x00, // kiss code, filled per test
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reference time
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin, filled per test
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // T2 zero
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // T3 zero
];

const ORIGIN: std::ops::Range<usize> = 24..32;
const T2: std::ops::Range<usize> = 32..40;
const T3: std::ops::Range<usize> = 40..48;

fn source() -> SourceId {
    SourceId::new(SOURCE)
}

fn at() -> Mono {
    Mono::from_nanos(AT_NANOS)
}

/// The fixture with the request's transmit timestamp echoed as origin.
fn reply_to(fixture: &[u8; 48], request: &[u8]) -> Vec<u8> {
    let mut reply = fixture.to_vec();
    reply[ORIGIN].copy_from_slice(&request[40..48]);
    reply
}

fn parse(bytes: &[u8], token: &RequestToken, t4: u64) -> Result<Sample, QueryFailure> {
    parse_response(bytes, SERVER, token, NtpTime::from_bits(t4), source(), at())
}

/// Builds a request at `t1`, answers it with `fixture` and parses at `t4`.
fn exchange(fixture: &[u8; 48], t1: u64, t4: u64) -> Result<Sample, QueryFailure> {
    let (request, token) = build_request(NtpTime::from_bits(t1), SERVER);
    parse(&reply_to(fixture, &request), &token, t4)
}

/// Fixture A with one change applied after the origin is set.
fn mutated_a(change: impl FnOnce(&mut Vec<u8>)) -> Result<Sample, QueryFailure> {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let mut reply = reply_to(&FIXTURE_A, &request);
    change(&mut reply);
    parse(&reply, &token, T4_A)
}

fn kod(code: [u8; 4]) -> [u8; 48] {
    let mut f = FIXTURE_KOD;
    f[12..16].copy_from_slice(&code);
    f
}

/// Tolerance for the 2^-32 s fixture rounding and the nanosecond step.
const TOL: f64 = 5e-9;

fn assert_close(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() <= TOL,
        "{what}: got {got:.12}, want {want:.12}"
    );
}

#[test]
fn parses_valid_fixture_into_sample() {
    let s = exchange(&FIXTURE_A, T1, T4_A).expect("valid reply");
    assert_eq!(s.source, source());
    assert_eq!(s.at, at());
    assert_eq!(s.stratum, 2);
    assert!(!s.unsynchronised);
    assert!(!s.leap_alarm);
    assert_close(s.offset.as_secs(), 10.0, "offset");
    assert_close(s.delay.as_secs(), 0.040, "delay");
}

#[test]
fn kod_maps_to_failure() {
    let cases = [
        (*b"DENY", KodCode::Deny),
        (*b"RSTR", KodCode::Rstr),
        (*b"RATE", KodCode::Rate),
        // Codes the engine does not name. It backs off as for RATE.
        (*b"INIT", KodCode::Other),
        (*b"STEP", KodCode::Other),
        (*b"NTSN", KodCode::Other),
        (*b"AUTH", KodCode::Other),
    ];
    for (code, want) in cases {
        let got = exchange(&kod(code), T1, T4_A);
        assert_eq!(
            got,
            Err(QueryFailure::KissOfDeath(want)),
            "code {}",
            String::from_utf8_lossy(&code)
        );
    }
}

#[test]
fn stratum_zero_maps_to_failure() {
    // Stratum 0 without a readable kiss code: unspecified, not a kiss.
    for refid in [
        [0, 0, 0, 0],
        [0xC0, 0, 2, 1],
        *b"de y",
        [b'R', b'A', b'T', 0],
    ] {
        let got = exchange(&kod(refid), T1, T4_A);
        assert_eq!(got, Err(QueryFailure::Malformed), "refid {refid:?}");
    }
    // A full, otherwise valid reply with stratum 0 and an address refid.
    let got = mutated_a(|r| r[1] = 0);
    assert_eq!(got, Err(QueryFailure::Malformed));
}

#[test]
fn rejects_wrong_origin_timestamp() {
    for bit in 0..64 {
        let got = mutated_a(|r| {
            let byte = ORIGIN.start + bit / 8;
            r[byte] ^= 1 << (bit % 8);
        });
        assert_eq!(got, Err(QueryFailure::Malformed), "origin bit {bit}");
    }
    assert_eq!(
        mutated_a(|r| r[ORIGIN].fill(0)),
        Err(QueryFailure::Malformed)
    );
}

#[test]
fn rejects_reply_to_a_different_request() {
    let (first, _) = build_request(NtpTime::from_bits(T1), SERVER);
    let (_, second) = build_request(NtpTime::from_bits(T1), SERVER);
    let reply = reply_to(&FIXTURE_A, &first);
    assert_eq!(parse(&reply, &second, T4_A), Err(QueryFailure::Malformed));
}

#[test]
fn rejects_reply_from_unexpected_address() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let reply = reply_to(&FIXTURE_A, &request);
    let others = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 123),
        SocketAddr::new(SERVER.ip(), 124),
        SocketAddr::new(SERVER.ip(), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 123),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            123,
        ),
    ];
    for from in others {
        let got = parse_response(
            &reply,
            from,
            &token,
            NtpTime::from_bits(T4_A),
            source(),
            at(),
        );
        assert_eq!(got, Err(QueryFailure::Malformed), "from {from}");
    }
}

#[test]
fn kod_is_not_honoured_without_a_matching_origin_or_address() {
    // A blind spoofer must not be able to silence a source (CVE-2015-7704).
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let mut reply = reply_to(&kod(*b"DENY"), &request);
    let wrong_port = SocketAddr::new(SERVER.ip(), 1123);
    let got = parse_response(
        &reply,
        wrong_port,
        &token,
        NtpTime::from_bits(T4_A),
        source(),
        at(),
    );
    assert_eq!(got, Err(QueryFailure::Malformed));
    reply[ORIGIN.start] ^= 0x80;
    assert_eq!(parse(&reply, &token, T4_A), Err(QueryFailure::Malformed));
}

#[test]
fn accepts_ipv4_mapped_form_of_the_same_address() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let reply = reply_to(&FIXTURE_A, &request);
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped()),
        123,
    );
    let got = parse_response(
        &reply,
        mapped,
        &token,
        NtpTime::from_bits(T4_A),
        source(),
        at(),
    );
    assert!(got.is_ok(), "{got:?}");
}

#[test]
fn rejects_wrong_mode_or_version() {
    for mode in [0u8, 1, 2, 3, 5, 6, 7] {
        let got = mutated_a(|r| r[0] = (r[0] & !0x07) | mode);
        assert_eq!(got, Err(QueryFailure::Malformed), "mode {mode}");
    }
    for version in [0u8, 1, 2, 5, 6, 7] {
        let got = mutated_a(|r| r[0] = (r[0] & !0x38) | (version << 3));
        assert_eq!(got, Err(QueryFailure::Malformed), "version {version}");
    }
}

#[test]
fn accepts_version_3_reply() {
    let got = mutated_a(|r| r[0] = (r[0] & !0x38) | (3 << 3));
    assert!(got.is_ok(), "{got:?}");
}

#[test]
fn rejects_truncated_packet() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let reply = reply_to(&FIXTURE_A, &request);
    for len in 0..48 {
        assert_eq!(
            parse(&reply[..len], &token, T4_A),
            Err(QueryFailure::Malformed),
            "length {len}"
        );
    }
}

#[test]
fn origin_timestamp_is_random_per_request() {
    let now = NtpTime::from_bits(T1);
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let (request, _) = build_request(now, SERVER);
        assert_eq!(request.len(), 48);
        let origin: [u8; 8] = request[40..48].try_into().expect("8 bytes");
        assert_ne!(u64::from_be_bytes(origin), T1, "real time leaked");
        assert!(seen.insert(origin), "origin repeated");
    }
}

#[test]
fn request_carries_nothing_but_version_mode_poll_and_nonce() {
    let (request, _) = build_request(NtpTime::from_bits(T1), SERVER);
    // LI 0, VN 4, mode 3 (client).
    assert_eq!(request[0], 0x23);
    assert_eq!(request[2], 6, "poll 2^6 s");
    // Stratum, precision, root fields, refid, reference, origin and receive
    // timestamps are zero, so the request does not reveal our clock.
    assert!(request[1..2].iter().all(|&b| b == 0));
    assert!(request[3..40].iter().all(|&b| b == 0));
}

#[test]
fn token_debug_hides_origin_and_address() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let text = format!("{token:?}");
    let origin = u64::from_be_bytes(request[40..48].try_into().expect("8 bytes"));
    assert!(!text.contains(&origin.to_string()), "{text}");
    assert!(!text.contains(&format!("{origin:x}")), "{text}");
    assert!(!text.contains("192.0.2.10"), "{text}");
}

#[test]
fn computes_offset_and_delay_on_asymmetric_path() {
    let s = exchange(&FIXTURE_B, T1, T4_B).expect("valid reply");
    assert_eq!(s.stratum, 1);
    assert_close(s.offset.as_secs(), 0.010, "offset");
    assert_close(s.delay.as_secs(), 0.040, "delay");
}

#[test]
fn computes_negative_offset() {
    let s = exchange(&FIXTURE_C, T1, T4_C).expect("valid reply");
    assert_close(s.offset.as_secs(), -2.5, "offset");
    assert_close(s.delay.as_secs(), 0.020, "delay");
}

#[test]
fn handles_era_rollover_across_the_boundary() {
    let s = exchange(&FIXTURE_ERA, ERA_T1, ERA_T4).expect("valid reply");
    assert_close(s.offset.as_secs(), 1.0, "offset");
    assert_close(s.delay.as_secs(), 0.5, "delay");
}

#[test]
fn handles_request_in_2035_and_reply_stamped_in_2036() {
    let t1 = NtpTime::from_unix_nanos(WIDE_T1_UNIX_SECS * 1_000_000_000);
    assert_eq!(t1.to_bits(), WIDE_T1);
    let s = exchange(&FIXTURE_WIDE, WIDE_T1, WIDE_T4).expect("valid reply");
    // 39 days less 4.5 ms. The tolerance scales with the size.
    let want = 3_369_599.995_5;
    assert!(
        (s.offset.as_secs() - want).abs() < 1e-6,
        "{}",
        s.offset.as_secs()
    );
    assert_close(s.delay.as_secs(), 0.029, "delay");
}

#[test]
fn converts_unix_nanos_to_ntp_time() {
    // The Unix epoch is NTP second 2_208_988_800.
    assert_eq!(NtpTime::from_unix_nanos(0).to_bits(), 2_208_988_800 << 32);
    // Half a second is the top fraction bit.
    assert_eq!(
        NtpTime::from_unix_nanos(500_000_000).to_bits(),
        (2_208_988_800 << 32) | 0x8000_0000
    );
    // 2036-02-07T06:28:16Z starts era 1 at zero.
    assert_eq!(
        NtpTime::from_unix_nanos(2_085_978_496_000_000_000).to_bits(),
        0
    );
    // Before 1900 wraps into era -1. One second before is second 0xFFFFFFFF.
    assert_eq!(
        NtpTime::from_unix_nanos(-2_208_988_801_000_000_000).to_bits(),
        0xFFFF_FFFF_0000_0000
    );
    // Extremes do not panic.
    let _ = NtpTime::from_unix_nanos(i128::MAX);
    let _ = NtpTime::from_unix_nanos(i128::MIN);
}

#[test]
fn rejects_leap_alarm() {
    let got = mutated_a(|r| r[0] |= 0xC0);
    assert_eq!(got, Err(QueryFailure::Malformed));
}

#[test]
fn accepts_leap_second_warnings() {
    for li in [1u8, 2] {
        let s = mutated_a(|r| r[0] = (r[0] & 0x3F) | (li << 6)).expect("valid reply");
        assert!(!s.leap_alarm);
        assert!(!s.unsynchronised);
    }
}

#[test]
fn rejects_stratum_16_and_above() {
    for stratum in [16u8, 17, 128, 255] {
        let got = mutated_a(|r| r[1] = stratum);
        assert_eq!(got, Err(QueryFailure::Malformed), "stratum {stratum}");
    }
    let s = mutated_a(|r| r[1] = 15).expect("stratum 15 is valid");
    assert_eq!(s.stratum, 15);
}

#[test]
fn rejects_zero_transmit_or_receive_timestamp() {
    assert_eq!(mutated_a(|r| r[T3].fill(0)), Err(QueryFailure::Malformed));
    assert_eq!(mutated_a(|r| r[T2].fill(0)), Err(QueryFailure::Malformed));
}

#[test]
fn rejects_zero_timestamps_even_at_the_era_boundary() {
    // Near the boundary a zero field is in time order with the rest, so
    // only the explicit zero check catches it. RFC 5905 treats zero as
    // "not set".
    let t1 = 0xFFFF_FFFF_FFFF_FF00;
    let t4 = 0x0000_0000_0000_0200;
    let cases: [(u64, u64); 2] = [(0, 1), (0xFFFF_FFFF_FFFF_FFF0, 0)];
    for (t2, t3) in cases {
        let mut fixture = FIXTURE_A;
        fixture[T2].copy_from_slice(&t2.to_be_bytes());
        fixture[T3].copy_from_slice(&t3.to_be_bytes());
        assert_eq!(
            exchange(&fixture, t1, t4),
            Err(QueryFailure::Malformed),
            "t2 {t2:#x} t3 {t3:#x}"
        );
        // The same shape one unit away from zero is accepted.
        fixture[T2].copy_from_slice(&(t2 | 1).to_be_bytes());
        fixture[T3].copy_from_slice(&(t3 | 2).to_be_bytes());
        assert!(exchange(&fixture, t1, t4).is_ok(), "t2 {t2:#x} t3 {t3:#x}");
    }
}

#[test]
fn rejects_server_transmit_before_receive() {
    // T3 one fraction unit before T2.
    let got = mutated_a(|r| {
        let t2 = u64::from_be_bytes(r[T2].try_into().expect("8 bytes"));
        r[T3].copy_from_slice(&(t2 - 1).to_be_bytes());
    });
    assert_eq!(got, Err(QueryFailure::Malformed));
}

#[test]
fn rejects_reply_received_before_request_sent() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let reply = reply_to(&FIXTURE_A, &request);
    assert_eq!(parse(&reply, &token, T1 - 1), Err(QueryFailure::Malformed));
}

#[test]
fn rejects_negative_delay() {
    // Server claims 50 ms of processing inside a 41 ms round trip.
    let got = mutated_a(|r| {
        let t2 = u64::from_be_bytes(r[T2].try_into().expect("8 bytes"));
        let fifty_ms = 0x0CCC_CCCD;
        r[T3].copy_from_slice(&(t2 + fifty_ms).to_be_bytes());
    });
    assert_eq!(got, Err(QueryFailure::Malformed));
}

#[test]
fn ignores_trailing_extension_or_mac_bytes() {
    // We send no extension fields and hold no key, so nothing after the
    // 48 byte header can be checked. The adapter reads the header only.
    let base = exchange(&FIXTURE_A, T1, T4_A).expect("valid reply");
    let trailers: [&[u8]; 4] = [
        // RFC 7822 extension field: type 0x0104, length 16, 12 bytes value.
        &[
            0x01, 0x04, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ],
        // Legacy MAC shape: 4 byte key id and 16 byte digest.
        &[
            0, 0, 0, 1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA,
        ],
        // Junk that no parser could read.
        &[0xFF, 0xFF, 0xFF],
        &[0; 1000],
    ];
    for trailer in trailers {
        let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
        let mut reply = reply_to(&FIXTURE_A, &request);
        reply.extend_from_slice(trailer);
        let s = parse(&reply, &token, T4_A).expect("trailer ignored");
        assert_eq!(s, base, "trailer of {} bytes", trailer.len());
    }
}

#[test]
fn malformed_packets_all_return_err() {
    type Change = fn(&mut Vec<u8>);
    let table: [(&str, Change); 26] = [
        ("empty", |r| r.clear()),
        ("one byte", |r| r.truncate(1)),
        ("47 bytes", |r| r.truncate(47)),
        ("mode 0 reserved", |r| r[0] &= !0x07),
        ("mode 1 symmetric active", |r| r[0] = (r[0] & !0x07) | 1),
        ("mode 3 client", |r| r[0] = (r[0] & !0x07) | 3),
        ("mode 5 broadcast", |r| r[0] = (r[0] & !0x07) | 5),
        ("mode 7 private", |r| r[0] = (r[0] & !0x07) | 7),
        ("version 0", |r| r[0] &= !0x38),
        ("version 2", |r| r[0] = (r[0] & !0x38) | (2 << 3)),
        ("version 5", |r| r[0] = (r[0] & !0x38) | (5 << 3)),
        ("version 7", |r| r[0] |= 0x38),
        ("leap alarm", |r| r[0] |= 0xC0),
        ("stratum 16", |r| r[1] = 16),
        ("stratum 255", |r| r[1] = 255),
        ("stratum 0 address refid", |r| r[1] = 0),
        ("transmit zero", |r| r[40..48].fill(0)),
        ("receive zero", |r| r[32..40].fill(0)),
        ("origin zero", |r| r[24..32].fill(0)),
        ("origin all ones", |r| r[24..32].fill(0xFF)),
        ("origin low bit", |r| r[31] ^= 1),
        ("transmit before receive", |r| {
            r[40..44].copy_from_slice(&[0xEE, 0x9C, 0xDD, 0x09]);
        }),
        ("mode 6 control", |r| r[0] = (r[0] & !0x07) | 6),
        ("receive min, transmit max", |r| {
            r[32..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
            r[40..48].fill(0xFF);
        }),
        ("all ones header", |r| r.fill(0xFF)),
        ("all zero header", |r| r.fill(0)),
    ];
    for (name, change) in table {
        assert!(mutated_a(change).is_err(), "{name} was accepted");
    }
}

/// `SplitMix64`, so the garbage run is the same on every machine.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

fn assert_sane(s: &Sample) {
    assert!(s.offset.as_secs().is_finite());
    assert!(s.delay.as_secs().is_finite() && s.delay.as_secs() >= 0.0);
    assert!((1..=15).contains(&s.stratum));
    assert!(!s.leap_alarm && !s.unsynchronised);
}

#[test]
fn random_garbage_never_panics_and_needs_the_origin() {
    let mut rng = SplitMix(0x5EED_F00D_7E57);
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let origin = &request[40..48];
    for i in 0..5000 {
        let len = usize::from(rng.byte()) % 120;
        let mut packet: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Every other packet echoes the right origin so checks past the
        // origin gate run too.
        let spliced = i % 2 == 1 && packet.len() >= 32;
        if spliced {
            packet[ORIGIN].copy_from_slice(origin);
        }
        match parse(&packet, &token, T4_A) {
            Ok(s) => {
                assert!(spliced, "accepted without our origin: {packet:02x?}");
                assert_sane(&s);
            }
            Err(QueryFailure::KissOfDeath(_)) => assert!(spliced, "kiss without our origin"),
            Err(_) => {}
        }
    }
}

#[test]
fn single_bit_flips_never_panic_and_origin_flips_fail() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let reply = reply_to(&FIXTURE_A, &request);
    for bit in 0..reply.len() * 8 {
        let mut flipped = reply.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        let got = parse(&flipped, &token, T4_A);
        if ORIGIN.contains(&(bit / 8)) {
            assert_eq!(got, Err(QueryFailure::Malformed), "origin bit {bit}");
        }
        if let Ok(s) = got {
            assert_sane(&s);
        }
    }
}
