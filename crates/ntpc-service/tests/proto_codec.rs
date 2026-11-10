//! Header codec tests.
//!
//! There is no external parser to compare against, so this file holds a
//! second, deliberately naive decoder. It builds each field one byte at a
//! time with shifts and masks. It shares no code with `codec::decode`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ntpc_core::{Mono, QueryFailure, SourceId};
use ntpc_service::proto::codec::{self, HEADER_LEN, Header};
use ntpc_service::proto::{NtpTime, build_request, parse_response};

/// TEST-NET-1 address, reserved for documentation (RFC 5737).
const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 123);

/// 2026-11-10T00:00:00Z.
const T1: u64 = 0xEE9C_DD00_0000_0000;
/// T1 + 0.041 s.
const T4: u64 = 0xEE9C_DD00_0A7E_F9DB;

/// Every byte holds a different value, so a field read from the wrong
/// offset gives a visibly wrong number. Byte 0 is `0b10_011_101`: LI 2,
/// version 3, mode 5. Bytes 1 to 47 count up from 0x81, so poll and
/// precision have the top bit set and a sign mistake shows too.
fn distinct_bytes() -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[0] = 0b1001_1101;
    for (i, slot) in b.iter_mut().enumerate().skip(1) {
        *slot = 0x80 + u8::try_from(i).expect("below 48");
    }
    b
}

#[test]
fn decodes_every_field_from_its_offset() {
    let h = codec::decode(&distinct_bytes()).expect("48 bytes");
    assert_eq!(h.leap, 2);
    assert_eq!(h.version, 3);
    assert_eq!(h.mode, 5);
    assert_eq!(h.stratum, 0x81);
    assert_eq!(h.poll, -126, "0x82 as i8");
    assert_eq!(h.precision, -125, "0x83 as i8");
    assert_eq!(h.root_delay, 0x8485_8687);
    assert_eq!(h.root_dispersion, 0x8889_8A8B);
    assert_eq!(h.reference_id, [0x8C, 0x8D, 0x8E, 0x8F]);
    assert_eq!(h.reference_time, 0x9091_9293_9495_9697);
    assert_eq!(h.origin_time, 0x9899_9A9B_9C9D_9E9F);
    assert_eq!(h.receive_time, 0xA0A1_A2A3_A4A5_A6A7);
    assert_eq!(h.transmit_time, 0xA8A9_AAAB_ACAD_AEAF);
}

#[test]
fn encode_writes_every_field_to_its_offset() {
    let bytes = distinct_bytes();
    let h = codec::decode(&bytes).expect("48 bytes");
    assert_eq!(codec::encode(&h), bytes);
}

#[test]
fn encode_masks_bit_fields() {
    let mut h = Header::client_request(6, 1);
    h.leap = 0xFF;
    h.version = 0xFF;
    h.mode = 0xFF;
    assert_eq!(codec::encode(&h)[0], 0xFF);
    h.leap = 0x04;
    h.version = 0x08;
    h.mode = 0x08;
    assert_eq!(codec::encode(&h)[0], 0x00, "overflow bits must drop");
}

#[test]
fn request_round_trips() {
    for transmit in [1, 0x0123_4567_89AB_CDEF, u64::MAX] {
        let h = Header::client_request(6, transmit);
        let bytes = codec::encode(&h);
        assert_eq!(codec::decode(&bytes), Some(h));
        assert_eq!(bytes[0], 0x23, "LI 0, VN 4, mode 3");
        assert_eq!(&bytes[40..48], &transmit.to_be_bytes());
    }
    let (request, _) = build_request(NtpTime::from_bits(T1), SERVER);
    let h = codec::decode(&request).expect("48 bytes");
    assert_eq!((h.leap, h.version, h.mode, h.poll), (0, 4, 3, 6));
    assert_eq!(Header::client_request(6, h.transmit_time), h);
}

#[test]
fn truncated_input_decodes_to_none() {
    let bytes = distinct_bytes();
    for len in 0..HEADER_LEN {
        assert_eq!(codec::decode(&bytes[..len]), None, "length {len}");
    }
    assert!(codec::decode(&bytes).is_some());
    let mut longer = bytes.to_vec();
    longer.extend_from_slice(&[0xEE; 100]);
    assert_eq!(
        codec::decode(&longer),
        codec::decode(&bytes),
        "trailer ignored"
    );
}

/// A valid stratum 2 reply to `request`, server 10 s ahead. Same times as
/// fixture A in `proto_fixtures.rs`.
fn valid_reply(request: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; HEADER_LEN];
    r[0] = 0x24; // LI 0, VN 4, mode 4
    r[1] = 2; // stratum
    r[2] = 6; // poll
    r[12..16].copy_from_slice(&[0xC0, 0x00, 0x02, 0x01]); // refid
    r[24..32].copy_from_slice(&request[40..48]); // origin echoes our nonce
    r[32..40].copy_from_slice(&0xEE9C_DD0A_051E_B852_u64.to_be_bytes()); // T1 + 10.020
    r[40..48].copy_from_slice(&0xEE9C_DD0A_0560_4189_u64.to_be_bytes()); // T1 + 10.021
    r
}

#[test]
fn every_leap_version_mode_combination() {
    let (request, token) = build_request(NtpTime::from_bits(T1), SERVER);
    let base = valid_reply(&request);
    let mut accepted = 0;
    for leap in 0u8..4 {
        for version in 0u8..8 {
            for mode in 0u8..8 {
                let mut r = base.clone();
                r[0] = (leap << 6) | (version << 3) | mode;
                let got = parse_response(
                    &r,
                    SERVER,
                    &token,
                    NtpTime::from_bits(T4),
                    SourceId::new(1),
                    Mono::from_nanos(0),
                );
                // RFC 5905: a server reply is mode 4. We accept version 3 and
                // 4. LI 3 means the server is not synchronised.
                let want_ok = leap != 3 && matches!(version, 3 | 4) && mode == 4;
                if want_ok {
                    accepted += 1;
                    assert!(got.is_ok(), "LI {leap} VN {version} mode {mode}: {got:?}");
                } else {
                    assert_eq!(
                        got,
                        Err(QueryFailure::Malformed),
                        "LI {leap} VN {version} mode {mode}"
                    );
                }
            }
        }
    }
    assert_eq!(accepted, 6, "3 leap values times 2 versions");
}

/// Big-endian value of `n` bytes from `from`, built one byte at a time.
fn naive_be(b: &[u8], from: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for k in 0..n {
        v = (v << 8) | u64::from(b[from + k]);
    }
    v
}

/// Two's complement by hand, not by `i8::from_be_bytes`.
fn naive_i8(byte: u8) -> i8 {
    let wide = if byte >= 0x80 {
        i16::from(byte) - 256
    } else {
        i16::from(byte)
    };
    i8::try_from(wide).expect("in range")
}

fn naive_decode(b: &[u8]) -> Option<Header> {
    if b.len() < 48 {
        return None;
    }
    Some(Header {
        leap: (b[0] & 0b1100_0000) >> 6,
        version: (b[0] & 0b0011_1000) >> 3,
        mode: b[0] & 0b0000_0111,
        stratum: b[1],
        poll: naive_i8(b[2]),
        precision: naive_i8(b[3]),
        root_delay: u32::try_from(naive_be(b, 4, 4)).expect("4 bytes"),
        root_dispersion: u32::try_from(naive_be(b, 8, 4)).expect("4 bytes"),
        reference_id: [b[12], b[13], b[14], b[15]],
        reference_time: naive_be(b, 16, 8),
        origin_time: naive_be(b, 24, 8),
        receive_time: naive_be(b, 32, 8),
        transmit_time: naive_be(b, 40, 8),
    })
}

/// `SplitMix64`, so the corpus is the same on every machine.
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

#[test]
fn codec_agrees_with_naive_decoder_on_garbage() {
    let mut rng = SplitMix(0xC0DE_C0DE_0000_0048);
    for _ in 0..10_000 {
        let len = usize::from(rng.byte()) % 120;
        let packet: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let got = codec::decode(&packet);
        assert_eq!(got, naive_decode(&packet), "{packet:02x?}");
        if let Some(h) = got {
            assert_eq!(&codec::encode(&h)[..], &packet[..HEADER_LEN]);
        }
    }
    // Edge patterns the random run may miss.
    for fill in [0x00, 0xFF, 0x80, 0x7F] {
        let packet = [fill; HEADER_LEN];
        assert_eq!(
            codec::decode(&packet),
            naive_decode(&packet),
            "fill {fill:#x}"
        );
    }
}
