//! Feeds arbitrary bytes to `parse_response`.
//!
//! Each input is parsed twice. Once as sent, which must never be accepted
//! because it cannot hold our random origin. Once with our origin written
//! into bytes 24 to 31, so the checks past the origin gate run too.

#![no_main]

use std::net::SocketAddr;

use libfuzzer_sys::fuzz_target;
use ntpc_core::{Mono, QueryFailure, SourceId};
use ntpc_service::proto::{NtpTime, build_request, parse_response};

/// 2026-11-10T00:00:00Z as an NTP timestamp.
const T1: u64 = 0xEE9C_DD00_0000_0000;
/// T1 plus about 41 ms.
const T4: u64 = 0xEE9C_DD00_0A7E_F9DB;

fuzz_target!(|data: &[u8]| {
    let server = SocketAddr::from(([192, 0, 2, 10], 123));
    let (request, token) = build_request(NtpTime::from_bits(T1), server);
    let parse = |bytes: &[u8]| {
        parse_response(
            bytes,
            server,
            &token,
            NtpTime::from_bits(T4),
            SourceId::new(1),
            Mono::from_nanos(0),
        )
    };

    let raw = parse(data);
    // A 2^-64 chance per input that random bytes hit the origin.
    assert!(
        matches!(raw, Err(QueryFailure::Malformed)),
        "accepted without our origin: {raw:?}"
    );

    if let (Some(origin), true) = (request.get(40..48), data.len() >= 32) {
        let mut spliced = data.to_vec();
        if let Some(slot) = spliced.get_mut(24..32) {
            slot.copy_from_slice(origin);
        }
        if let Ok(s) = parse(&spliced) {
            assert!(s.offset.as_secs().is_finite());
            assert!(s.delay.as_secs().is_finite() && s.delay.as_secs() >= 0.0);
            assert!((1..=15).contains(&s.stratum));
        }
    }
});
