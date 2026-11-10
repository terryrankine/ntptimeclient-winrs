//! NTP protocol adapter. Builds client requests and checks server replies.
//!
//! [`codec`] moves the 48 header bytes. Every check that decides whether a
//! reply is trusted is here.
//!
//! Rules:
//! - The transmit timestamp of a request is random, not our clock. A blind
//!   spoofer cannot guess it, and the server learns nothing about our time.
//! - A reply counts only if it comes from the address and port the request
//!   went to and echoes that random value exactly. Kiss-o'-Death is honoured
//!   only after both checks, so a spoofer cannot silence a source.
//! - Only the header is read. An unauthenticated client has nothing to check
//!   extension fields or a MAC against, so it ignores anything after byte 48.
//! - Absolute times become integer nanosecond deltas before any `f64`.
//!   NTP subtraction wraps, so a reply across the 2036 era boundary works.

pub mod codec;

use std::net::SocketAddr;

use ntpc_core::{Delay, KodCode, Mono, Offset, QueryFailure, Sample, SourceId};

use codec::{Header, LEAP_ALARM, MODE_SERVER};

/// Highest stratum a usable server can report. 16 means unsynchronised.
const MAX_STRATUM: u8 = 15;

/// Poll exponent sent in the request, 2^6 = 64 s, the engine's shortest.
const REQUEST_POLL: i8 = 6;

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Seconds from 1900-01-01 (NTP era 0) to 1970-01-01 (Unix epoch).
const UNIX_TO_NTP_SECS: i128 = 2_208_988_800;

/// An NTP timestamp: seconds since the start of the current NTP era in the
/// high 32 bits and the binary fraction in the low 32 bits.
///
/// The era number is not stored. Differences between two values are taken
/// modulo 2^32 s, which is right while they are within 68 years.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtpTime(u64);

impl NtpTime {
    /// Wraps a raw 32.32 timestamp.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// The raw 32.32 timestamp.
    #[must_use]
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// Converts nanoseconds since the Unix epoch. Any value is accepted.
    /// The result wraps into the matching NTP era.
    #[must_use]
    pub fn from_unix_nanos(nanos: i128) -> Self {
        let secs = nanos.div_euclid(NANOS_PER_SEC);
        let sub = nanos.rem_euclid(NANOS_PER_SEC);
        // `secs` is at most about 1.7e29, far from the i128 limit.
        let era_secs = (secs + UNIX_TO_NTP_SECS).rem_euclid(1 << 32);
        // `sub` is below 1e9, so the shifted value fits and the quotient is
        // below 2^32.
        let fraction = (sub << 32) / NANOS_PER_SEC;
        let bits = (era_secs << 32) | fraction;
        Self(u64::try_from(bits).unwrap_or(0))
    }
}

/// What a reply must match. Built by [`build_request`].
///
/// `Debug` prints no field. The origin is a secret until the reply comes
/// back, and a log line holding it would help a spoofer.
pub struct RequestToken {
    /// The random transmit timestamp we sent. `None` if the OS gave no
    /// random bytes. Then no reply can match.
    origin: Option<u64>,
    /// Where the request went.
    dest: SocketAddr,
    /// Our real clock when the request left (T1).
    sent: NtpTime,
}

impl std::fmt::Debug for RequestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestToken").finish_non_exhaustive()
    }
}

/// Builds a 48 byte NTP version 4 client request for `dest`.
///
/// `now` is our clock as the request leaves. It goes into the token, not the
/// packet.
#[must_use]
pub fn build_request(now: NtpTime, dest: SocketAddr) -> (Vec<u8>, RequestToken) {
    // `getrandom` reads the OS CSPRNG (`ProcessPrng` on Windows).
    let mut nonce = [0u8; 8];
    let origin = getrandom::fill(&mut nonce)
        .ok()
        .map(|()| u64::from_be_bytes(nonce));
    // On failure the request still goes out with a zero transmit time. The
    // token holds no origin, so even a reply that echoes zero is refused.
    let header = Header::client_request(REQUEST_POLL, origin.unwrap_or(0));
    (
        codec::encode(&header).to_vec(),
        RequestToken {
            origin,
            dest,
            sent: now,
        },
    )
}

/// Checks a reply and turns it into a sample.
///
/// `received` is our clock when the reply arrived (T4). `at` is the
/// monotonic time of arrival.
///
/// # Errors
///
/// - [`QueryFailure::KissOfDeath`] for a stratum 0 reply that passes the
///   address and origin checks and carries a kiss code.
/// - [`QueryFailure::Malformed`] for everything else that is not a usable
///   server reply to this request.
pub fn parse_response(
    bytes: &[u8],
    from: SocketAddr,
    token: &RequestToken,
    received: NtpTime,
    source: SourceId,
    at: Mono,
) -> Result<Sample, QueryFailure> {
    const BAD: QueryFailure = QueryFailure::Malformed;

    if !same_endpoint(from, token.dest) {
        return Err(BAD);
    }
    let h = codec::decode(bytes).ok_or(BAD)?;
    // We send version 4. Old servers answer with 3. Version 5 has another
    // layout and other kiss rules.
    if !matches!(h.version, 3 | 4) {
        return Err(BAD);
    }
    if token.origin != Some(h.origin_time) {
        return Err(BAD);
    }
    if h.mode != MODE_SERVER {
        return Err(BAD);
    }
    // A kiss usually carries LI 3, so it is read before the leap check.
    if h.stratum == 0 {
        return Err(kiss(h.reference_id));
    }
    // Rejected here, not passed on as flags. The engine filter keeps the
    // lowest-delay sample per source before selection drops flagged ones,
    // so one flagged sample could hide that source's good samples.
    if h.stratum > MAX_STRATUM || h.leap == LEAP_ALARM {
        return Err(BAD);
    }

    let t1 = token.sent.to_bits();
    let t2 = h.receive_time;
    let t3 = h.transmit_time;
    let t4 = received.to_bits();
    // Zero means the server never set the field.
    if t2 == 0 || t3 == 0 {
        return Err(BAD);
    }

    let round_trip = diff_nanos(t4, t1);
    let in_server = diff_nanos(t3, t2);
    let delay = round_trip - in_server;
    // Each step backwards is impossible on an honest path. A negative delay
    // would also win the lowest-delay filter.
    if round_trip < 0 || in_server < 0 || delay < 0 {
        return Err(BAD);
    }
    let offset = i128::midpoint(diff_nanos(t2, t1), diff_nanos(t3, t4));

    Ok(Sample {
        source,
        offset: Offset::from_secs(secs(offset)),
        delay: Delay::from_secs(secs(delay)),
        stratum: h.stratum,
        // LI 3 is rejected above, so a sample never carries either flag.
        unsynchronised: false,
        leap_alarm: false,
        at,
    })
}

/// Maps a stratum 0 reply. RFC 5905 puts the kiss code in the refid as four
/// ASCII characters. Anything else at stratum 0 is not a kiss.
fn kiss(code: [u8; 4]) -> QueryFailure {
    match &code {
        b"DENY" => QueryFailure::KissOfDeath(KodCode::Deny),
        b"RSTR" => QueryFailure::KissOfDeath(KodCode::Rstr),
        b"RATE" => QueryFailure::KissOfDeath(KodCode::Rate),
        c if c
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) =>
        {
            QueryFailure::KissOfDeath(KodCode::Other)
        }
        _ => QueryFailure::Malformed,
    }
}

/// Same host and port. A dual-stack socket may report an IPv4 peer in its
/// mapped IPv6 form, so both sides are compared in canonical form.
fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

/// `later - earlier` in nanoseconds, floored. The subtraction wraps and is
/// read as signed, so the result is the nearest one within +-2^31 s. This is
/// what makes era rollover work.
fn diff_nanos(later: u64, earlier: u64) -> i128 {
    let units = i128::from(later.wrapping_sub(earlier).cast_signed());
    // At most 2^63 * 1e9, well inside i128. The shift floors.
    (units * NANOS_PER_SEC) >> 32
}

#[expect(
    clippy::cast_precision_loss,
    reason = "a delta of at most 2^31 s in nanoseconds keeps sub-microsecond precision"
)]
fn secs(nanos: i128) -> f64 {
    nanos as f64 / 1e9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_nanos_keeps_sign_and_fraction() {
        let base = 0x0000_0010_0000_0000;
        let later = 0x0000_0010_8000_0000;
        assert_eq!(diff_nanos(later, base), 500_000_000);
        assert_eq!(diff_nanos(base, later), -500_000_000);
    }

    #[test]
    fn diff_nanos_wraps_across_the_era() {
        // Era 0 last second plus 0.5 to era 1 second 0 plus 0.5: one second.
        assert_eq!(
            diff_nanos(0x0000_0000_8000_0000, 0xFFFF_FFFF_8000_0000),
            1_000_000_000
        );
    }

    #[test]
    fn diff_nanos_extremes_do_not_panic() {
        for (a, b) in [(0, u64::MAX), (u64::MAX, 0), (1 << 63, 0), (0, 1 << 63)] {
            let _ = diff_nanos(a, b);
        }
    }

    #[test]
    fn kiss_maps_named_codes_and_shape() {
        assert_eq!(kiss(*b"DENY"), QueryFailure::KissOfDeath(KodCode::Deny));
        assert_eq!(kiss(*b"X9ZZ"), QueryFailure::KissOfDeath(KodCode::Other));
        assert_eq!(kiss(*b"deny"), QueryFailure::Malformed);
    }
}
