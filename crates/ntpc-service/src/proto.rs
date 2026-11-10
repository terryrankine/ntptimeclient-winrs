//! NTP protocol adapter. Builds client requests and checks server replies.
//!
//! The `ntp-proto` parser decodes the 48 byte header and draws the random
//! origin. Every check that decides whether a reply is trusted is here.
//!
//! Rules:
//! - The transmit timestamp of a request is random, not our clock. A blind
//!   spoofer cannot guess it, and the server learns nothing about our time.
//! - A reply counts only if it comes from the address and port the request
//!   went to and echoes that random value exactly. Kiss-o'-Death is honoured
//!   only after both checks, so a spoofer cannot silence a source.
//! - Only the header is read. We send no extension fields and hold no key,
//!   so anything after byte 48 cannot be checked and is ignored.
//! - Absolute times become integer nanosecond deltas before any `f64`.
//!   NTP subtraction wraps, so a reply across the 2036 era boundary works.

use std::io::Cursor;
use std::net::SocketAddr;

use ntp_proto::{
    NoCipher, NtpAssociationMode, NtpDuration, NtpLeapIndicator, NtpPacket, NtpTimestamp,
    PollInterval,
};
use ntpc_core::{Delay, KodCode, Mono, Offset, QueryFailure, Sample, SourceId};

/// Header length in bytes for versions 3 and 4.
const HEADER_LEN: usize = 48;

/// Highest stratum a usable server can report. 16 means unsynchronised.
const MAX_STRATUM: u8 = 15;

/// Poll exponent sent in the request, 2^6 = 64 s, the engine's shortest.
const REQUEST_POLL: u8 = 6;

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

    fn to_timestamp(self) -> NtpTimestamp {
        let secs = u32::try_from(self.0 >> 32).unwrap_or(u32::MAX);
        let fraction = self.0 & 0xFFFF_FFFF;
        // Below 1e9 because `fraction` is below 2^32.
        let nanos = u32::try_from((fraction * 1_000_000_000) >> 32).unwrap_or(0);
        NtpTimestamp::from_seconds_nanos_since_ntp_era(secs, nanos)
    }
}

/// What a reply must match. Built by [`build_request`].
///
/// `Debug` prints no field. The origin is a secret until the reply comes
/// back, and a log line holding it would help a spoofer.
pub struct RequestToken {
    /// The random transmit timestamp we sent, as wire bytes.
    origin: [u8; 8],
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
    // `ntp-proto` fills the transmit timestamp from `rand::thread_rng`,
    // a ChaCha CSPRNG seeded by the OS. Its own identifier type is not
    // nameable outside the crate, so the token keeps the wire bytes.
    let (packet, _) = NtpPacket::poll_message(PollInterval::from_byte(REQUEST_POLL));
    let mut buf = [0u8; HEADER_LEN];
    let written = packet
        .serialize(&mut Cursor::new(&mut buf[..]), &NoCipher, None)
        .is_ok();
    // A v4 poll message with no extension fields is exactly 48 bytes, so
    // the write cannot fail. Should a future `ntp-proto` change that, an
    // all-zero origin makes every reply fail the origin check.
    let origin = if written {
        transmit_bytes(&buf)
    } else {
        buf = [0; HEADER_LEN];
        [0; 8]
    };
    (
        buf.to_vec(),
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
    let header = bytes.get(..HEADER_LEN).ok_or(BAD)?;
    let first = header.first().copied().ok_or(BAD)?;
    // Version 5 has another layout and other kiss rules. We send v4, so a v5
    // answer is wrong. Rejecting it here keeps that parser path unused.
    if !matches!((first >> 3) & 0x07, 3 | 4) {
        return Err(BAD);
    }
    if header.get(24..32) != Some(&token.origin[..]) {
        return Err(BAD);
    }
    let (packet, _) = NtpPacket::deserialize(header, &NoCipher).map_err(|_| BAD)?;
    if packet.mode() != NtpAssociationMode::Server {
        return Err(BAD);
    }
    // A kiss usually carries LI 3, so it is read before the leap check.
    if packet.stratum() == 0 {
        return Err(kiss(&packet, header));
    }
    if packet.stratum() > MAX_STRATUM || packet.leap() == NtpLeapIndicator::Unsynchronized {
        return Err(BAD);
    }

    let t1 = token.sent.to_timestamp();
    let t2 = packet.receive_timestamp();
    let t3 = packet.transmit_timestamp();
    let t4 = received.to_timestamp();
    // Zero means the server never set the field.
    if t2 == NtpTimestamp::default() || t3 == NtpTimestamp::default() {
        return Err(BAD);
    }

    let round_trip = nanos(t4 - t1);
    let in_server = nanos(t3 - t2);
    let delay = round_trip - in_server;
    // Each step backwards is impossible on an honest path. A negative delay
    // would also win the lowest-delay filter.
    if round_trip < 0 || in_server < 0 || delay < 0 {
        return Err(BAD);
    }
    let offset = i128::midpoint(nanos(t2 - t1), nanos(t3 - t4));

    Ok(Sample {
        source,
        offset: Offset::from_secs(secs(offset)),
        delay: Delay::from_secs(secs(delay)),
        stratum: packet.stratum(),
        // LI 3 is rejected above, so a sample never carries either flag.
        unsynchronised: false,
        leap_alarm: false,
        at,
    })
}

/// Maps a stratum 0 reply. RFC 5905 puts the kiss code in the refid as four
/// ASCII characters. Anything else at stratum 0 is not a kiss.
fn kiss(packet: &NtpPacket<'_>, header: &[u8]) -> QueryFailure {
    // The interval only matters for v5 kiss rules. v5 is rejected earlier.
    let poll = PollInterval::from_byte(REQUEST_POLL);
    if packet.is_kiss_deny() {
        QueryFailure::KissOfDeath(KodCode::Deny)
    } else if packet.is_kiss_rstr() {
        QueryFailure::KissOfDeath(KodCode::Rstr)
    } else if packet.is_kiss_rate(poll) {
        QueryFailure::KissOfDeath(KodCode::Rate)
    } else if header.get(12..16).is_some_and(|c| {
        c.iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    }) {
        // `ntp-proto` cannot name other codes. The shape check is ours.
        QueryFailure::KissOfDeath(KodCode::Other)
    } else {
        QueryFailure::Malformed
    }
}

/// Same host and port. A dual-stack socket may report an IPv4 peer in its
/// mapped IPv6 form, so both sides are compared in canonical form.
fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

fn transmit_bytes(header: &[u8; HEADER_LEN]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&header[40..48]);
    out
}

/// A wrapped NTP difference as signed nanoseconds.
fn nanos(d: NtpDuration) -> i128 {
    let (s, n) = d.as_seconds_nanos();
    i128::from(s) * NANOS_PER_SEC + i128::from(n)
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
    fn nanos_keeps_sign_and_fraction() {
        let base = NtpTime::from_bits(0x0000_0010_0000_0000).to_timestamp();
        let later = NtpTime::from_bits(0x0000_0010_8000_0000).to_timestamp();
        assert_eq!(nanos(later - base), 500_000_000);
        assert_eq!(nanos(base - later), -500_000_000);
    }

    #[test]
    fn to_timestamp_extremes_do_not_panic() {
        for bits in [0, 1, u64::MAX, 0xFFFF_FFFF, 0xFFFF_FFFF_0000_0000] {
            let _ = NtpTime::from_bits(bits).to_timestamp();
        }
    }
}
