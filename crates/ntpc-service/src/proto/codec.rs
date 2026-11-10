//! NTP version 3 and 4 header codec, RFC 5905 figure 8.
//!
//! It only moves bytes. It does not judge them. All checks live in
//! `proto.rs`. Every read goes through `get`, so no input can panic it.

/// Length of the header in bytes.
pub const HEADER_LEN: usize = 48;

/// Mode 3, a client request.
pub const MODE_CLIENT: u8 = 3;
/// Mode 4, a server reply.
pub const MODE_SERVER: u8 = 4;
/// Leap indicator 3, the alarm: the clock is not synchronised.
pub const LEAP_ALARM: u8 = 3;

/// The 48 byte header, one field per wire field, raw values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Byte 0, bits 7 and 6.
    pub leap: u8,
    /// Byte 0, bits 5 to 3.
    pub version: u8,
    /// Byte 0, bits 2 to 0.
    pub mode: u8,
    /// Byte 1.
    pub stratum: u8,
    /// Byte 2, log2 seconds.
    pub poll: i8,
    /// Byte 3, log2 seconds.
    pub precision: i8,
    /// Bytes 4 to 7, unsigned 16.16 seconds.
    pub root_delay: u32,
    /// Bytes 8 to 11, unsigned 16.16 seconds.
    pub root_dispersion: u32,
    /// Bytes 12 to 15. A kiss code at stratum 0.
    pub reference_id: [u8; 4],
    /// Bytes 16 to 23, 32.32 timestamp.
    pub reference_time: u64,
    /// Bytes 24 to 31. The client's transmit time, echoed.
    pub origin_time: u64,
    /// Bytes 32 to 39. Server time when the request arrived (T2).
    pub receive_time: u64,
    /// Bytes 40 to 47. Server time when the reply left (T3).
    pub transmit_time: u64,
}

impl Header {
    /// A version 4 client request. Every field but `transmit` and `poll` is
    /// zero, so the request tells the server nothing about our clock.
    #[must_use]
    pub fn client_request(poll: i8, transmit: u64) -> Self {
        Self {
            leap: 0,
            version: 4,
            mode: MODE_CLIENT,
            stratum: 0,
            poll,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference_time: 0,
            origin_time: 0,
            receive_time: 0,
            transmit_time: transmit,
        }
    }
}

/// Reads the first 48 bytes. `None` if there are fewer.
///
/// Bytes after the header are not read. We send no extension fields and
/// hold no key, so an unauthenticated client has nothing to check them
/// against and ignores them (RFC 7822).
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Header> {
    let first = *bytes.first()?;
    if bytes.len() < HEADER_LEN {
        return None;
    }
    Some(Header {
        leap: first >> 6,
        version: (first >> 3) & 0x07,
        mode: first & 0x07,
        stratum: *bytes.get(1)?,
        poll: i8::from_be_bytes([*bytes.get(2)?]),
        precision: i8::from_be_bytes([*bytes.get(3)?]),
        root_delay: u32::from_be_bytes(four(bytes, 4)?),
        root_dispersion: u32::from_be_bytes(four(bytes, 8)?),
        reference_id: four(bytes, 12)?,
        reference_time: u64::from_be_bytes(eight(bytes, 16)?),
        origin_time: u64::from_be_bytes(eight(bytes, 24)?),
        receive_time: u64::from_be_bytes(eight(bytes, 32)?),
        transmit_time: u64::from_be_bytes(eight(bytes, 40)?),
    })
}

/// Writes the 48 byte header. Fields wider than their wire bits are
/// masked, so `leap`, `version` and `mode` cannot spill into each other.
#[must_use]
pub fn encode(h: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    // Every range below is a constant inside the 48 byte array.
    out[0] = ((h.leap & 0x03) << 6) | ((h.version & 0x07) << 3) | (h.mode & 0x07);
    out[1] = h.stratum;
    out[2..3].copy_from_slice(&h.poll.to_be_bytes());
    out[3..4].copy_from_slice(&h.precision.to_be_bytes());
    out[4..8].copy_from_slice(&h.root_delay.to_be_bytes());
    out[8..12].copy_from_slice(&h.root_dispersion.to_be_bytes());
    out[12..16].copy_from_slice(&h.reference_id);
    out[16..24].copy_from_slice(&h.reference_time.to_be_bytes());
    out[24..32].copy_from_slice(&h.origin_time.to_be_bytes());
    out[32..40].copy_from_slice(&h.receive_time.to_be_bytes());
    out[40..48].copy_from_slice(&h.transmit_time.to_be_bytes());
    out
}

/// Four bytes starting at `at`, or `None` if the input is too short.
fn four(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    bytes.get(at..at.checked_add(4)?)?.try_into().ok()
}

/// Eight bytes starting at `at`, or `None` if the input is too short.
fn eight(bytes: &[u8], at: usize) -> Option<[u8; 8]> {
    bytes.get(at..at.checked_add(8)?)?.try_into().ok()
}
