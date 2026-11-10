//! Sends one NTP query and waits for its reply. Blocking, one socket per
//! query.
//!
//! Ruling R90: no async runtime. A query blocks its own worker thread for at
//! most the timeout. The host runs each query on a worker, so the engine
//! loop never waits on the network.
//!
//! Rules for [`UdpTransport::query`]:
//! - One fresh socket per query, on an ephemeral port the OS picks. A blind
//!   spoofer must guess the port as well as the 64-bit random origin.
//! - The socket is not connected. A connected socket would let the OS drop
//!   datagrams from other addresses before we see them. We want to see and
//!   count them, and [`parse_response`] already checks the sender address and
//!   port.
//! - The receive time is read right after `recv_from` returns, before any
//!   parsing, so parse cost does not show up as delay.
//! - Ruling R55: a datagram that fails a check (malformed, wrong sender,
//!   wrong origin, truncated) is discarded and the wait goes on until the
//!   deadline. Only a good reply, a kiss-of-death or the deadline ends the
//!   query. Otherwise one spoofed datagram could cancel every real query.
//! - At most [`MAX_DISCARDS`] datagrams are discarded per query. The next
//!   bad one ends the query as [`QueryFailure::Malformed`]. That bounds the
//!   work a flood can cause. The real reply may then be lost, and the engine
//!   sees one failed query.
//! - The query returns at the first good reply or kiss-of-death, so the
//!   request token and its socket are dropped then. A replay of that reply
//!   reaches a closed port, and a later query has a new origin (Task 9 M4).
//! - Nothing a network peer sends can panic this code. Every read is bounds
//!   checked by the codec and every error is mapped.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ntpc_core::{Mono, QueryFailure, Sample, SourceId};

use crate::logging::{Level, Logger};
use crate::proto::{NtpTime, build_request, parse_response};

/// Most datagrams discarded in one query before it ends as malformed.
/// An honest server sends one reply. Eight leaves room for strays and
/// duplicates on a bad path.
pub const MAX_DISCARDS: u32 = 8;

/// Receive buffer. A plain reply is 48 bytes. Extension fields can make it
/// longer. Only the header is read, but a larger datagram must still fit,
/// because Windows reports a datagram longer than the buffer as an error.
const RECV_BUF: usize = 2048;

/// Shortest socket read timeout. A zero timeout is an error in `std`.
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

/// Byte range of the transmit timestamp in a request.
const TRANSMIT_FIELD: std::ops::Range<usize> = 40..48;

/// Time as the host sees it. Separate from [`ntpc_core::Clock`] because a
/// query worker reads time on its own thread, while the clock is owned by
/// the engine loop and needs `&mut` to change.
pub trait TimeSource: Send + Sync {
    /// Monotonic time. Counts awake time only on the real platform source.
    fn mono(&self) -> Mono;
    /// Wall time in nanoseconds since the Unix epoch, UTC.
    fn wall_ns(&self) -> i128;
}

/// `std` time. For tests and console development only. `Instant` may count
/// sleep, which breaks the engine's awake-time contract, so the service
/// uses the platform source (Task 14c).
#[derive(Debug, Clone, Copy)]
pub struct StdTimeSource {
    start: Instant,
}

impl StdTimeSource {
    /// Monotonic time starts at zero now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for StdTimeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for StdTimeSource {
    fn mono(&self) -> Mono {
        let nanos = u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Mono::from_nanos(nanos)
    }

    fn wall_ns(&self) -> i128 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i128::try_from(d.as_nanos()).unwrap_or(i128::MAX),
            Err(e) => -i128::try_from(e.duration().as_nanos()).unwrap_or(i128::MAX),
        }
    }
}

/// Thread priority for the timing path. The Windows version raises the
/// worker thread's priority (Task 14c). The default does nothing.
pub trait ThreadTuning: Send + Sync {
    /// Called on the worker thread before the request is built.
    fn raise_priority(&self) {}
}

/// Leaves the thread priority alone.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTuning;

impl ThreadTuning for NoTuning {}

/// Counters a transport keeps across queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    /// Requests sent without a random origin, because the OS gave no random
    /// bytes (R57). No reply can match them.
    pub nonce_failures: u64,
    /// Datagrams that failed a check and were discarded (R55).
    pub discarded: u64,
    /// ICMP errors reported on a socket. Ignored like a bad datagram,
    /// because ICMP can be spoofed too.
    pub resets: u64,
}

/// Sends one query and waits for one answer.
pub trait Transport: Send + Sync {
    /// Queries `dest` for `source`. Blocks for at most about `timeout`.
    ///
    /// # Errors
    /// The [`QueryFailure`] the engine should see.
    fn query(
        &self,
        source: SourceId,
        dest: SocketAddr,
        timeout: Duration,
    ) -> Result<Sample, QueryFailure>;

    /// Counters for `status.json`.
    fn stats(&self) -> TransportStats {
        TransportStats::default()
    }
}

#[derive(Debug, Default)]
struct Counters {
    nonce_failures: AtomicU64,
    discarded: AtomicU64,
    resets: AtomicU64,
}

/// NTP over `std::net::UdpSocket`.
pub struct UdpTransport {
    time: Arc<dyn TimeSource>,
    tuning: Arc<dyn ThreadTuning>,
    logger: Arc<dyn Logger>,
    bind_v4: Ipv4Addr,
    bind_v6: Ipv6Addr,
    counters: Counters,
}

impl std::fmt::Debug for UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpTransport")
            .field("bind_v4", &self.bind_v4)
            .field("bind_v6", &self.bind_v6)
            .finish_non_exhaustive()
    }
}

impl UdpTransport {
    /// A transport that binds the unspecified address of the destination's
    /// family.
    #[must_use]
    pub fn new(
        time: Arc<dyn TimeSource>,
        tuning: Arc<dyn ThreadTuning>,
        logger: Arc<dyn Logger>,
    ) -> Self {
        Self {
            time,
            tuning,
            logger,
            bind_v4: Ipv4Addr::UNSPECIFIED,
            bind_v6: Ipv6Addr::UNSPECIFIED,
            counters: Counters::default(),
        }
    }

    /// Binds these local addresses instead. Tests bind loopback, so the
    /// firewall never sees a wildcard socket.
    #[must_use]
    pub fn bind_to(mut self, v4: Ipv4Addr, v6: Ipv6Addr) -> Self {
        self.bind_v4 = v4;
        self.bind_v6 = v6;
        self
    }

    fn socket_for(&self, dest: SocketAddr) -> io::Result<UdpSocket> {
        let local = match dest {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(self.bind_v4), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(self.bind_v6), 0),
        };
        UdpSocket::bind(local)
    }

    fn discard(&self, discards: &mut u32) -> Option<QueryFailure> {
        self.counters.discarded.fetch_add(1, Ordering::Relaxed);
        *discards += 1;
        (*discards > MAX_DISCARDS).then_some(QueryFailure::Malformed)
    }
}

impl Transport for UdpTransport {
    fn query(
        &self,
        source: SourceId,
        dest: SocketAddr,
        timeout: Duration,
    ) -> Result<Sample, QueryFailure> {
        self.tuning.raise_priority();
        let deadline = Instant::now() + timeout;
        let socket = self
            .socket_for(dest)
            .map_err(|_| QueryFailure::Unreachable)?;
        let (request, token) = build_request(NtpTime::from_unix_nanos(self.time.wall_ns()), dest);
        // R57: proto keeps the origin private. A failed RNG sends a zero
        // transmit field, which a real nonce is with chance 2^-64.
        if request
            .get(TRANSMIT_FIELD)
            .is_some_and(|f| f.iter().all(|&b| b == 0))
        {
            let n = self.counters.nonce_failures.fetch_add(1, Ordering::Relaxed) + 1;
            self.logger.log(
                Level::Error,
                "nonce_missing",
                &format!(
                    "the OS gave no random bytes for an NTP request. No reply can match it. \
                     {n} such requests so far"
                ),
            );
        }
        socket
            .send_to(&request, dest)
            .map_err(|_| QueryFailure::Unreachable)?;

        let mut buf = [0u8; RECV_BUF];
        let mut discards = 0u32;
        let mut reset_seen = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(if reset_seen {
                    QueryFailure::Unreachable
                } else {
                    QueryFailure::Timeout
                });
            }
            if socket
                .set_read_timeout(Some(left.max(MIN_READ_TIMEOUT)))
                .is_err()
            {
                return Err(QueryFailure::Unreachable);
            }
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    // T4 first. Everything after this is not network delay.
                    let received = NtpTime::from_unix_nanos(self.time.wall_ns());
                    let at = self.time.mono();
                    let bytes = buf.get(..n).unwrap_or(&[]);
                    match parse_response(bytes, from, &token, received, source, at) {
                        Ok(sample) => return Ok(sample),
                        Err(QueryFailure::KissOfDeath(code)) => {
                            return Err(QueryFailure::KissOfDeath(code));
                        }
                        Err(_) => {
                            if let Some(fail) = self.discard(&mut discards) {
                                return Err(fail);
                            }
                        }
                    }
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {}
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused => {
                        // ICMP port unreachable on Windows. Spoofable, so it
                        // does not end the wait. It counts against the
                        // discard cap, so a socket that keeps reporting it
                        // cannot spin this loop until the deadline.
                        self.counters.resets.fetch_add(1, Ordering::Relaxed);
                        reset_seen = true;
                        discards += 1;
                        if discards > MAX_DISCARDS {
                            return Err(QueryFailure::Unreachable);
                        }
                    }
                    // A datagram longer than the buffer, or any other
                    // per-datagram error.
                    _ => {
                        if let Some(fail) = self.discard(&mut discards) {
                            return Err(fail);
                        }
                    }
                },
            }
        }
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            nonce_failures: self.counters.nonce_failures.load(Ordering::Relaxed),
            discarded: self.counters.discarded.load(Ordering::Relaxed),
            resets: self.counters.resets.load(Ordering::Relaxed),
        }
    }
}
