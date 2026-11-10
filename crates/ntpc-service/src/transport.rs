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
//! - Rulings R55 and R97: a datagram that fails a check (malformed, wrong
//!   sender, wrong origin, truncated, too long) is discarded, and so is an
//!   ICMP error report. The wait goes on until the deadline. Only a good
//!   reply, a kiss-of-death or the deadline ends the query. No count of bad
//!   datagrams ends it, or a blind spoofer who knows the port could cancel
//!   every real query. A flood costs CPU for at most the timeout, and each
//!   loop turn waits in the socket for a datagram, so the work is bounded
//!   by what arrives.
//! - One guard against a hot loop: [`MAX_IO_ERRORS_IN_ROW`] socket errors in
//!   a row that are not about one datagram end the query as
//!   [`QueryFailure::Unreachable`]. A broken socket fails at once on every
//!   call, so without the guard the loop would spin until the deadline.
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

/// Socket errors in a row, not tied to one datagram, that end a query as
/// unreachable. A datagram, an ICMP report or a read timeout in between
/// resets the count. Only a broken socket gets there.
pub const MAX_IO_ERRORS_IN_ROW: u32 = 16;

/// Windows `WSAEMSGSIZE`: one datagram was longer than the buffer.
const WSAEMSGSIZE: i32 = 10040;

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

    fn check_nonce(&self, request: &[u8]) {
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
    }

    /// One request and the wait for its answer, on any socket.
    fn exchange<S: Socket>(
        &self,
        socket: &S,
        source: SourceId,
        dest: SocketAddr,
        deadline: Instant,
    ) -> Result<Sample, QueryFailure> {
        // T1 is read here. `build_request` draws the nonce after it (proto.rs
        // takes T1 as an argument and is not ours to change), so T1 is early
        // by one CSPRNG call and an encode, about a microsecond. That adds
        // about half of it to the offset.
        let (request, token) = build_request(NtpTime::from_unix_nanos(self.time.wall_ns()), dest);
        self.check_nonce(&request);
        socket
            .send(&request, dest)
            .map_err(|_| QueryFailure::Unreachable)?;

        let mut buf = [0u8; RECV_BUF];
        let mut errors_in_row = 0u32;
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
            if socket.set_timeout(left.max(MIN_READ_TIMEOUT)).is_err() {
                return Err(QueryFailure::Unreachable);
            }
            match socket.recv(&mut buf) {
                Ok((n, from)) => {
                    // T4 first. Everything after this is not network delay.
                    let received = NtpTime::from_unix_nanos(self.time.wall_ns());
                    let at = self.time.mono();
                    errors_in_row = 0;
                    let bytes = buf.get(..n).unwrap_or(&[]);
                    match parse_response(bytes, from, &token, received, source, at) {
                        Ok(sample) => return Ok(sample),
                        Err(QueryFailure::KissOfDeath(code)) => {
                            return Err(QueryFailure::KissOfDeath(code));
                        }
                        Err(_) => {
                            self.counters.discarded.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => errors_in_row = 0,
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused => {
                        // ICMP port unreachable on Windows. Spoofable, so it
                        // never ends the wait. One arrives per ICMP packet.
                        self.counters.resets.fetch_add(1, Ordering::Relaxed);
                        reset_seen = true;
                        errors_in_row = 0;
                    }
                    _ if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                        // One datagram too long for the buffer.
                        self.counters.discarded.fetch_add(1, Ordering::Relaxed);
                        errors_in_row = 0;
                    }
                    _ => {
                        errors_in_row += 1;
                        if errors_in_row >= MAX_IO_ERRORS_IN_ROW {
                            return Err(QueryFailure::Unreachable);
                        }
                    }
                },
            }
        }
    }
}

/// The three socket calls a query makes. A trait so tests can feed errors
/// that loopback cannot produce, such as a run of ICMP reports.
trait Socket {
    fn send(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize>;
    fn set_timeout(&self, d: Duration) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

impl Socket for UdpSocket {
    fn send(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.send_to(buf, dest)
    }

    fn set_timeout(&self, d: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(d))
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf)
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
        self.exchange(&socket, source, dest, deadline)
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            nonce_failures: self.counters.nonce_failures.load(Ordering::Relaxed),
            discarded: self.counters.discarded.load(Ordering::Relaxed),
            resets: self.counters.resets.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LineLogger, MemorySink};
    use crate::proto::codec::{self, Header, MODE_SERVER};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 123);

    enum Step {
        Reset,
        Broken,
        Good,
    }

    /// Plays a script of receive results. `Good` answers the request.
    struct Script {
        steps: RefCell<VecDeque<Step>>,
        request: RefCell<Vec<u8>>,
        calls: RefCell<u32>,
    }

    impl Socket for Script {
        fn send(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
            *self.request.borrow_mut() = buf.to_vec();
            Ok(buf.len())
        }

        fn set_timeout(&self, _d: Duration) -> io::Result<()> {
            Ok(())
        }

        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            *self.calls.borrow_mut() += 1;
            match self.steps.borrow_mut().pop_front() {
                Some(Step::Reset) => Err(io::ErrorKind::ConnectionReset.into()),
                Some(Step::Broken) => Err(io::Error::other("socket broken")),
                Some(Step::Good) => {
                    let req = codec::decode(&self.request.borrow()).expect("request");
                    let now = NtpTime::from_unix_nanos(StdTimeSource::new().wall_ns()).to_bits();
                    let reply = codec::encode(&Header {
                        leap: 0,
                        version: 4,
                        mode: MODE_SERVER,
                        stratum: 2,
                        poll: 6,
                        precision: -20,
                        root_delay: 0,
                        root_dispersion: 0,
                        reference_id: *b"TEST",
                        reference_time: now,
                        origin_time: req.transmit_time,
                        receive_time: now,
                        transmit_time: now,
                    });
                    buf[..48].copy_from_slice(&reply);
                    Ok((48, SERVER))
                }
                // Nothing more: the socket read times out.
                None => Err(io::ErrorKind::TimedOut.into()),
            }
        }
    }

    fn run(steps: Vec<Step>) -> (Result<Sample, QueryFailure>, u32, TransportStats) {
        let time = Arc::new(StdTimeSource::new());
        let log = Arc::new(LineLogger::new(Box::new(MemorySink::new()), time.clone()));
        let t = UdpTransport::new(time, Arc::new(NoTuning), log);
        let s = Script {
            steps: RefCell::new(steps.into()),
            request: RefCell::new(Vec::new()),
            calls: RefCell::new(0),
        };
        let deadline = Instant::now() + Duration::from_millis(100);
        let r = t.exchange(&s, SourceId::new(1), SERVER, deadline);
        let calls = *s.calls.borrow();
        (r, calls, t.stats())
    }

    #[test]
    fn fifty_icmp_resets_then_a_good_reply_is_ok() {
        let mut steps: Vec<Step> = (0..50).map(|_| Step::Reset).collect();
        steps.push(Step::Good);
        let (r, _, stats) = run(steps);
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(stats.resets, 50);
    }

    #[test]
    fn a_run_of_socket_errors_ends_as_unreachable() {
        let steps: Vec<Step> = (0..100).map(|_| Step::Broken).collect();
        let (r, calls, _) = run(steps);
        assert_eq!(r, Err(QueryFailure::Unreachable));
        assert_eq!(calls, MAX_IO_ERRORS_IN_ROW);
    }

    #[test]
    fn socket_errors_split_by_resets_do_not_end_the_query() {
        let mut steps = Vec::new();
        for _ in 0..5 {
            steps.extend((1..MAX_IO_ERRORS_IN_ROW).map(|_| Step::Broken));
            steps.push(Step::Reset);
        }
        steps.push(Step::Good);
        let (r, _, _) = run(steps);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn resets_alone_end_as_unreachable_at_the_deadline() {
        assert_eq!(run(vec![Step::Reset]).0, Err(QueryFailure::Unreachable));
        assert_eq!(run(vec![]).0, Err(QueryFailure::Timeout));
    }
}
