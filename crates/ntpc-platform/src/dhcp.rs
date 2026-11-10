//! DHCP-supplied NTP servers, IPv4 option 42 only.
//!
//! The pure parts build everywhere so the fuzz job on Linux sees them. The
//! OS calls live in `win32::dhcp`. Method, rules and sources:
//! `docs/architecture.md`, "Platform: DHCP option 42".

use std::net::Ipv4Addr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

mod per_adapter;

pub use per_adapter::{
    AdapterKey, AdapterLease, LeaseOptions, merged_servers, read_lease_servers_per_adapter,
};

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

/// Why DHCP servers could not be read or watched. The text holds Win32
/// error codes only: no address, adapter name or GUID.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DhcpError {
    /// Not Windows. Version one reads DHCP on Windows only.
    #[error("reading DHCP servers is not supported on this platform")]
    Unsupported,
    /// `GetAdaptersAddresses` failed.
    #[error("listing network adapters failed (os error {0})")]
    AdapterList(i32),
    /// `DhcpCApiInitialize` failed.
    #[error("starting the DHCP client API failed (os error {0})")]
    ApiStart(i32),
    /// Every leased adapter's request failed. The code is the first one.
    #[error("every DHCP option request failed (os error {0})")]
    Request(i32),
    /// The address-change subscription failed.
    #[error("watching for address changes failed (os error {0})")]
    Watch(i32),
}

#[cfg(windows)]
fn os_code(e: &std::io::Error) -> i32 {
    // -1 marks an error that carried no OS code, such as a refused buffer.
    e.raw_os_error().unwrap_or(-1)
}

/// Reads the NTP servers (option 42) from every leased IPv4 adapter.
///
/// BLOCKING and may touch the NETWORK: when option 42 is not in the DHCP
/// client cache, Windows sends a DHCPINFORM per adapter and a call may take
/// up to 2 minutes. Run it on its own thread, at start, after a
/// [`DhcpWatcher`] change and on a long timer. Never in a tight loop.
///
/// Adapters: up, DHCP enabled, leased, not loopback or tunnel, ordered by
/// metric then interface index. Servers are joined in that order,
/// deduplicated and capped at [`MAX_SERVERS`]. `Ok(empty)` when no adapter
/// has a lease or no lease holds option 42.
///
/// # Errors
/// [`DhcpError::Unsupported`] off Windows. On Windows an error only when
/// the adapter list or API start fails, or every adapter request fails.
///
/// Since Task 14c this is [`read_lease_servers_per_adapter`] with nothing
/// skipped, merged by [`merged_servers`]. Same adapters, order, caps and
/// errors as before.
#[cfg(windows)]
pub fn read_lease_servers() -> Result<Vec<Ipv4Addr>, DhcpError> {
    read_lease_servers_per_adapter(&std::collections::HashSet::new())
        .map(|leases| merged_servers(&leases))
}

/// Off Windows there is no DHCP reader in version one.
///
/// # Errors
/// Always [`DhcpError::Unsupported`].
#[cfg(not(windows))]
pub fn read_lease_servers() -> Result<Vec<Ipv4Addr>, DhcpError> {
    Err(DhcpError::Unsupported)
}

/// Signals when an IPv4 address changes: a lease gained, lost or moved.
///
/// This is also the R66 network-change signal that resets the resolver
/// backoff. It fires on any IPv4 unicast address change, not only a lease
/// change. On [`WaitOutcome::Changed`] the host calls
/// [`read_lease_servers`] and feeds the result to a [`LeaseTracker`].
/// A renewal that changes only option 42 may not fire, so the host also
/// re-reads on a long timer.
#[derive(Debug)]
pub struct DhcpWatcher {
    signal: Arc<Signal>,
    // Declared after `signal` and dropped after `Drop::drop` has woken the
    // waiters, so a deregistration never races a waiter.
    #[cfg(windows)]
    _registration: crate::win32::dhcp::AddrChangeRegistration,
}

impl DhcpWatcher {
    /// Subscribes to IPv4 address changes. Read only.
    ///
    /// # Errors
    /// [`DhcpError::Watch`] if the OS refuses, [`DhcpError::Unsupported`]
    /// off Windows.
    pub fn new() -> Result<Self, DhcpError> {
        let signal = Arc::new(Signal::default());
        #[cfg(windows)]
        {
            let registration =
                crate::win32::dhcp::AddrChangeRegistration::register(Arc::clone(&signal))
                    .map_err(|e| DhcpError::Watch(os_code(&e)))?;
            Ok(Self {
                signal,
                _registration: registration,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = signal;
            Err(DhcpError::Unsupported)
        }
    }

    /// Blocks until an address change, a cancel or `timeout`. Changes that
    /// came before the call are not lost. Several count as one.
    #[must_use]
    pub fn wait(&self, timeout: Duration) -> WaitOutcome {
        self.signal.wait(timeout)
    }

    /// A handle that cancels this watcher from another thread.
    #[must_use]
    pub fn canceller(&self) -> WatchCanceller {
        WatchCanceller(Arc::clone(&self.signal))
    }
}

impl Drop for DhcpWatcher {
    fn drop(&mut self) {
        // Wake any waiter on a canceller's thread first. The registration
        // field drops after this and deregisters.
        self.signal.cancel();
    }
}

/// Whether the DHCP server list changed since the last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseChange {
    /// Same set of servers as before.
    Unchanged,
    /// The first list, or servers were added or removed.
    Changed,
}

/// Decides "changed" by comparing the previous and the new server list.
///
/// The first list counts as a change. The same set in another order is not
/// a change: the resolver keys sources by address and the reader's order is
/// already deterministic. On a read error the host does not call `update`,
/// so the last good list stays: an error is not a lost lease.
#[derive(Debug, Default, Clone)]
pub struct LeaseTracker {
    last: Option<Vec<Ipv4Addr>>,
}

impl LeaseTracker {
    /// A tracker that has seen nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `servers` and says whether they differ from the last list.
    pub fn update(&mut self, servers: &[Ipv4Addr]) -> LeaseChange {
        let sorted = |l: &[Ipv4Addr]| {
            let mut v = l.to_vec();
            v.sort_unstable();
            v.dedup();
            v
        };
        let change = match &self.last {
            Some(prev) if sorted(prev) == sorted(servers) => LeaseChange::Unchanged,
            _ => LeaseChange::Changed,
        };
        self.last = Some(servers.to_vec());
        change
    }

    /// The last list recorded, in the reader's order.
    #[must_use]
    pub fn current(&self) -> Option<&[Ipv4Addr]> {
        self.last.as_deref()
    }
}

/// What ended a [`DhcpWatcher::wait`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// An IPv4 address changed. Several changes since the last wait count
    /// as one. Read the servers again.
    Changed,
    /// The timeout passed with no change.
    TimedOut,
    /// The watcher was cancelled or is being dropped.
    Cancelled,
}

#[derive(Debug, Default)]
struct SignalState {
    pending: bool,
    cancelled: bool,
}

/// The wake-up the OS callback sets and `wait` takes. Split from the OS
/// subscription so it is testable without a network.
#[derive(Debug, Default)]
pub(crate) struct Signal {
    state: Mutex<SignalState>,
    cv: Condvar,
}

impl Signal {
    fn lock(&self) -> MutexGuard<'_, SignalState> {
        // A poisoned lock still holds two plain flags. Carrying on is safe,
        // and the OS callback must never panic.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks a change. Called from the OS callback thread: it never blocks
    /// beyond the short lock and never panics.
    pub(crate) fn notify(&self) {
        self.lock().pending = true;
        self.cv.notify_all();
    }

    /// Wakes every waiter for good.
    pub(crate) fn cancel(&self) {
        self.lock().cancelled = true;
        self.cv.notify_all();
    }

    /// Blocks until a change, a cancel or `timeout`. A cancel wins over a
    /// pending change. A change is taken, so the next wait blocks again.
    pub(crate) fn wait(&self, timeout: Duration) -> WaitOutcome {
        let guard = self.lock();
        // `wait_timeout_while` measures elapsed time itself, so spurious
        // wake-ups and a huge timeout are both handled.
        let (mut s, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |s| !s.pending && !s.cancelled)
            .unwrap_or_else(PoisonError::into_inner);
        if s.cancelled {
            WaitOutcome::Cancelled
        } else if s.pending {
            s.pending = false;
            WaitOutcome::Changed
        } else {
            WaitOutcome::TimedOut
        }
    }
}

/// Cancels a [`DhcpWatcher`] from another thread. A blocked or later
/// `wait` returns [`WaitOutcome::Cancelled`].
#[derive(Debug, Clone)]
pub struct WatchCanceller(Arc<Signal>);

impl WatchCanceller {
    /// Wakes the watcher's waiters for good.
    pub fn cancel(&self) {
        self.0.cancel();
    }
}

// ---- Helpers for the OS buffers. Pure, so they are tested everywhere. ----
// Only the Windows reader calls them, hence the dead-code allowance.

/// `IF_TYPE_SOFTWARE_LOOPBACK` (Learn, `IP_ADAPTER_ADDRESSES_LH`).
pub(crate) const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// `IF_TYPE_TUNNEL` (same page).
pub(crate) const IF_TYPE_TUNNEL: u32 = 131;
/// `DhcpRequestParams` refuses an adapter name of 256 characters or more.
pub(crate) const MAX_ADAPTER_NAME: usize = 255;

/// The fields the reader needs from one adapter record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct AdapterInfo {
    /// Adapter GUID string as a NUL-terminated wide string.
    pub name: Vec<u16>,
    pub if_index: u32,
    pub metric: u32,
    /// Operational status is up.
    pub up: bool,
    pub dhcp_enabled: bool,
    pub if_type: u32,
    /// A non-zero `Dhcpv4Server`: the adapter holds a lease.
    pub has_lease: bool,
    /// The `Dhcpv4Server` address, the lease server. Half of the
    /// per-adapter negative cache key (R82).
    pub lease_server: Option<Ipv4Addr>,
}

/// Keeps adapters that are up, DHCP enabled, leased, and not loopback or
/// tunnel. Sorts by metric then interface index so the preferred route
/// comes first and the order is the same every time. A repeated name is
/// dropped so one adapter is never asked twice.
#[must_use]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn select_adapters(list: Vec<AdapterInfo>) -> Vec<AdapterInfo> {
    let mut kept: Vec<AdapterInfo> = list
        .into_iter()
        .filter(|a| {
            a.up && a.dhcp_enabled
                && a.has_lease
                && a.if_type != IF_TYPE_SOFTWARE_LOOPBACK
                && a.if_type != IF_TYPE_TUNNEL
        })
        .collect();
    kept.sort_by(|x, y| (x.metric, x.if_index, &x.name).cmp(&(y.metric, y.if_index, &y.name)));
    let mut seen: Vec<Vec<u16>> = Vec::new();
    kept.retain(|a| {
        if seen.contains(&a.name) {
            false
        } else {
            seen.push(a.name.clone());
            true
        }
    });
    kept
}

/// Offset of `[ptr, ptr + len)` inside the buffer `[start, start + buf_len)`.
/// `None` when the range is null, wraps or leaves the buffer. Every pointer
/// the OS hands back is checked this way before it is read.
#[must_use]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn offset_in(start: usize, buf_len: usize, ptr: usize, len: usize) -> Option<usize> {
    if ptr == 0 || ptr < start {
        return None;
    }
    let off = ptr - start;
    let end = off.checked_add(len)?;
    (end <= buf_len).then_some(off)
}

/// The bytes of a NUL-terminated string that starts at `offset`. `None`
/// when no NUL comes before the end of the buffer.
#[must_use]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn c_str_at(buf: &[u8], offset: usize) -> Option<&[u8]> {
    let tail = buf.get(offset..)?;
    let n = tail.iter().position(|&b| b == 0)?;
    Some(&tail[..n])
}

/// Widens an adapter name for `DhcpRequestParams`. Only a GUID string is
/// accepted: hex digits, braces and dashes, 1 to 255 characters. Anything
/// else is refused, so a corrupt name can never reach the API.
#[must_use]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn adapter_name_wide(name: &[u8]) -> Option<Vec<u16>> {
    if name.is_empty() || name.len() > MAX_ADAPTER_NAME {
        return None;
    }
    if !name
        .iter()
        .all(|&b| b.is_ascii_hexdigit() || b == b'{' || b == b'}' || b == b'-')
    {
        return None;
    }
    let mut w: Vec<u16> = name.iter().map(|&b| u16::from(b)).collect();
    w.push(0);
    Some(w)
}

/// The address of a `SOCKADDR_IN` (family `AF_INET` = 2, little endian),
/// `None` for another family, a short buffer or the zero address. A
/// non-zero `Dhcpv4Server` is how a lease shows.
#[must_use]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn sockaddr_in_addr(sa: &[u8]) -> Option<Ipv4Addr> {
    // SOCKADDR_IN: family u16, port u16, address 4 bytes, zero padding 8.
    if sa.len() < 16 || u16::from_le_bytes([sa[0], sa[1]]) != 2 {
        return None;
    }
    let a = Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
    (!a.is_unspecified()).then_some(a)
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

#[cfg(test)]
mod buffer_tests {
    use super::*;

    fn adapter(name: &str, metric: u32, if_index: u32) -> AdapterInfo {
        AdapterInfo {
            name: adapter_name_wide(name.as_bytes()).expect("test name is a GUID"),
            if_index,
            metric,
            up: true,
            dhcp_enabled: true,
            if_type: 6,
            has_lease: true,
            lease_server: Some(Ipv4Addr::new(192, 0, 2, 67)),
        }
    }

    #[test]
    fn select_keeps_only_up_leased_dhcp_adapters() {
        let ok = adapter("{AAAA}", 10, 1);
        let mut down = adapter("{BBBB}", 10, 2);
        down.up = false;
        let mut static_ip = adapter("{CCCC}", 10, 3);
        static_ip.dhcp_enabled = false;
        let mut no_lease = adapter("{DDDD}", 10, 4);
        no_lease.has_lease = false;
        let mut lo = adapter("{EEEE}", 10, 5);
        lo.if_type = IF_TYPE_SOFTWARE_LOOPBACK;
        let mut tun = adapter("{FFFF}", 10, 6);
        tun.if_type = IF_TYPE_TUNNEL;
        let got = select_adapters(vec![down, static_ip, no_lease, lo, tun, ok.clone()]);
        assert_eq!(got, vec![ok]);
    }

    #[test]
    fn select_orders_by_metric_then_index_and_drops_repeats() {
        let a = adapter("{0001}", 50, 9);
        let b = adapter("{0002}", 5, 20);
        let c = adapter("{0003}", 5, 3);
        let again = adapter("{0003}", 70, 30);
        let got = select_adapters(vec![a.clone(), again, b.clone(), c.clone()]);
        assert_eq!(got, vec![c, b, a]);
    }

    #[test]
    fn select_of_nothing_is_nothing() {
        assert_eq!(select_adapters(Vec::new()), Vec::new());
    }

    #[test]
    fn offset_in_accepts_ranges_inside_only() {
        assert_eq!(offset_in(1000, 100, 1000, 100), Some(0));
        assert_eq!(offset_in(1000, 100, 1040, 10), Some(40));
        assert_eq!(offset_in(1000, 100, 1100, 0), Some(100));
        assert_eq!(offset_in(1000, 100, 1095, 6), None);
        assert_eq!(offset_in(1000, 100, 999, 1), None);
        assert_eq!(offset_in(1000, 100, 0, 0), None);
        assert_eq!(offset_in(1000, 100, 1001, usize::MAX), None);
        assert_eq!(offset_in(usize::MAX - 4, 4, usize::MAX - 1, 8), None);
    }

    #[test]
    fn c_str_at_needs_a_nul_inside_the_buffer() {
        let buf = b"ab\0cd\0ef";
        assert_eq!(c_str_at(buf, 0), Some(&b"ab"[..]));
        assert_eq!(c_str_at(buf, 3), Some(&b"cd"[..]));
        assert_eq!(c_str_at(buf, 2), Some(&b""[..]));
        assert_eq!(c_str_at(buf, 6), None, "no terminating NUL");
        assert_eq!(c_str_at(buf, 8), None);
        assert_eq!(c_str_at(buf, 100), None);
        assert_eq!(c_str_at(&[], 0), None);
    }

    #[test]
    fn adapter_name_accepts_a_guid_and_terminates_it() {
        let name = b"{01234567-89AB-cdef-0123-456789ABCDEF}";
        let w = adapter_name_wide(name).expect("valid");
        assert_eq!(w.len(), name.len() + 1);
        assert_eq!(w.last(), Some(&0));
        assert!(
            w[..name.len()]
                .iter()
                .zip(name)
                .all(|(a, b)| *a == u16::from(*b))
        );
    }

    #[test]
    fn adapter_name_refuses_anything_else() {
        assert_eq!(adapter_name_wide(b""), None);
        assert_eq!(adapter_name_wide(b"{0123}\0x"), None, "interior NUL");
        assert_eq!(adapter_name_wide(br"..\evil"), None);
        assert_eq!(adapter_name_wide(b"{01 23}"), None);
        assert_eq!(adapter_name_wide("{0é}".as_bytes()), None, "not ASCII");
        assert_eq!(
            adapter_name_wide(&[0xED, 0xA0, 0x80]),
            None,
            "lone surrogate bytes"
        );
        assert!(adapter_name_wide(&[b'a'; MAX_ADAPTER_NAME]).is_some());
        assert_eq!(adapter_name_wide(&[b'a'; MAX_ADAPTER_NAME + 1]), None);
        assert_eq!(adapter_name_wide(&vec![b'a'; 1 << 20]), None, "huge");
    }

    #[test]
    fn sockaddr_in_addr_reads_family_and_address() {
        let mut sa = [0u8; 16];
        sa[0] = 2;
        sa[4..8].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(sockaddr_in_addr(&sa), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(sockaddr_in_addr(&sa[..15]), None, "truncated");
        let mut zero = sa;
        zero[4..8].copy_from_slice(&[0; 4]);
        assert_eq!(sockaddr_in_addr(&zero), None);
        let mut v6 = sa;
        v6[0] = 23;
        assert_eq!(sockaddr_in_addr(&v6), None);
        assert_eq!(sockaddr_in_addr(&[]), None);
    }

    #[test]
    fn helpers_never_panic_on_random_input() {
        let mut s = 0xdead_beef_cafe_f00du64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..5_000 {
            let len = usize::try_from(next() % 64).unwrap_or(0);
            let buf: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            let off = usize::try_from(next() % 80).unwrap_or(0);
            if let Some(s) = c_str_at(&buf, off) {
                assert!(!s.contains(&0));
            }
            let _ = adapter_name_wide(&buf);
            let _ = sockaddr_in_addr(&buf);
            let p = usize::try_from(next()).unwrap_or(0);
            let n = usize::try_from(next() % 4096).unwrap_or(0);
            if let Some(o) = offset_in(4096, 1024, p, n) {
                assert!(o + n <= 1024);
            }
        }
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;
    use std::thread;
    use std::time::Instant;

    const A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const C: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 200);

    #[test]
    fn first_list_is_a_change() {
        let mut t = LeaseTracker::new();
        assert_eq!(t.current(), None);
        assert_eq!(t.update(&[A]), LeaseChange::Changed);
        assert_eq!(t.current(), Some(&[A][..]));
    }

    #[test]
    fn first_empty_list_is_a_change_too() {
        let mut t = LeaseTracker::new();
        assert_eq!(t.update(&[]), LeaseChange::Changed);
        assert_eq!(t.update(&[]), LeaseChange::Unchanged);
    }

    #[test]
    fn same_list_is_no_change() {
        let mut t = LeaseTracker::new();
        t.update(&[A, B]);
        assert_eq!(t.update(&[A, B]), LeaseChange::Unchanged);
    }

    #[test]
    fn reorder_is_no_change_but_the_new_order_is_kept() {
        let mut t = LeaseTracker::new();
        t.update(&[A, B]);
        assert_eq!(t.update(&[B, A]), LeaseChange::Unchanged);
        assert_eq!(t.current(), Some(&[B, A][..]));
    }

    #[test]
    fn add_remove_and_all_removed_are_changes() {
        let mut t = LeaseTracker::new();
        t.update(&[A, B]);
        assert_eq!(t.update(&[A, B, C]), LeaseChange::Changed, "add");
        assert_eq!(t.update(&[A, C]), LeaseChange::Changed, "remove");
        assert_eq!(t.update(&[B, C]), LeaseChange::Changed, "swap one");
        assert_eq!(t.update(&[]), LeaseChange::Changed, "all removed");
        assert_eq!(t.current(), Some(&[][..]));
        assert_eq!(t.update(&[A]), LeaseChange::Changed, "lease back");
    }

    #[test]
    fn wait_times_out_with_no_change() {
        let s = Signal::default();
        assert_eq!(s.wait(Duration::from_millis(20)), WaitOutcome::TimedOut);
    }

    #[test]
    fn notify_before_wait_is_not_lost_and_bursts_coalesce() {
        let s = Signal::default();
        s.notify();
        s.notify();
        assert_eq!(s.wait(Duration::from_secs(5)), WaitOutcome::Changed);
        assert_eq!(s.wait(Duration::from_millis(10)), WaitOutcome::TimedOut);
    }

    #[test]
    fn notify_from_another_thread_wakes_a_waiter() {
        let s = Arc::new(Signal::default());
        let s2 = Arc::clone(&s);
        let h = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            s2.notify();
        });
        let start = Instant::now();
        assert_eq!(s.wait(Duration::from_secs(10)), WaitOutcome::Changed);
        assert!(start.elapsed() < Duration::from_secs(5));
        h.join().expect("notifier thread");
    }

    #[test]
    fn cancel_wakes_a_blocked_waiter_and_sticks() {
        let s = Arc::new(Signal::default());
        let c = WatchCanceller(Arc::clone(&s));
        let h = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            c.cancel();
        });
        assert_eq!(s.wait(Duration::from_secs(10)), WaitOutcome::Cancelled);
        h.join().expect("cancel thread");
        s.notify();
        assert_eq!(s.wait(Duration::from_secs(1)), WaitOutcome::Cancelled);
    }

    #[test]
    fn huge_timeout_does_not_overflow() {
        let s = Signal::default();
        s.notify();
        assert_eq!(s.wait(Duration::MAX), WaitOutcome::Changed);
    }
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn error_text_holds_no_address() {
        let all = [
            DhcpError::Unsupported,
            DhcpError::AdapterList(87),
            DhcpError::ApiStart(5),
            DhcpError::Request(1460),
            DhcpError::Watch(-1),
        ];
        for e in all {
            let t = e.to_string();
            assert_ne!(t, "");
            assert!(!t.contains('{'), "no GUID: {t}");
            // An IPv4 address needs three dots. A sentence has none here.
            assert!(t.matches('.').count() < 3, "no address: {t}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn watcher_waits_and_drops_without_hanging() {
        // Read only: a subscription, no packet. Asserts no network state.
        let w = DhcpWatcher::new().expect("subscribe");
        let start = Instant::now();
        let got = w.wait(Duration::from_millis(50));
        // A real address change during the test is allowed. A cancel is not.
        assert_ne!(got, WaitOutcome::Cancelled);
        let c = w.canceller();
        drop(w);
        c.cancel();
        assert!(start.elapsed() < Duration::from_secs(10), "drop hung");
    }

    #[cfg(windows)]
    #[test]
    fn canceller_wakes_a_blocked_watcher() {
        let w = DhcpWatcher::new().expect("subscribe");
        let c = w.canceller();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            c.cancel();
        });
        // Changes may arrive first. Loop until the cancel lands.
        let start = Instant::now();
        while w.wait(Duration::from_secs(10)) != WaitOutcome::Cancelled {
            assert!(start.elapsed() < Duration::from_secs(10), "cancel lost");
        }
        h.join().expect("cancel thread");
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_everything_is_unsupported() {
        assert_eq!(read_lease_servers(), Err(DhcpError::Unsupported));
        assert!(matches!(DhcpWatcher::new(), Err(DhcpError::Unsupported)));
    }

    /// Ignored: it may send a DHCPINFORM on every leased adapter and block
    /// up to 2 minutes each. Run it only on a throwaway VM. It checks that
    /// the call returns and prints nothing, never which servers it found.
    #[cfg(windows)]
    #[test]
    #[ignore = "may send a DHCPINFORM: network action, throwaway VM only"]
    fn live_read_returns_without_panic() {
        match read_lease_servers() {
            Ok(list) => assert!(list.len() <= MAX_SERVERS),
            Err(e) => assert_ne!(e.to_string(), ""),
        }
    }
}
