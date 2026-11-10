//! `GetAdaptersAddresses` and bounds-checked walks over the lists it
//! writes. Shared by `win32::dhcp` (IPv4 adapters with a lease) and
//! `crate::net` (own unicast addresses).
//!
//! Every pointer the OS returns is checked to lie wholly inside the buffer
//! we passed, and to be aligned, before a node is read. A walk stops at a
//! node it has seen already, so a cyclic `Next` cannot loop, and at a cap,
//! so a long list stays cheap.

use std::collections::BTreeSet;
use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::net::IpAddr;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use super::error_from_code;
use crate::dhcp::offset_in;
use crate::net::parse_sockaddr;

/// Learn suggests a 15 KB first buffer for `GetAdaptersAddresses`.
const BUF_START: usize = 16 * 1024;
/// Refuse to grow the buffer past this. A real list is far smaller.
const BUF_MAX: usize = 1 << 20;
/// The required size may grow between calls (Learn). Retry a few times.
const TRIES: usize = 4;
/// Stop a walk after this many nodes, on any list.
pub(crate) const MAX_NODES: usize = 1024;
/// Stop collecting raw addresses after this many. `crate::net` caps the
/// result lower after removing duplicates.
const MAX_RAW_ADDRESSES: usize = 4096;

/// The flags both callers use: unicast only, no names the OS must look up.
pub(crate) const FLAGS: u32 = GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_SKIP_DNS_SERVER
    | GAA_FLAG_SKIP_FRIENDLY_NAME;

/// A list the OS wrote. Kept as u64 words for the 8-byte alignment the
/// structs need.
pub(crate) struct AdapterBuffer(Vec<u64>);

impl AdapterBuffer {
    /// The buffer as bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        as_bytes(&self.0)
    }
}

/// A u64 slice viewed as bytes.
pub(crate) fn as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: same allocation, 8 times the length, and u8 has no alignment
    // or validity rules. The view borrows `words`.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8) }
}

/// Calls `GetAdaptersAddresses(family, flags)`. Read only, no packet.
/// `Ok(None)` when the OS has no adapter of that family.
///
/// # Errors
/// The OS error, or `ERROR_BUFFER_OVERFLOW` if the buffer would pass 1 MiB.
pub(crate) fn fetch(family: u16, flags: u32) -> io::Result<Option<AdapterBuffer>> {
    let mut want = BUF_START;
    for _ in 0..TRIES {
        let mut buf = vec![0u64; want.div_ceil(8)];
        let bytes_len = buf.len() * 8;
        let mut size =
            u32::try_from(bytes_len).map_err(|_| error_from_code(ERROR_BUFFER_OVERFLOW))?;
        // SAFETY: `buf` is a live, zeroed, 8-aligned allocation of `size`
        // bytes. The reserved pointer must be null (Learn). `size` is a live
        // u32 the call updates.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(family),
                flags,
                ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &raw mut size,
            )
        };
        match rc {
            NO_ERROR => return Ok(Some(AdapterBuffer(buf))),
            ERROR_NO_DATA => return Ok(None),
            ERROR_BUFFER_OVERFLOW => {
                let need = usize::try_from(size).unwrap_or(usize::MAX);
                if need > BUF_MAX {
                    return Err(error_from_code(ERROR_BUFFER_OVERFLOW));
                }
                want = need.max(want + 1);
            }
            other => return Err(error_from_code(other)),
        }
    }
    Err(error_from_code(ERROR_BUFFER_OVERFLOW))
}

/// A list node type that may be copied out of an OS buffer.
///
/// # Safety
/// Every bit pattern must be a valid value: the type holds only integers,
/// raw pointers, arrays and unions of those. No reference, `bool`, enum
/// or `NonNull`.
pub(crate) unsafe trait PlainNode {}

// SAFETY: windows-sys declares it as `repr(C)` integers, raw pointers, u8
// arrays, a GUID and unions of u32 pairs and u64. Any bits are valid.
unsafe impl PlainNode for IP_ADAPTER_ADDRESSES_LH {}
// SAFETY: as above: a u32 pair or u64 union, a raw pointer, a
// `SOCKET_ADDRESS` (raw pointer and i32) and integer fields.
unsafe impl PlainNode for IP_ADAPTER_UNICAST_ADDRESS_LH {}

/// Copies out the chain of `T` nodes that starts at the absolute address
/// `first`. A node must lie wholly inside `bytes` and be aligned for `T`.
/// The walk stops at a null or bad pointer, at a node seen already (a
/// cyclic `Next`) and after `cap` nodes. It never reads outside `bytes`.
pub(crate) fn walk_chain<T: PlainNode>(
    bytes: &[u8],
    first: usize,
    next: impl Fn(&T) -> usize,
    cap: usize,
) -> Vec<T> {
    let start = bytes.as_ptr() as usize;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut at = first;
    while out.len() < cap {
        let Some(off) = offset_in(start, bytes.len(), at, size_of::<T>()) else {
            break;
        };
        if !at.is_multiple_of(align_of::<T>()) || !seen.insert(off) {
            break;
        }
        // SAFETY: `off + size_of::<T>()` lies inside `bytes` (offset_in) and
        // the address is aligned for `T`, both checked above. `T` is a
        // `PlainNode`, so any bits the OS or a test wrote are a valid value.
        // `read` copies, so no reference into the buffer outlives this line.
        let node: T = unsafe { ptr::read(bytes.as_ptr().add(off).cast::<T>()) };
        at = next(&node);
        out.push(node);
    }
    out
}

/// The adapter list in `bytes`, which starts at offset 0.
pub(crate) fn adapters(bytes: &[u8]) -> Vec<IP_ADAPTER_ADDRESSES_LH> {
    walk_chain(
        bytes,
        bytes.as_ptr() as usize,
        |n: &IP_ADAPTER_ADDRESSES_LH| n.Next as usize,
        MAX_NODES,
    )
}

/// The `Length` an adapter record must have before its unicast list is
/// read: the field must exist in what the OS wrote.
const ADAPTER_NEEDS: usize = offset_of!(IP_ADAPTER_ADDRESSES_LH, FirstAnycastAddress);
/// The `Length` a unicast record must have before its address is read.
const UNICAST_NEEDS: usize = offset_of!(IP_ADAPTER_UNICAST_ADDRESS_LH, PrefixOrigin);

/// Every unicast address in an adapter list the OS wrote into `bytes`. A
/// record whose `Length` is too short is skipped, its `Next` still
/// followed. A sockaddr outside the buffer or of an unknown family is
/// skipped. Unsorted, may hold duplicates.
pub(crate) fn unicast_in(bytes: &[u8]) -> Vec<IpAddr> {
    let start = bytes.as_ptr() as usize;
    let mut out = Vec::new();
    for adapter in adapters(bytes) {
        // SAFETY: both union views are plain u32 pairs, valid for any bits.
        let length = unsafe { adapter.Anonymous1.Anonymous.Length };
        if usize::try_from(length).unwrap_or(0) < ADAPTER_NEEDS {
            continue;
        }
        let nodes = walk_chain(
            bytes,
            adapter.FirstUnicastAddress as usize,
            |n: &IP_ADAPTER_UNICAST_ADDRESS_LH| n.Next as usize,
            MAX_NODES,
        );
        for node in nodes {
            // SAFETY: a u32 view of a u32-pair or u64 union.
            let length = unsafe { node.Anonymous.Anonymous.Length };
            if usize::try_from(length).unwrap_or(0) < UNICAST_NEEDS {
                continue;
            }
            let sa = node.Address;
            let sa_len = usize::try_from(sa.iSockaddrLength).unwrap_or(0);
            if let Some(o) = offset_in(start, bytes.len(), sa.lpSockaddr as usize, sa_len)
                && let Some(ip) = parse_sockaddr(&bytes[o..o + sa_len])
            {
                out.push(ip);
                if out.len() >= MAX_RAW_ADDRESSES {
                    return out;
                }
            }
        }
    }
    out
}

/// Every unicast address of every adapter, IPv4 and IPv6. Read only.
///
/// # Errors
/// The OS error if `GetAdaptersAddresses` fails.
pub(crate) fn own_unicast_addresses() -> io::Result<Vec<IpAddr>> {
    Ok(fetch(AF_UNSPEC, FLAGS)?.map_or_else(Vec::new, |b| unicast_in(b.bytes())))
}

/// Test helpers that lay crafted lists into a u64 arena. Shared with the
/// DHCP walker tests.
#[cfg(test)]
pub(crate) mod craft {
    use super::*;

    /// A zeroed arena of `bytes` bytes, 8-aligned.
    pub(crate) fn arena(bytes: usize) -> Vec<u64> {
        vec![0u64; bytes.div_ceil(8)]
    }

    /// Absolute address of byte `off` in the arena.
    pub(crate) fn addr(buf: &[u64], off: usize) -> usize {
        buf.as_ptr() as usize + off
    }

    /// Writes `v` at byte `off`. Panics if it does not fit.
    pub(crate) fn put<T>(buf: &mut [u64], off: usize, v: T) {
        assert!(
            off + size_of::<T>() <= buf.len() * 8,
            "crafted write out of the arena"
        );
        // SAFETY: the target range lies inside the arena, checked above.
        // `write_unaligned` needs no alignment.
        unsafe {
            ptr::write_unaligned(buf.as_mut_ptr().cast::<u8>().add(off).cast::<T>(), v);
        }
    }

    /// Writes raw bytes at `off`.
    pub(crate) fn put_bytes(buf: &mut [u64], off: usize, b: &[u8]) {
        assert!(
            off + b.len() <= buf.len() * 8,
            "crafted write out of the arena"
        );
        // SAFETY: the target range lies inside the arena, checked above.
        unsafe {
            ptr::copy_nonoverlapping(b.as_ptr(), buf.as_mut_ptr().cast::<u8>().add(off), b.len());
        }
    }

    /// A zeroed adapter record with a full `Length`.
    pub(crate) fn adapter_node() -> IP_ADAPTER_ADDRESSES_LH {
        let mut n = IP_ADAPTER_ADDRESSES_LH::default();
        n.Anonymous1.Anonymous.Length =
            u32::try_from(size_of::<IP_ADAPTER_ADDRESSES_LH>()).unwrap();
        n
    }

    /// A zeroed unicast record with a full `Length`.
    pub(crate) fn unicast_node() -> IP_ADAPTER_UNICAST_ADDRESS_LH {
        let mut n = IP_ADAPTER_UNICAST_ADDRESS_LH::default();
        n.Anonymous.Anonymous.Length =
            u32::try_from(size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>()).unwrap();
        n
    }

    /// A `SOCKADDR_IN` for `a`.
    pub(crate) fn sin(a: [u8; 4]) -> [u8; 16] {
        let mut v = [0u8; 16];
        v[0] = 2;
        v[4..8].copy_from_slice(&a);
        v
    }

    /// A `SOCKADDR_IN6` for `a`.
    pub(crate) fn sin6(a: std::net::Ipv6Addr) -> [u8; 28] {
        let mut v = [0u8; 28];
        v[0] = 23;
        v[8..24].copy_from_slice(&a.octets());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::craft::*;
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const A_SIZE: usize = size_of::<IP_ADAPTER_ADDRESSES_LH>();
    const U_SIZE: usize = size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
    const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);

    /// Unicast nodes at `offs`, linked in the given order of `links`
    /// (index of the next node, or `None` for the end).
    fn unicast_chain(buf: &mut [u64], offs: &[usize], links: &[Option<usize>]) {
        for (i, &off) in offs.iter().enumerate() {
            let mut n = unicast_node();
            n.Next = links[i].map_or(ptr::null_mut(), |j| addr(buf, offs[j]) as *mut _);
            put(buf, off, n);
        }
    }

    fn count(buf: &[u64], first: usize) -> usize {
        walk_chain(
            as_bytes(buf),
            first,
            |n: &IP_ADAPTER_UNICAST_ADDRESS_LH| n.Next as usize,
            MAX_NODES,
        )
        .len()
    }

    #[test]
    fn walks_a_plain_chain() {
        let mut buf = arena(4096);
        let offs = [
            0,
            U_SIZE.next_multiple_of(8),
            2 * U_SIZE.next_multiple_of(8),
        ];
        unicast_chain(&mut buf, &offs, &[Some(1), Some(2), None]);
        assert_eq!(count(&buf, addr(&buf, 0)), 3);
    }

    #[test]
    fn a_cyclic_next_stops_at_the_first_repeat() {
        let mut buf = arena(4096);
        let step = U_SIZE.next_multiple_of(8);
        unicast_chain(&mut buf, &[0, step], &[Some(1), Some(0)]);
        assert_eq!(count(&buf, addr(&buf, 0)), 2);
        let mut own = arena(4096);
        unicast_chain(&mut own, &[0], &[Some(0)]);
        assert_eq!(count(&own, addr(&own, 0)), 1, "self loop");
    }

    #[test]
    fn a_pointer_outside_the_buffer_ends_the_walk() {
        let mut buf = arena(1024);
        let len = buf.len() * 8;
        let mut n = unicast_node();
        // Past the end, before the start, straddling the end, and null.
        for bad in [
            addr(&buf, len + 64),
            addr(&buf, 0).wrapping_sub(64),
            addr(&buf, len - 8),
            0,
        ] {
            n.Next = bad as *mut _;
            put(&mut buf, 0, n);
            assert_eq!(count(&buf, addr(&buf, 0)), 1, "{bad:#x}");
        }
        assert_eq!(count(&buf, addr(&buf, len)), 0, "first node past the end");
    }

    #[test]
    fn a_misaligned_node_ends_the_walk() {
        let mut buf = arena(2048);
        let mut n = unicast_node();
        n.Next = addr(&buf, 512 + 4) as *mut _;
        put(&mut buf, 0, n);
        put(&mut buf, 512 + 4, unicast_node());
        assert_eq!(count(&buf, addr(&buf, 0)), 1);
    }

    #[test]
    fn the_cap_bounds_a_long_chain() {
        let step = U_SIZE.next_multiple_of(8);
        let n = MAX_NODES + 10;
        let mut buf = arena(step * n);
        let offs: Vec<usize> = (0..n).map(|i| i * step).collect();
        let links: Vec<Option<usize>> = (0..n).map(|i| (i + 1 < n).then_some(i + 1)).collect();
        unicast_chain(&mut buf, &offs, &links);
        assert_eq!(count(&buf, addr(&buf, 0)), MAX_NODES);
    }

    /// One adapter at 0 whose unicast list holds `sockaddrs`. Returns the
    /// arena. Unicast nodes follow the adapter, sockaddrs follow those.
    fn one_adapter(sockaddrs: &[&[u8]]) -> Vec<u64> {
        let mut buf = arena(8192);
        let u0 = A_SIZE.next_multiple_of(8);
        let step = U_SIZE.next_multiple_of(8);
        let s0 = u0 + step * sockaddrs.len();
        let mut a = adapter_node();
        if !sockaddrs.is_empty() {
            a.FirstUnicastAddress = addr(&buf, u0) as *mut _;
        }
        put(&mut buf, 0, a);
        for (i, sa) in sockaddrs.iter().enumerate() {
            let sa_off = s0 + i * 32;
            put_bytes(&mut buf, sa_off, sa);
            let mut n = unicast_node();
            n.Address.lpSockaddr = addr(&buf, sa_off) as *mut _;
            n.Address.iSockaddrLength = i32::try_from(sa.len()).unwrap();
            if i + 1 < sockaddrs.len() {
                n.Next = addr(&buf, u0 + step * (i + 1)) as *mut _;
            }
            put(&mut buf, u0 + step * i, n);
        }
        buf
    }

    #[test]
    fn reads_ipv4_and_ipv6_unicast_addresses() {
        let buf = one_adapter(&[&sin([192, 0, 2, 7]), &sin6(V6)]);
        assert_eq!(
            unicast_in(as_bytes(&buf)),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), IpAddr::V6(V6)]
        );
    }

    #[test]
    fn a_short_unicast_length_skips_that_record_only() {
        let mut buf = one_adapter(&[&sin([192, 0, 2, 7]), &sin([198, 51, 100, 1])]);
        let u0 = A_SIZE.next_multiple_of(8);
        let mut n: IP_ADAPTER_UNICAST_ADDRESS_LH = walk_chain(
            as_bytes(&buf),
            addr(&buf, u0),
            |n: &IP_ADAPTER_UNICAST_ADDRESS_LH| n.Next as usize,
            1,
        )[0];
        n.Anonymous.Anonymous.Length = 8;
        put(&mut buf, u0, n);
        assert_eq!(
            unicast_in(as_bytes(&buf)),
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))]
        );
    }

    #[test]
    fn a_short_adapter_length_skips_its_addresses() {
        let mut buf = one_adapter(&[&sin([192, 0, 2, 7])]);
        let mut a = adapters(as_bytes(&buf))[0];
        a.Anonymous1.Anonymous.Length = 16;
        put(&mut buf, 0, a);
        assert_eq!(unicast_in(as_bytes(&buf)), Vec::<IpAddr>::new());
    }

    #[test]
    fn a_sockaddr_outside_the_buffer_or_too_short_is_skipped() {
        let mut buf = one_adapter(&[&sin([192, 0, 2, 7]), &sin([203, 0, 113, 5])]);
        let u0 = A_SIZE.next_multiple_of(8);
        let step = U_SIZE.next_multiple_of(8);
        let first = |b: &[u64], at: usize| -> IP_ADAPTER_UNICAST_ADDRESS_LH {
            walk_chain(
                as_bytes(b),
                addr(b, at),
                |n: &IP_ADAPTER_UNICAST_ADDRESS_LH| n.Next as usize,
                1,
            )[0]
        };
        let mut n0 = first(&buf, u0);
        n0.Address.lpSockaddr = addr(&buf, buf.len() * 8 - 4) as *mut _;
        put(&mut buf, u0, n0);
        let mut n1 = first(&buf, u0 + step);
        n1.Address.iSockaddrLength = 8;
        put(&mut buf, u0 + step, n1);
        assert_eq!(unicast_in(as_bytes(&buf)), Vec::<IpAddr>::new());
    }

    #[test]
    fn cyclic_adapters_do_not_loop() {
        let mut buf = one_adapter(&[&sin([192, 0, 2, 7])]);
        let mut a = adapters(as_bytes(&buf))[0];
        a.Next = addr(&buf, 0) as *mut _;
        put(&mut buf, 0, a);
        assert_eq!(adapters(as_bytes(&buf)).len(), 1);
        assert_eq!(unicast_in(as_bytes(&buf)).len(), 1);
    }

    #[test]
    fn garbage_arenas_never_panic() {
        let mut s = 0x0bad_c0de_dead_beefu64;
        for _ in 0..300 {
            let mut buf = arena(4096);
            let base = addr(&buf, 0) as u64;
            for w in &mut buf {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                // Many words point into or just past the arena, so walks
                // happen and run into every check.
                *w = match s % 4 {
                    0 => 0,
                    1 => s,
                    _ => base + s % 4200,
                };
            }
            let got = unicast_in(as_bytes(&buf));
            assert!(got.len() <= MAX_RAW_ADDRESSES);
        }
    }

    /// Read only. One `GetAdaptersAddresses` call, no packet. Checks no
    /// value and prints nothing.
    #[test]
    fn live_fetch_reads_without_error() {
        let list = own_unicast_addresses().expect("GetAdaptersAddresses");
        assert!(list.len() <= MAX_RAW_ADDRESSES);
    }
}
