//! IP Helper and DHCP client API calls for `crate::dhcp`.
//!
//! Facts and sources: `docs/architecture.md`, "Platform: DHCP option 42".
//! Every pointer the OS returns is checked to lie inside the buffer we
//! passed before it is read. Policy (which adapters, caps, ordering) lives
//! in `crate::dhcp`.

use std::ffi::c_void;
use std::io;
use std::mem::offset_of;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_DATA, HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::Dhcp::{
    DHCPAPI_PARAMS, DHCPCAPI_PARAMS_ARRAY, DHCPCAPI_REQUEST_SYNCHRONOUS, DhcpCApiCleanup,
    DhcpCApiInitialize, DhcpRequestParams,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::AF_INET;

use super::{adapters, error_from_code};
use crate::dhcp::{AdapterInfo, Signal, adapter_name_wide, c_str_at, offset_in, sockaddr_in_addr};

/// Option 42, NTP servers (RFC 2132).
const OPTION_NTP_SERVERS: u32 = 42;
/// Option 42 fits in 255 bytes. Room for the array the API also writes.
const OPTION_BUF_START: usize = 1024;
/// Refuse to grow the option buffer past this.
const OPTION_BUF_MAX: usize = 64 * 1024;
/// The required size may grow between calls (Learn). Retry a few times.
const TRIES: usize = 4;

/// Lists IPv4 adapters with the fields `crate::dhcp` filters on. Read only.
///
/// # Errors
/// The OS error if `GetAdaptersAddresses` fails or the buffer would pass
/// 1 MiB.
pub(crate) fn list_adapters() -> io::Result<Vec<AdapterInfo>> {
    Ok(adapters::fetch(AF_INET, adapters::FLAGS)?
        .map_or_else(Vec::new, |b| walk_adapters(b.bytes())))
}

/// Walks the adapter list the OS wrote into `bytes`. The shared walker
/// stops at a node outside the buffer, a misaligned node, a repeat (a
/// cyclic `Next`) and after `adapters::MAX_NODES`. A pointer field outside
/// the buffer skips that field.
fn walk_adapters(bytes: &[u8]) -> Vec<AdapterInfo> {
    let start = bytes.as_ptr() as usize;
    // Fields up to and including `Dhcpv4Server` exist from Vista on.
    let needed = offset_of!(IP_ADAPTER_ADDRESSES_LH, CompartmentId);
    let mut out = Vec::new();
    for node in adapters::adapters(bytes) {
        // SAFETY: both union views are plain u32 pairs, valid for any bits.
        let (length, if_index) = unsafe {
            (
                node.Anonymous1.Anonymous.Length,
                node.Anonymous1.Anonymous.IfIndex,
            )
        };
        // SAFETY: `Flags` is a u32 view of a u32 bitfield union.
        let flags = unsafe { node.Anonymous2.Flags };
        if usize::try_from(length).unwrap_or(0) >= needed
            && let Some(info) = adapter_info(bytes, start, &node, if_index, flags)
        {
            out.push(info);
        }
    }
    out
}

/// One adapter record. `None` when its name is missing or not a GUID.
fn adapter_info(
    bytes: &[u8],
    start: usize,
    node: &IP_ADAPTER_ADDRESSES_LH,
    if_index: u32,
    flags: u32,
) -> Option<AdapterInfo> {
    let name_off = offset_in(start, bytes.len(), node.AdapterName as usize, 1)?;
    let name = adapter_name_wide(c_str_at(bytes, name_off)?)?;
    let sa = node.Dhcpv4Server;
    let sa_len = usize::try_from(sa.iSockaddrLength).unwrap_or(0);
    let lease_server = offset_in(start, bytes.len(), sa.lpSockaddr as usize, sa_len)
        .and_then(|o| sockaddr_in_addr(&bytes[o..o + sa_len]));
    Some(AdapterInfo {
        name,
        if_index,
        metric: node.Ipv4Metric,
        up: node.OperStatus == IfOperStatusUp,
        dhcp_enabled: flags & IP_ADAPTER_DHCP_ENABLED != 0,
        if_type: node.IfType,
        has_lease: lease_server.is_some(),
        lease_server,
    })
}

/// The DHCP client API, started for the life of this value.
pub(crate) struct DhcpApi(());

impl DhcpApi {
    /// Calls `DhcpCApiInitialize`.
    ///
    /// # Errors
    /// The OS error code if it fails.
    pub(crate) fn start() -> io::Result<Self> {
        let mut version = 0u32;
        // SAFETY: `version` is a live u32 out value.
        let rc = unsafe { DhcpCApiInitialize(&raw mut version) };
        if rc != NO_ERROR {
            return Err(error_from_code(rc));
        }
        Ok(Self(()))
    }

    /// Asks the DHCP client for option 42 on one adapter. `name` is a
    /// NUL-terminated wide GUID string from `adapter_name_wide`.
    ///
    /// NETWORK: if option 42 is not in the client cache, Windows sends a
    /// DHCPINFORM and may block up to 2 minutes (Learn).
    ///
    /// # Errors
    /// The OS error code if the call fails or the buffer would pass 64 KiB.
    // `&self` is the proof that the API was started. It carries no data.
    #[allow(clippy::unused_self)]
    pub(crate) fn request_option42(&self, name: &[u16]) -> io::Result<Option<Vec<u8>>> {
        if name.last() != Some(&0) || name.len() > crate::dhcp::MAX_ADAPTER_NAME + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "adapter name"));
        }
        let mut want = OPTION_BUF_START;
        for _ in 0..TRIES {
            let mut buf = vec![0u8; want];
            let mut size =
                u32::try_from(buf.len()).map_err(|_| error_from_code(ERROR_MORE_DATA))?;
            let mut param = DHCPAPI_PARAMS {
                Flags: 0,
                OptionId: OPTION_NTP_SERVERS,
                IsVendor: 0,
                Data: ptr::null_mut(),
                nBytesData: 0,
            };
            let recd = DHCPCAPI_PARAMS_ARRAY {
                nParams: 1,
                Params: &raw mut param,
            };
            let send = DHCPCAPI_PARAMS_ARRAY {
                nParams: 0,
                Params: ptr::null_mut(),
            };
            // SAFETY: `name` is NUL-terminated and under 256 characters,
            // checked above. `param`, `buf` and `size` are live locals that
            // outlive the call. `size` holds the buffer length. Reserved,
            // class id and request id are null, which Learn allows for a
            // non-persistent request. The call writes `param.Data` to point
            // into `buf`, checked below before any read.
            let rc = unsafe {
                DhcpRequestParams(
                    DHCPCAPI_REQUEST_SYNCHRONOUS,
                    ptr::null_mut(),
                    name.as_ptr(),
                    ptr::null_mut(),
                    send,
                    recd,
                    buf.as_mut_ptr(),
                    &raw mut size,
                    ptr::null(),
                )
            };
            match rc {
                NO_ERROR => {
                    let n = usize::try_from(param.nBytesData).unwrap_or(usize::MAX);
                    if n == 0 {
                        return Ok(None);
                    }
                    let Some(o) =
                        offset_in(buf.as_ptr() as usize, buf.len(), param.Data as usize, n)
                    else {
                        // Data outside our buffer: corrupt, never read it.
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "option outside buffer",
                        ));
                    };
                    return Ok(Some(buf[o..o + n].to_vec()));
                }
                ERROR_MORE_DATA => {
                    let need = usize::try_from(size).unwrap_or(usize::MAX);
                    if need > OPTION_BUF_MAX {
                        return Err(error_from_code(ERROR_MORE_DATA));
                    }
                    want = need.max(want + 1);
                }
                other => return Err(error_from_code(other)),
            }
        }
        Err(error_from_code(ERROR_MORE_DATA))
    }
}

impl Drop for DhcpApi {
    fn drop(&mut self) {
        // SAFETY: pairs the successful `DhcpCApiInitialize` in `start`. No
        // arguments.
        unsafe { DhcpCApiCleanup() };
    }
}

/// A live `NotifyUnicastIpAddressChange(AF_INET)` subscription. Dropping it
/// deregisters. Read only.
pub(crate) struct AddrChangeRegistration {
    handle: HANDLE,
    /// The `Arc` handed to the OS as the callback context.
    context: *const Signal,
}

impl std::fmt::Debug for AddrChangeRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddrChangeRegistration")
            .finish_non_exhaustive()
    }
}

// SAFETY: the handle is only passed to `CancelMibChangeNotify2`, which has
// no thread affinity (Learn names only the callback thread as forbidden).
// The context is an `Arc<Signal>`, and `Signal` is `Send + Sync`.
unsafe impl Send for AddrChangeRegistration {}
// SAFETY: `&self` gives no access to the handle or the context.
unsafe impl Sync for AddrChangeRegistration {}

/// The OS callback. Learn: calls are serialised. It only sets a flag.
unsafe extern "system" fn on_addr_change(
    context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: `context` is the `Arc<Signal>` pointer from `register`. Its
    // count is released only after `CancelMibChangeNotify2` has returned,
    // which waits for a running callback (see Drop), so it is live here.
    let signal = unsafe { &*context.cast::<Signal>() };
    signal.notify();
}

impl AddrChangeRegistration {
    /// Subscribes `signal` to IPv4 unicast address changes.
    ///
    /// # Errors
    /// The OS error code if the registration fails.
    pub(crate) fn register(signal: Arc<Signal>) -> io::Result<Self> {
        let context = Arc::into_raw(signal);
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: the callback has the documented signature. `context` stays
        // valid until Drop releases it after the cancel. No initial
        // notification is asked for. `handle` is a live out value.
        let rc = unsafe {
            NotifyUnicastIpAddressChange(
                AF_INET,
                Some(on_addr_change),
                context.cast::<c_void>(),
                false,
                &raw mut handle,
            )
        };
        if rc != NO_ERROR || handle.is_null() {
            // SAFETY: registration failed, so the OS holds no copy of the
            // pointer. This takes back the count `into_raw` gave away.
            drop(unsafe { Arc::from_raw(context) });
            return Err(error_from_code(if rc == NO_ERROR {
                ERROR_NO_DATA
            } else {
                rc
            }));
        }
        Ok(Self { handle, context })
    }
}

impl Drop for AddrChangeRegistration {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful registration and is
        // cancelled once, here. Drop never runs on the callback thread: the
        // callback holds no reference to this value.
        let rc = unsafe { CancelMibChangeNotify2(self.handle) };
        if rc == NO_ERROR {
            // SAFETY: the subscription is gone and the cancel waited for any
            // running callback (Learn's deadlock warning implies the wait).
            // So nobody else uses the pointer. Released once, here.
            drop(unsafe { Arc::from_raw(self.context) });
        }
        // On failure the context is leaked on purpose: a few bytes are
        // better than a callback reading freed memory.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These read the adapter list and register for notifications. Both are
    // read only and send no packet. They print nothing and check no value.

    #[test]
    fn adapter_list_reads_without_error() {
        let list = list_adapters().expect("GetAdaptersAddresses");
        for a in &list {
            assert_eq!(a.name.last(), Some(&0));
        }
    }

    #[test]
    fn dhcp_api_starts_and_stops() {
        let api = DhcpApi::start().expect("DhcpCApiInitialize");
        drop(api);
    }

    #[test]
    fn request_refuses_an_unterminated_name() {
        let api = DhcpApi::start().expect("DhcpCApiInitialize");
        let err = api
            .request_option42(&[u16::from(b'{')])
            .expect_err("no NUL");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // Crafted buffers for the adapter walker (Task 13 review M7).
    mod crafted {
        use super::super::*;
        use crate::win32::adapters::as_bytes;
        use crate::win32::adapters::craft::{adapter_node, addr, arena, put, put_bytes, sin};
        use std::mem::size_of;
        use std::net::Ipv4Addr;

        const A_SIZE: usize = size_of::<IP_ADAPTER_ADDRESSES_LH>();
        const NAME: &[u8] = b"{00000000-0000-0000-0000-000000000001}\0";

        /// Two leased, up, DHCP adapters at 0 and one record further on,
        /// with names and lease sockaddrs after them. Index 7 and 9.
        fn two_adapters() -> Vec<u64> {
            let mut buf = arena(8192);
            let second = A_SIZE.next_multiple_of(8);
            let data = 2 * second;
            put_bytes(&mut buf, data, NAME);
            let mut name2 = NAME.to_vec();
            name2[36] = b'2';
            put_bytes(&mut buf, data + 64, &name2);
            put_bytes(&mut buf, data + 128, &sin([192, 0, 2, 67]));
            put_bytes(&mut buf, data + 160, &sin([198, 51, 100, 67]));
            for (i, off) in [0, second].into_iter().enumerate() {
                let mut a = adapter_node();
                a.Anonymous1.Anonymous.IfIndex = 7 + 2 * u32::try_from(i).unwrap();
                a.Anonymous2.Flags = IP_ADAPTER_DHCP_ENABLED;
                a.OperStatus = IfOperStatusUp;
                a.IfType = 6;
                a.AdapterName = addr(&buf, data + 64 * i) as *mut u8;
                a.Dhcpv4Server.lpSockaddr = addr(&buf, data + 128 + 32 * i) as *mut _;
                a.Dhcpv4Server.iSockaddrLength = 16;
                if i == 0 {
                    a.Next = addr(&buf, second) as *mut _;
                }
                put(&mut buf, off, a);
            }
            buf
        }

        fn node_at(buf: &[u64], off: usize) -> IP_ADAPTER_ADDRESSES_LH {
            adapters::walk_chain(
                as_bytes(buf),
                addr(buf, off),
                |n: &IP_ADAPTER_ADDRESSES_LH| n.Next as usize,
                1,
            )[0]
        }

        #[test]
        fn reads_both_adapters_and_their_lease_servers() {
            let buf = two_adapters();
            let got = walk_adapters(as_bytes(&buf));
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].if_index, 7);
            assert_eq!(got[0].lease_server, Some(Ipv4Addr::new(192, 0, 2, 67)));
            assert_eq!(got[1].lease_server, Some(Ipv4Addr::new(198, 51, 100, 67)));
            assert!(got.iter().all(|a| a.has_lease && a.up && a.dhcp_enabled));
        }

        #[test]
        fn a_cyclic_next_does_not_loop() {
            let mut buf = two_adapters();
            let second = A_SIZE.next_multiple_of(8);
            let mut b = node_at(&buf, second);
            b.Next = addr(&buf, 0) as *mut _;
            put(&mut buf, second, b);
            assert_eq!(walk_adapters(as_bytes(&buf)).len(), 2);
        }

        #[test]
        fn a_next_outside_the_buffer_ends_the_walk() {
            let mut buf = two_adapters();
            let mut a = node_at(&buf, 0);
            a.Next = addr(&buf, buf.len() * 8 - 16) as *mut _;
            put(&mut buf, 0, a);
            assert_eq!(walk_adapters(as_bytes(&buf)).len(), 1);
        }

        #[test]
        fn a_short_length_skips_that_adapter_only() {
            let mut buf = two_adapters();
            let mut a = node_at(&buf, 0);
            a.Anonymous1.Anonymous.Length = 64;
            put(&mut buf, 0, a);
            let got = walk_adapters(as_bytes(&buf));
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].if_index, 9);
        }

        #[test]
        fn a_name_or_lease_outside_the_buffer_is_not_read() {
            let mut buf = two_adapters();
            let mut a = node_at(&buf, 0);
            a.AdapterName = addr(&buf, buf.len() * 8 + 8) as *mut u8;
            put(&mut buf, 0, a);
            let second = A_SIZE.next_multiple_of(8);
            let mut b = node_at(&buf, second);
            b.Dhcpv4Server.lpSockaddr = addr(&buf, buf.len() * 8 - 8) as *mut _;
            put(&mut buf, second, b);
            let got = walk_adapters(as_bytes(&buf));
            assert_eq!(got.len(), 1, "no name: adapter dropped");
            assert_eq!(got[0].lease_server, None, "lease outside: no lease");
            assert!(!got[0].has_lease);
        }
    }

    #[test]
    fn registration_can_be_made_and_dropped() {
        let signal = Arc::new(Signal::default());
        let reg = AddrChangeRegistration::register(Arc::clone(&signal)).expect("register");
        drop(reg);
        // The OS released its count, so ours is the only one left.
        assert_eq!(Arc::strong_count(&signal), 1);
    }
}
