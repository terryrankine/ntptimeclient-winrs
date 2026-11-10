//! IP Helper and DHCP client API calls for `crate::dhcp`.
//!
//! Facts and sources: `docs/architecture.md`, "Platform: DHCP option 42".
//! Every pointer the OS returns is checked to lie inside the buffer we
//! passed before it is read. Policy (which adapters, caps, ordering) lives
//! in `crate::dhcp`.

use std::ffi::c_void;
use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_MORE_DATA, ERROR_NO_DATA, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::Dhcp::{
    DHCPAPI_PARAMS, DHCPCAPI_PARAMS_ARRAY, DHCPCAPI_REQUEST_SYNCHRONOUS, DhcpCApiCleanup,
    DhcpCApiInitialize, DhcpRequestParams,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED, MIB_NOTIFICATION_TYPE,
    MIB_UNICASTIPADDRESS_ROW, NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::AF_INET;

use super::error_from_code;
use crate::dhcp::{
    AdapterInfo, Signal, adapter_name_wide, c_str_at, offset_in, sockaddr_in_is_set,
};

/// Option 42, NTP servers (RFC 2132).
const OPTION_NTP_SERVERS: u32 = 42;
/// Learn suggests a 15 KB first buffer for `GetAdaptersAddresses`.
const ADAPTER_BUF_START: usize = 16 * 1024;
/// Refuse to grow the adapter buffer past this. A real list is far smaller.
const ADAPTER_BUF_MAX: usize = 1 << 20;
/// Stop walking a list longer than this. Guards against a loop in `Next`.
const MAX_ADAPTERS: usize = 1024;
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
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut want = ADAPTER_BUF_START;
    for _ in 0..TRIES {
        // u64 words give the 8-byte alignment the structs need.
        let mut buf = vec![0u64; want.div_ceil(8)];
        let bytes_len = buf.len() * 8;
        let mut size =
            u32::try_from(bytes_len).map_err(|_| error_from_code(ERROR_BUFFER_OVERFLOW))?;
        // SAFETY: `buf` is a live, zeroed, 8-aligned allocation of `size`
        // bytes. The reserved pointer must be null (Learn). `size` is a live
        // u32 the call updates.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                flags,
                ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &raw mut size,
            )
        };
        match rc {
            NO_ERROR => return Ok(walk_adapters(&buf)),
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => {
                let need = usize::try_from(size).unwrap_or(usize::MAX);
                if need > ADAPTER_BUF_MAX {
                    return Err(error_from_code(ERROR_BUFFER_OVERFLOW));
                }
                want = need.max(want + 1);
            }
            other => return Err(error_from_code(other)),
        }
    }
    Err(error_from_code(ERROR_BUFFER_OVERFLOW))
}

/// Walks the adapter list the OS wrote into `buf`. A node or pointer that
/// does not lie wholly inside `buf` ends the walk or skips the field.
fn walk_adapters(buf: &[u64]) -> Vec<AdapterInfo> {
    // SAFETY: a u64 slice viewed as bytes: same allocation, 8 times the
    // length, u8 has no alignment or validity rules. Borrowed from `buf`.
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
    let start = bytes.as_ptr() as usize;
    let node_size = size_of::<IP_ADAPTER_ADDRESSES_LH>();
    // Fields up to and including `Dhcpv4Server` exist from Vista on.
    let needed = offset_of!(IP_ADAPTER_ADDRESSES_LH, CompartmentId);
    let mut out = Vec::new();
    let mut off = 0usize;
    for _ in 0..MAX_ADAPTERS {
        if off + node_size > bytes.len()
            || !off.is_multiple_of(align_of::<IP_ADAPTER_ADDRESSES_LH>())
        {
            break;
        }
        // SAFETY: `off` is aligned and `off + node_size` is inside `bytes`,
        // checked above. The buffer was zeroed and then written by the OS.
        // Every field is an integer, pointer or union of those, so any bit
        // pattern is a valid value. `read` copies, so no reference into the
        // buffer outlives this line.
        let node: IP_ADAPTER_ADDRESSES_LH = unsafe { ptr::read(bytes.as_ptr().add(off).cast()) };
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
        let next = node.Next as usize;
        if next == 0 {
            break;
        }
        match offset_in(start, bytes.len(), next, node_size) {
            Some(o) => off = o,
            None => break,
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
    let has_lease = offset_in(start, bytes.len(), sa.lpSockaddr as usize, sa_len)
        .is_some_and(|o| sockaddr_in_is_set(&bytes[o..o + sa_len]));
    Some(AdapterInfo {
        name,
        if_index,
        metric: node.Ipv4Metric,
        up: node.OperStatus == IfOperStatusUp,
        dhcp_enabled: flags & IP_ADAPTER_DHCP_ENABLED != 0,
        if_type: node.IfType,
        has_lease,
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

    #[test]
    fn registration_can_be_made_and_dropped() {
        let signal = Arc::new(Signal::default());
        let reg = AddrChangeRegistration::register(Arc::clone(&signal)).expect("register");
        drop(reg);
        // The OS released its count, so ours is the only one left.
        assert_eq!(Arc::strong_count(&signal), 1);
    }
}
