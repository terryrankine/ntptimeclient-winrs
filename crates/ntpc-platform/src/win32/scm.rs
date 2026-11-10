//! Service control manager and domain join calls.
//!
//! Policy lives in `w32time` and `domain`. This file only wraps the calls.
//! Facts and sources: `docs/architecture.md`, "Platform: `w32time` takeover
//! and domain join".
//!
//! Each wrapper opens its own service handle with only the access its call
//! needs. The query wrappers ask for `SERVICE_QUERY_STATUS` or
//! `SERVICE_QUERY_CONFIG` and nothing else, so a read-only caller can never
//! hold a handle that could stop or reconfigure a service.

use std::ffi::c_void;
use std::io;
use std::ptr;

use super::error_from_code;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NETSETUP_JOIN_STATUS, NetApiBufferFree, NetGetJoinInformation,
};

/// `NERR_Success`.
const NERR_SUCCESS: u32 = 0;

/// Reads the raw `NETSETUP_JOIN_STATUS` of the local machine. Read only.
/// The name buffer is freed unread on every path.
///
/// # Errors
/// The `NET_API_STATUS` as an OS error.
pub fn join_status() -> io::Result<i32> {
    let mut name: windows_sys::core::PWSTR = ptr::null_mut();
    let mut status: NETSETUP_JOIN_STATUS = 0;
    // SAFETY: a null server means the local computer. Both out pointers point
    // at live locals of the documented types.
    let rc = unsafe { NetGetJoinInformation(ptr::null(), &raw mut name, &raw mut status) };
    if !name.is_null() {
        // SAFETY: the system allocated `name` and Learn says it must be
        // freed with NetApiBufferFree. It is freed once and never read.
        // The return value only reports an invalid pointer, which cannot
        // happen for a buffer the call itself returned.
        unsafe { NetApiBufferFree(name.cast::<c_void>().cast_const()) };
    }
    if rc != NERR_SUCCESS {
        return Err(error_from_code(rc));
    }
    Ok(status)
}
