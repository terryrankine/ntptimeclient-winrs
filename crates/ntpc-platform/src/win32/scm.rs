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

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NETSETUP_JOIN_STATUS, NetApiBufferFree, NetGetJoinInformation,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW,
    QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONTROL_STOP,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, StartServiceW,
};

use super::error_from_code;

/// Largest config buffer accepted. Learn: "The maximum size of this array
/// is 8K bytes". A bigger size from the OS is refused, not trusted.
const MAX_CONFIG_BYTES: u32 = 8 * 1024;

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

/// A service control manager handle. Closed once on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful OpenSCManagerW or
        // OpenServiceW and is closed exactly once here. A close failure has
        // no useful recovery.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// An open service. The service handle is declared first so it is closed
/// before the manager handle.
pub struct Service {
    svc: ScHandle,
    _scm: ScHandle,
}

/// `name` as a NUL-terminated wide string. Refuses an inner NUL.
fn wide_name(name: &str) -> io::Result<Vec<u16>> {
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service name holds a NUL",
        ));
    }
    Ok(name.encode_utf16().chain(std::iter::once(0)).collect())
}

/// Opens `name` on the local machine with exactly `access`.
fn open(name: &str, access: u32) -> io::Result<Service> {
    let wname = wide_name(name)?;
    // SAFETY: null machine and database names mean the local active
    // database. SC_MANAGER_CONNECT is the least right OpenServiceW needs.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(io::Error::last_os_error());
    }
    let scm = ScHandle(scm);
    // SAFETY: `scm.0` is a live manager handle. `wname` is NUL-terminated
    // and outlives the call.
    let svc = unsafe { OpenServiceW(scm.0, wname.as_ptr(), access) };
    if svc.is_null() {
        // Read before the drop of `scm` can touch the last error.
        let e = io::Error::last_os_error();
        drop(scm);
        return Err(e);
    }
    Ok(Service {
        svc: ScHandle(svc),
        _scm: scm,
    })
}

/// Opens `name` for queries only: `SERVICE_QUERY_STATUS |
/// SERVICE_QUERY_CONFIG`.
///
/// # Errors
/// The OS error, for example 1060 when the service does not exist.
pub fn open_query(name: &str) -> io::Result<Service> {
    open(name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)
}

/// Opens `name` with `SERVICE_STOP | SERVICE_QUERY_STATUS`. Mutating.
///
/// # Errors
/// The OS error.
pub fn open_stop(name: &str) -> io::Result<Service> {
    open(name, SERVICE_STOP | SERVICE_QUERY_STATUS)
}

/// Opens `name` with `SERVICE_START`. Mutating.
///
/// # Errors
/// The OS error.
pub fn open_start(name: &str) -> io::Result<Service> {
    open(name, SERVICE_START)
}

/// Opens `name` with `SERVICE_CHANGE_CONFIG`. Mutating.
///
/// # Errors
/// The OS error.
pub fn open_change_config(name: &str) -> io::Result<Service> {
    open(name, SERVICE_CHANGE_CONFIG)
}

/// The `dwCurrentState` of the service. Read only.
///
/// # Errors
/// The OS error.
pub fn current_state(s: &Service) -> io::Result<u32> {
    // The struct is a few dozen bytes, so the size fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let size = size_of::<SERVICE_STATUS_PROCESS>() as u32;
    // SAFETY: SERVICE_STATUS_PROCESS is plain old data, all zero is valid.
    let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    // SAFETY: `st` is a live SERVICE_STATUS_PROCESS of `size` bytes, the
    // layout SC_STATUS_PROCESS_INFO writes. `needed` is a live out slot.
    let ok = unsafe {
        QueryServiceStatusEx(
            s.svc.0,
            SC_STATUS_PROCESS_INFO,
            ptr::from_mut(&mut st).cast::<u8>(),
            size,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.dwCurrentState)
}

/// The `dwStartType` from `QueryServiceConfigW`. Read only. The strings in
/// the struct are never read.
///
/// # Errors
/// The OS error, or an error if the OS asks for more than 8 KiB.
pub fn start_type(s: &Service) -> io::Result<u32> {
    let mut needed = 0u32;
    // SAFETY: a null buffer of size 0 asks only for the size (Learn).
    let ok = unsafe { QueryServiceConfigW(s.svc.0, ptr::null_mut(), 0, &raw mut needed) };
    // SAFETY: GetLastError only reads the thread's last error value. It is
    // read straight after the call.
    let last = unsafe { GetLastError() };
    if ok != 0 || last != ERROR_INSUFFICIENT_BUFFER {
        return Err(if ok != 0 {
            io::Error::other("service config query gave no size")
        } else {
            error_from_code(last)
        });
    }
    // The buffer must hold at least the fixed part we read.
    #[allow(clippy::cast_possible_truncation)]
    let min = size_of::<QUERY_SERVICE_CONFIGW>() as u32;
    if !(min..=MAX_CONFIG_BYTES).contains(&needed) {
        return Err(io::Error::other("service config size out of range"));
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let mut needed2 = 0u32;
    // SAFETY: `buf` holds at least `needed` writable bytes, aligned to 8,
    // which covers the pointer alignment of QUERY_SERVICE_CONFIGW.
    let ok = unsafe {
        QueryServiceConfigW(
            s.svc.0,
            buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),
            needed,
            &raw mut needed2,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded and filled a QUERY_SERVICE_CONFIGW at the
    // start of `buf`, checked above to fit. Only a u32 field is read.
    Ok(unsafe { (*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>()).dwStartType })
}

/// The delayed auto start flag. Read only.
///
/// # Errors
/// The OS error, or an error if the OS asks for a size out of range.
pub fn delayed_auto_start(s: &Service) -> io::Result<bool> {
    let mut needed = 0u32;
    // SAFETY: a null buffer of size 0 asks only for the size.
    let ok = unsafe {
        QueryServiceConfig2W(
            s.svc.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    // SAFETY: as above, read straight after the call.
    let last = unsafe { GetLastError() };
    if ok != 0 || last != ERROR_INSUFFICIENT_BUFFER {
        return Err(if ok != 0 {
            io::Error::other("delayed start query gave no size")
        } else {
            error_from_code(last)
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let min = size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as u32;
    if !(min..=MAX_CONFIG_BYTES).contains(&needed) {
        return Err(io::Error::other("delayed start size out of range"));
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let mut needed2 = 0u32;
    // SAFETY: `buf` holds at least `needed` writable, aligned bytes.
    let ok = unsafe {
        QueryServiceConfig2W(
            s.svc.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            buf.as_mut_ptr().cast::<u8>(),
            needed,
            &raw mut needed2,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call filled a SERVICE_DELAYED_AUTO_START_INFO at the start
    // of `buf`, checked above to fit.
    let flag =
        unsafe { (*buf.as_ptr().cast::<SERVICE_DELAYED_AUTO_START_INFO>()).fDelayedAutostart };
    Ok(flag != 0)
}

/// Sends `SERVICE_CONTROL_STOP`. Does not wait. Mutating.
///
/// # Errors
/// The OS error, for example 1051 (dependents running) or 1062 (not active).
pub fn send_stop(s: &Service) -> io::Result<()> {
    // SAFETY: SERVICE_STATUS is plain old data, all zero is valid.
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a live SERVICE_STATUS out slot.
    let ok = unsafe { ControlService(s.svc.0, SERVICE_CONTROL_STOP, &raw mut st) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Starts the service with no arguments. Does not wait. Mutating.
///
/// # Errors
/// The OS error, for example 1056 (already running) or 1058 (disabled).
pub fn start(s: &Service) -> io::Result<()> {
    // SAFETY: zero arguments with a null vector is allowed (Learn).
    let ok = unsafe { StartServiceW(s.svc.0, 0, ptr::null()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets the start type and nothing else. Mutating.
///
/// # Errors
/// The OS error.
pub fn set_start_type(s: &Service, start_type: u32) -> io::Result<()> {
    // SAFETY: SERVICE_NO_CHANGE for the type and error control, and null for
    // every optional string, change only the start type (Learn). No tag is
    // asked for, so the tag out pointer is null.
    let ok = unsafe {
        ChangeServiceConfigW(
            s.svc.0,
            SERVICE_NO_CHANGE,
            start_type,
            SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets the delayed auto start flag. Mutating.
///
/// # Errors
/// The OS error.
pub fn set_delayed_auto_start(s: &Service, delayed: bool) -> io::Result<()> {
    let info = SERVICE_DELAYED_AUTO_START_INFO {
        fDelayedAutostart: i32::from(delayed),
    };
    // SAFETY: `info` is a live SERVICE_DELAYED_AUTO_START_INFO, the struct
    // this info level reads.
    let ok = unsafe {
        ChangeServiceConfig2W(
            s.svc.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            ptr::from_ref(&info).cast::<c_void>(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---- File helpers for the restore record ----
//
// They sit here, not in a new sibling file, so `win32.rs` keeps exactly the
// one `mod scm;` line this task added.

/// Renames `from` over `to` with `MOVEFILE_REPLACE_EXISTING |
/// MOVEFILE_WRITE_THROUGH`. Learn (MoveFileExW): with write-through "the
/// function does not return until the file is actually moved on the disk".
/// So the restore record survives a power cut right after the call.
///
/// # Errors
/// The OS error, or `InvalidInput` for a path with a NUL.
pub fn replace_file_write_through(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from = super::wide(from)?;
    let to = super::wide(to)?;
    // SAFETY: both names are NUL-terminated wide strings that outlive the
    // call. The flags are documented values.
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The hard link count of an open file. Read only.
///
/// # Errors
/// The OS error.
pub fn file_link_count(file: &std::fs::File) -> io::Result<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain old data, all zero is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a live handle for the whole call. `info` is a live
    // out slot of the documented type.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.nNumberOfLinks)
}
