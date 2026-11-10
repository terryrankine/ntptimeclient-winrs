//! Read-only queries of a service: status with exit codes, the main
//! config (image path, account, start type) and the optional settings the
//! registration writes (privileges, SID type, failure actions). Used by
//! registration (R109 start wait, R110 image path check) and by the VM
//! tests that read back what install wrote (M11).
//!
//! Each call opens its own handle with `SERVICE_QUERY_STATUS` or
//! `SERVICE_QUERY_CONFIG` only.

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfig2W,
    QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_SID_INFO, SERVICE_STATUS_PROCESS,
};

use super::error_from_code;

/// Largest buffer accepted. Learn (`QueryServiceConfigW`): "The maximum
/// size of this array is 8K bytes". The same cap is used for the optional
/// settings, which are smaller.
const MAX_BYTES: u32 = 8 * 1024;

struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: from a successful open, closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

struct Opened {
    svc: Sc,
    _scm: Sc,
}

fn open(name: &str, access: u32) -> io::Result<Opened> {
    if name.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"));
    }
    let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: null machine and database mean the local active database.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(io::Error::last_os_error());
    }
    let scm = Sc(scm);
    // SAFETY: `scm.0` is live, `w` is NUL-terminated and outlives the call.
    let h = unsafe { OpenServiceW(scm.0, w.as_ptr(), access) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Opened {
        svc: Sc(h),
        _scm: scm,
    })
}

/// State and exit codes from `QueryServiceStatusEx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFacts {
    /// `dwCurrentState`.
    pub state: u32,
    /// `dwWin32ExitCode`.
    pub win32_exit: u32,
    /// `dwServiceSpecificExitCode`.
    pub specific_exit: u32,
}

/// Reads the status. Read only.
///
/// # Errors
/// The OS error, 1060 when the service does not exist.
pub fn status(name: &str) -> io::Result<StatusFacts> {
    let s = open(name, SERVICE_QUERY_STATUS)?;
    // SAFETY: plain old data, all zero is valid.
    let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    #[allow(clippy::cast_possible_truncation)]
    let size = size_of::<SERVICE_STATUS_PROCESS>() as u32;
    // SAFETY: `st` is a live SERVICE_STATUS_PROCESS of `size` bytes.
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
    Ok(StatusFacts {
        state: st.dwCurrentState,
        win32_exit: st.dwWin32ExitCode,
        specific_exit: st.dwServiceSpecificExitCode,
    })
}

/// A NUL-terminated wide string at `p`, at most `max` units, as text.
///
/// # Safety
/// `p` is null or points into a live buffer whose end is at least `max`
/// units away.
unsafe fn wide_at(p: *const u16, max: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    // SAFETY: the caller guarantees `max` readable units from `p`.
    while n < max && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` units from `p` were just read and are inside the buffer.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// Units from `p` to the end of `buf`, or 0 if `p` is outside it.
fn units_left(buf: &[u64], p: *const u16) -> usize {
    let start = buf.as_ptr() as usize;
    let end = start + buf.len() * 8;
    let at = p as usize;
    if at < start || at >= end {
        return 0;
    }
    (end - at) / 2
}

/// The main config fields registration needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFacts {
    /// `lpBinaryPathName`, the image path.
    pub image_path: String,
    /// `lpServiceStartName`, the account.
    pub account: String,
    /// `dwStartType`.
    pub start_type: u32,
    /// `dwServiceType`.
    pub service_type: u32,
}

fn sized(f: impl Fn(*mut u8, u32, *mut u32) -> i32) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    let ok = f(ptr::null_mut(), 0, &raw mut needed);
    // SAFETY: read straight after the call.
    let last = unsafe { GetLastError() };
    if ok != 0 || last != ERROR_INSUFFICIENT_BUFFER {
        return Err(if ok != 0 {
            io::Error::other("query gave no size")
        } else {
            error_from_code(last)
        });
    }
    if !(4..=MAX_BYTES).contains(&needed) {
        return Err(io::Error::other("query size out of range"));
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let mut again = 0u32;
    let ok = f(buf.as_mut_ptr().cast::<u8>(), needed, &raw mut again);
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// Reads the main config. Read only.
///
/// # Errors
/// The OS error.
pub fn config(name: &str) -> io::Result<ConfigFacts> {
    let s = open(name, SERVICE_QUERY_CONFIG)?;
    let buf = sized(|p, n, need| {
        // SAFETY: `p` is null with `n` 0 (size query) or a buffer of `n`
        // writable bytes from a Vec<u64>, so it is 8-aligned, which covers
        // the struct's pointer alignment.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            QueryServiceConfigW(s.svc.0, p.cast::<QUERY_SERVICE_CONFIGW>(), n, need)
        }
    })?;
    if buf.len() * 8 < size_of::<QUERY_SERVICE_CONFIGW>() {
        return Err(io::Error::other("config buffer too small"));
    }
    // SAFETY: the call filled a QUERY_SERVICE_CONFIGW at the start of `buf`,
    // checked above to fit. Its string pointers point into `buf`.
    let c = unsafe { &*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let path = c.lpBinaryPathName.cast_const();
    let account = c.lpServiceStartName.cast_const();
    Ok(ConfigFacts {
        // SAFETY: the pointers point into `buf` or are null. `units_left`
        // bounds each read to the end of `buf`.
        image_path: unsafe { wide_at(path, units_left(&buf, path)) },
        // SAFETY: as above.
        account: unsafe { wide_at(account, units_left(&buf, account)) },
        start_type: c.dwStartType,
        service_type: c.dwServiceType,
    })
}

fn config2(name: &str, level: u32) -> io::Result<Vec<u64>> {
    let s = open(name, SERVICE_QUERY_CONFIG)?;
    sized(|p, n, need| {
        // SAFETY: as in `config`, for the struct `level` writes.
        unsafe { QueryServiceConfig2W(s.svc.0, level, p, n, need) }
    })
}

/// The required privileges (a multi-string). Read only.
///
/// # Errors
/// The OS error.
pub fn privileges(name: &str) -> io::Result<Vec<String>> {
    let buf = config2(name, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)?;
    // SAFETY: the call wrote a SERVICE_REQUIRED_PRIVILEGES_INFOW at the
    // start of `buf` (at least 4 bytes, checked in `sized`, in a buffer rounded up to 8).
    let info = unsafe { &*buf.as_ptr().cast::<SERVICE_REQUIRED_PRIVILEGES_INFOW>() };
    let mut out = Vec::new();
    let mut p = info.pmszRequiredPrivileges.cast_const();
    loop {
        let left = units_left(&buf, p);
        if left == 0 {
            break;
        }
        // SAFETY: `p` points into `buf` with `left` units to its end.
        let s = unsafe { wide_at(p, left) };
        if s.is_empty() {
            break;
        }
        let n = s.encode_utf16().count() + 1;
        out.push(s);
        // SAFETY: `n` is at most `left`, so `p + n` stays inside or one
        // past the end of `buf`, which `units_left` then reports as 0.
        p = unsafe { p.add(n.min(left)) };
    }
    Ok(out)
}

/// The service SID type. Read only.
///
/// # Errors
/// The OS error.
pub fn sid_type(name: &str) -> io::Result<u32> {
    let buf = config2(name, SERVICE_CONFIG_SERVICE_SID_INFO)?;
    // SAFETY: the call wrote a SERVICE_SID_INFO at the start of `buf`.
    Ok(unsafe { (*buf.as_ptr().cast::<SERVICE_SID_INFO>()).dwServiceSidType })
}

/// The failure actions: reset period and `(type, delay ms)` per action.
/// Read only.
///
/// # Errors
/// The OS error.
pub fn failure_actions(name: &str) -> io::Result<(u32, Vec<(i32, u32)>)> {
    let buf = config2(name, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    if buf.len() * 8 < size_of::<SERVICE_FAILURE_ACTIONSW>() {
        return Err(io::Error::other("failure actions buffer too small"));
    }
    // SAFETY: the call wrote a SERVICE_FAILURE_ACTIONSW at the start of
    // `buf`, checked to fit.
    let fa = unsafe { &*buf.as_ptr().cast::<SERVICE_FAILURE_ACTIONSW>() };
    let mut actions = Vec::new();
    let start = buf.as_ptr() as usize;
    let end = start + buf.len() * 8;
    let first = fa.lpsaActions as usize;
    let size = size_of::<windows_sys::Win32::System::Services::SC_ACTION>();
    for i in 0..fa.cActions as usize {
        let at = first + i * size;
        if fa.lpsaActions.is_null() || at < start || at + size > end {
            return Err(io::Error::other("failure action outside the buffer"));
        }
        // SAFETY: `at` is inside `buf` with room for one SC_ACTION, and the
        // array is aligned as the OS wrote it.
        let a = unsafe { &*fa.lpsaActions.add(i) };
        actions.push((a.Type, a.Delay));
    }
    Ok((fa.dwResetPeriod, actions))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Read only: w32time exists on every Windows and Authenticated Users
    // may query it (Learn, default service security).

    #[test]
    fn status_of_w32time_reads() {
        let s = status("w32time").unwrap();
        assert!((1..=7).contains(&s.state), "{s:?}");
    }

    #[test]
    fn config_of_w32time_reads_a_path_and_an_account() {
        let c = config("w32time").unwrap();
        assert!(c.image_path.to_lowercase().contains("svchost"), "{c:?}");
        assert_ne!(c.account, "");
    }

    #[test]
    fn optional_settings_of_w32time_read() {
        let p = privileges("w32time").unwrap();
        assert!(p.iter().all(|s| s.starts_with("Se")), "{p:?}");
        assert!(sid_type("w32time").unwrap() <= 3);
        let (_reset, actions) = failure_actions("w32time").unwrap();
        assert!(actions.len() < 16);
    }

    #[test]
    fn a_missing_service_is_1060() {
        assert_eq!(
            status("ntpc-test-no-such-service")
                .unwrap_err()
                .raw_os_error(),
            Some(1060)
        );
        assert_eq!(
            config("ntpc-test-no-such-service")
                .unwrap_err()
                .raw_os_error(),
            Some(1060)
        );
    }
}
