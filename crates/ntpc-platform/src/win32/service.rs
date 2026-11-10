//! Service process calls: the control dispatcher, the control handler,
//! status reports, our own service registration, the Event Log and the
//! console control handler.
//!
//! Policy lives in `ntpc-service` (`service.rs`, `registration.rs`,
//! `event_log.rs`). This file only wraps the calls. Facts and sources:
//! `docs/architecture.md`, "Service wrapper (Task 14c-B)".
//!
//! No panic may unwind across an `extern "system"` boundary. Every callback
//! the OS calls (`ServiceMain`, `HandlerEx`, the console handler) runs its
//! Rust body inside `catch_unwind`.

use std::ffi::c_void;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::{Mutex, OnceLock, PoisonError};

use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD,
    REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW,
    RegOpenKeyExW, RegSetValueExW,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, RegisterServiceCtrlHandlerExW, SC_ACTION, SC_ACTION_RESTART,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW, SERVICE_FAILURE_ACTIONS_FLAG,
    SERVICE_FAILURE_ACTIONSW, SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_SID_INFO, SERVICE_START,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

use super::error_from_code;

/// `DELETE`, the standard right `DeleteService` needs (Learn).
const DELETE: u32 = 0x0001_0000;

/// A NUL-terminated wide copy of `s`. Refuses an inner NUL.
fn wide_str(s: &str) -> io::Result<Vec<u16>> {
    if s.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "string holds a NUL",
        ));
    }
    Ok(s.encode_utf16().chain(std::iter::once(0)).collect())
}

/// A multi-string: each entry NUL-terminated, then one more NUL (Learn,
/// `SERVICE_REQUIRED_PRIVILEGES_INFOW`). Refuses an empty or NUL entry,
/// which would end the list early.
fn multi_string(items: &[&str]) -> io::Result<Vec<u16>> {
    let mut out = Vec::new();
    for item in items {
        if item.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty multi-string entry",
            ));
        }
        out.extend(wide_str(item)?);
    }
    out.push(0);
    Ok(out)
}

// ---------------------------------------------------------------- dispatcher

/// The Rust body `ServiceMain` runs. Taken once.
static SERVICE_BODY: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    // The arguments are ignored: the image path fixes the command line and
    // nothing the start request passes is trusted.
    let body = SERVICE_BODY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(body) = body {
        // A panic here must not unwind into the dispatcher. The body
        // reports its own STOPPED state, so nothing more can be done.
        let _ = catch_unwind(AssertUnwindSafe(body));
    }
}

/// Connects this process to the service control manager and runs `body`
/// on the thread the dispatcher creates for `ServiceMain`. Returns when the
/// service has reported `SERVICE_STOPPED`.
///
/// # Errors
/// The OS error, `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) when run
/// from a console instead of by the SCM.
pub fn run_dispatcher(name: &str, body: Box<dyn FnOnce() + Send>) -> io::Result<()> {
    let mut wname = wide_str(name)?;
    *SERVICE_BODY.lock().unwrap_or_else(PoisonError::into_inner) = Some(body);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: wname.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table ends with an all-null entry (Learn). `wname` and
    // `table` outlive the call, which returns only when the service stops.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        // Drop the unused body so a later call cannot run a stale one.
        SERVICE_BODY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------- handler

/// The control handler body: `(control, event_type) -> return code`.
pub type ControlFn = dyn Fn(u32, u32) -> u32 + Send + Sync;

unsafe extern "system" fn handler_ex(
    control: u32,
    event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    if context.is_null() {
        return NO_ERROR;
    }
    // SAFETY: `context` is the pointer `register_handler` leaked from a
    // `Box<Box<ControlFn>>`. It is never freed, so it is valid for the life
    // of the process, and the closure is `Sync`, so sharing it is sound.
    let f: &ControlFn = unsafe { &**context.cast::<Box<ControlFn>>() };
    // A panic must not unwind into the dispatcher. NO_ERROR is the answer
    // that never makes the SCM wait for a stop that will not come.
    catch_unwind(AssertUnwindSafe(|| f(control, event_type))).unwrap_or(NO_ERROR)
}

/// A service status handle. Learn: it "does not have to be closed", and
/// `SetServiceStatus` may be called "at any time from any thread".
#[derive(Debug, Clone, Copy)]
pub struct StatusHandle(SERVICE_STATUS_HANDLE);

// SAFETY: the handle is an opaque token the SCM hands out. Learn allows
// `SetServiceStatus` from any thread of the service, and the handle is
// never closed, so sharing it between threads is sound.
unsafe impl Send for StatusHandle {}
// SAFETY: as above. The handle is only passed by value to the OS.
unsafe impl Sync for StatusHandle {}

/// Registers `f` as the control handler of `name`. `f` is leaked on
/// purpose: the dispatcher may call it until the process ends.
///
/// # Errors
/// The OS error.
pub fn register_handler(name: &str, f: Box<ControlFn>) -> io::Result<StatusHandle> {
    let wname = wide_str(name)?;
    let context = Box::into_raw(Box::new(f)).cast::<c_void>();
    // SAFETY: `wname` is NUL-terminated and outlives the call. `context`
    // stays valid for ever (leaked). `handler_ex` has the HandlerEx shape.
    let h = unsafe { RegisterServiceCtrlHandlerExW(wname.as_ptr(), Some(handler_ex), context) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(StatusHandle(h))
}

/// The `SERVICE_STATUS` fields a service reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawStatus {
    /// `dwCurrentState`.
    pub state: u32,
    /// `dwControlsAccepted`.
    pub accepts: u32,
    /// `dwWin32ExitCode`.
    pub win32_exit: u32,
    /// `dwServiceSpecificExitCode`.
    pub specific_exit: u32,
    /// `dwCheckPoint`.
    pub checkpoint: u32,
    /// `dwWaitHint`, milliseconds.
    pub wait_hint_ms: u32,
}

/// Reports `s` for the service behind `h`.
///
/// # Errors
/// The OS error.
pub fn set_status(h: StatusHandle, s: RawStatus) -> io::Result<()> {
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: s.state,
        dwControlsAccepted: s.accepts,
        dwWin32ExitCode: s.win32_exit,
        dwServiceSpecificExitCode: s.specific_exit,
        dwCheckPoint: s.checkpoint,
        dwWaitHint: s.wait_hint_ms,
    };
    // SAFETY: `h.0` came from RegisterServiceCtrlHandlerExW. `st` is a live
    // SERVICE_STATUS for the duration of the call.
    let ok = unsafe { SetServiceStatus(h.0, &raw const st) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------- registration

/// A service control manager or service handle. Closed once on drop.
struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful OpenSCManagerW,
        // OpenServiceW or CreateServiceW and is closed exactly once here.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_manager(access: u32) -> io::Result<Sc> {
    // SAFETY: null machine and database names mean the local active
    // database.
    let h = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Sc(h))
}

/// An open service, closed before its manager.
struct Opened {
    svc: Sc,
    _scm: Sc,
}

fn open_service(name: &str, access: u32) -> io::Result<Opened> {
    let scm = open_manager(SC_MANAGER_CONNECT)?;
    let wname = wide_str(name)?;
    // SAFETY: `scm.0` is live, `wname` is NUL-terminated and outlives the
    // call.
    let h = unsafe { OpenServiceW(scm.0, wname.as_ptr(), access) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Opened {
        svc: Sc(h),
        _scm: scm,
    })
}

/// What `CreateServiceW` and `ChangeServiceConfigW` take from us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawServiceSpec {
    /// Service name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// The full command line, exe path already quoted.
    pub image_path: String,
    /// `SERVICE_AUTO_START` and friends.
    pub start_type: u32,
    /// `SERVICE_ERROR_NORMAL` and friends.
    pub error_control: u32,
}

/// Creates the service as `SERVICE_WIN32_OWN_PROCESS` under `LocalSystem`
/// (a null account, Learn) with no dependencies and no group.
///
/// # Errors
/// The OS error, 1073 when it exists, 1072 when marked for delete.
pub fn create_service(spec: &RawServiceSpec) -> io::Result<()> {
    let scm = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = wide_str(&spec.name)?;
    let display = wide_str(&spec.display_name)?;
    let path = wide_str(&spec.image_path)?;
    // SAFETY: every string is NUL-terminated and outlives the call. Null
    // group, tag, dependencies, account and password are allowed (Learn):
    // a null account means LocalSystem.
    let h = unsafe {
        CreateServiceW(
            scm.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_CHANGE_CONFIG | SERVICE_START,
            SERVICE_WIN32_OWN_PROCESS,
            spec.start_type,
            spec.error_control,
            path.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    drop(Sc(h));
    Ok(())
}

/// Rewrites type, start type, error control, image path, display name and
/// account (`LocalSystem`) of an existing service. Used on a re-install.
///
/// # Errors
/// The OS error.
pub fn update_service(spec: &RawServiceSpec) -> io::Result<()> {
    let s = open_service(&spec.name, SERVICE_CHANGE_CONFIG)?;
    let path = wide_str(&spec.image_path)?;
    let display = wide_str(&spec.display_name)?;
    let account = wide_str("LocalSystem")?;
    let empty = [0u16; 2];
    // SAFETY: the strings are NUL-terminated and outlive the call. An empty
    // double-NUL dependency list clears dependencies. The account
    // "LocalSystem" with an empty password is the documented way to name
    // the LocalSystem account in ChangeServiceConfigW.
    let ok = unsafe {
        ChangeServiceConfigW(
            s.svc.0,
            SERVICE_WIN32_OWN_PROCESS,
            spec.start_type,
            spec.error_control,
            path.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            empty.as_ptr(),
            account.as_ptr(),
            empty.as_ptr(),
            display.as_ptr(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One restart action: the delay in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartAfter(pub u32);

/// What `ChangeServiceConfig2W` sets on our service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExtras {
    /// `SERVICE_CONFIG_DESCRIPTION`.
    pub description: String,
    /// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`.
    pub delayed: bool,
    /// `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`, privilege names.
    pub privileges: Vec<String>,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS`: reset period in seconds.
    pub reset_period_s: u32,
    /// The restart actions, in order. The last one repeats (Learn).
    pub restarts: Vec<RestartAfter>,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
    pub actions_on_non_crash: bool,
    /// `SERVICE_CONFIG_SERVICE_SID_INFO`.
    pub sid_type: u32,
}

fn config2(s: &Opened, level: u32, info: *const c_void) -> io::Result<()> {
    // SAFETY: the caller passes a pointer to the live struct that `level`
    // reads (Learn, ChangeServiceConfig2W). The handle has
    // SERVICE_CHANGE_CONFIG and SERVICE_START, which the restart action
    // needs.
    let ok = unsafe { ChangeServiceConfig2W(s.svc.0, level, info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Applies every [`RawExtras`] field, in a fixed order. Stops at the first
/// failure and says which step failed.
///
/// # Errors
/// The step name and the OS error.
pub fn configure_service(name: &str, x: &RawExtras) -> Result<(), (&'static str, io::Error)> {
    let s = open_service(name, SERVICE_CHANGE_CONFIG | SERVICE_START).map_err(|e| ("open", e))?;

    let mut desc = wide_str(&x.description).map_err(|e| ("description", e))?;
    let d = SERVICE_DESCRIPTIONW {
        lpDescription: desc.as_mut_ptr(),
    };
    config2(&s, SERVICE_CONFIG_DESCRIPTION, ptr::from_ref(&d).cast())
        .map_err(|e| ("description", e))?;

    let delayed = SERVICE_DELAYED_AUTO_START_INFO {
        fDelayedAutostart: i32::from(x.delayed),
    };
    config2(
        &s,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
        ptr::from_ref(&delayed).cast(),
    )
    .map_err(|e| ("delayed start", e))?;

    let names: Vec<&str> = x.privileges.iter().map(String::as_str).collect();
    let mut privs = multi_string(&names).map_err(|e| ("required privileges", e))?;
    let p = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: privs.as_mut_ptr(),
    };
    config2(
        &s,
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        ptr::from_ref(&p).cast(),
    )
    .map_err(|e| ("required privileges", e))?;

    let mut actions: Vec<SC_ACTION> = x
        .restarts
        .iter()
        .map(|r| SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: r.0,
        })
        .collect();
    let count = u32::try_from(actions.len()).map_err(|_| {
        (
            "failure actions",
            io::Error::new(io::ErrorKind::InvalidInput, "too many actions"),
        )
    })?;
    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: x.reset_period_s,
        // Null leaves the reboot message and the command unchanged (Learn).
        // A fresh service has neither.
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: count,
        lpsaActions: actions.as_mut_ptr(),
    };
    config2(
        &s,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        ptr::from_ref(&fa).cast(),
    )
    .map_err(|e| ("failure actions", e))?;

    let flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: i32::from(x.actions_on_non_crash),
    };
    config2(
        &s,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        ptr::from_ref(&flag).cast(),
    )
    .map_err(|e| ("failure actions flag", e))?;

    let sid = SERVICE_SID_INFO {
        dwServiceSidType: x.sid_type,
    };
    config2(
        &s,
        SERVICE_CONFIG_SERVICE_SID_INFO,
        ptr::from_ref(&sid).cast(),
    )
    .map_err(|e| ("service SID type", e))?;
    Ok(())
}

/// Marks the service for deletion. Learn: it goes once every handle is
/// closed and the service is not running.
///
/// # Errors
/// The OS error, 1060 when it does not exist, 1072 when already marked.
pub fn delete_service(name: &str) -> io::Result<()> {
    let s = open_service(name, DELETE)?;
    // SAFETY: the handle is live and was opened with DELETE.
    let ok = unsafe { DeleteService(s.svc.0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------- registry

/// An open registry key. Closed once on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key came from a successful RegCreateKeyExW or
        // RegOpenKeyExW and is closed exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Whether `HKLM\<subkey>` exists. Opens it for query only.
///
/// # Errors
/// The OS error other than "not found".
pub fn hklm_key_exists(subkey: &str) -> io::Result<bool> {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let w = wide_str(subkey)?;
    let mut h: HKEY = ptr::null_mut();
    // SAFETY: `w` is NUL-terminated, `h` is a live out slot. Query access
    // only, 64-bit view so a 32-bit build sees the same key.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &raw mut h,
        )
    };
    match rc {
        0 => {
            drop(Key(h));
            Ok(true)
        }
        ERROR_FILE_NOT_FOUND => Ok(false),
        code => Err(error_from_code(code)),
    }
}

/// Creates (or opens) `HKLM\<subkey>` and writes `EventMessageFile` as
/// `REG_EXPAND_SZ` and `TypesSupported` as `REG_DWORD`. Mutating.
///
/// # Errors
/// The OS error.
pub fn write_event_source(subkey: &str, message_file: &str, types: u32) -> io::Result<()> {
    let w = wide_str(subkey)?;
    let mut h: HKEY = ptr::null_mut();
    let mut disposition = 0u32;
    // SAFETY: `w` is NUL-terminated, `h` and `disposition` are live out
    // slots. No class and default security, which the API allows.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            w.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            ptr::null(),
            &raw mut h,
            &raw mut disposition,
        )
    };
    if rc != 0 {
        return Err(error_from_code(rc));
    }
    let key = Key(h);
    let file = wide_str(message_file)?;
    let name = wide_str("EventMessageFile")?;
    let bytes = u32::try_from(file.len() * 2)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message file path too long"))?;
    // SAFETY: the key is live with KEY_SET_VALUE. The data is the wide
    // string with its NUL, `bytes` long, as REG_EXPAND_SZ needs.
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_EXPAND_SZ,
            file.as_ptr().cast::<u8>(),
            bytes,
        )
    };
    if rc != 0 {
        return Err(error_from_code(rc));
    }
    let name = wide_str("TypesSupported")?;
    let data = types.to_le_bytes();
    // SAFETY: as above, four bytes for REG_DWORD.
    let rc = unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_DWORD, data.as_ptr(), 4) };
    if rc != 0 {
        return Err(error_from_code(rc));
    }
    Ok(())
}

/// Deletes `HKLM\<subkey>`, which must have no subkeys. Mutating.
///
/// # Errors
/// The OS error, 2 when it does not exist.
pub fn delete_hklm_key(subkey: &str) -> io::Result<()> {
    let w = wide_str(subkey)?;
    // SAFETY: `w` is NUL-terminated and outlives the call.
    let rc = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, w.as_ptr()) };
    if rc != 0 {
        return Err(error_from_code(rc));
    }
    Ok(())
}

// ---------------------------------------------------------------- event log

/// A registered event source. Deregistered on drop.
#[derive(Debug)]
pub struct EventSource(HANDLE);

// SAFETY: the handle is used by one thread at a time (the sink's writer
// thread owns it). Event Log handles are not tied to the creating thread.
unsafe impl Send for EventSource {}

impl EventSource {
    /// `RegisterEventSourceW` on the local machine.
    ///
    /// # Errors
    /// The OS error.
    pub fn register(source: &str) -> io::Result<Self> {
        let w = wide_str(source)?;
        // SAFETY: a null server means the local computer. `w` outlives the
        // call.
        let h = unsafe { RegisterEventSourceW(ptr::null(), w.as_ptr()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }

    /// `ReportEventW` with one insertion string and no raw data.
    ///
    /// # Errors
    /// The OS error.
    pub fn report(&self, event_type: u16, event_id: u32, text: &str) -> io::Result<()> {
        let w = wide_str(text)?;
        let strings = [w.as_ptr()];
        // SAFETY: the handle is live. One string pointer in a live array.
        // No user SID and no raw data, both allowed as null with size 0.
        let ok = unsafe {
            ReportEventW(
                self.0,
                event_type,
                0,
                event_id,
                ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for EventSource {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegisterEventSourceW and is closed
        // once.
        unsafe { DeregisterEventSource(self.0) };
    }
}

// ---------------------------------------------------------------- console

/// The console control handler body. Gets the `CTRL_*_EVENT` code.
static CONSOLE_BODY: OnceLock<Box<dyn Fn(u32) + Send + Sync>> = OnceLock::new();

unsafe extern "system" fn console_handler(ctrl: u32) -> windows_sys::core::BOOL {
    match CONSOLE_BODY.get() {
        Some(f) => {
            // A panic must not unwind into the console runtime.
            let _ = catch_unwind(AssertUnwindSafe(|| f(ctrl)));
            1
        }
        None => 0,
    }
}

/// Installs `f` as this process's console control handler. Only the first
/// call installs anything.
///
/// # Errors
/// The OS error, or `AlreadyExists` on a second call.
pub fn set_console_handler(f: Box<dyn Fn(u32) + Send + Sync>) -> io::Result<()> {
    if CONSOLE_BODY.set(f).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "console handler already set",
        ));
    }
    // SAFETY: `console_handler` has the HandlerRoutine shape and lives for
    // the whole program.
    let ok = unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_string_ends_with_two_nuls() {
        let m = multi_string(&["SeSystemtimePrivilege"]).unwrap();
        assert_eq!(&m[m.len() - 2..], &[0, 0]);
        assert_eq!(m.iter().filter(|&&c| c == 0).count(), 2);
        let two = multi_string(&["A", "B"]).unwrap();
        assert_eq!(two, vec![u16::from(b'A'), 0, u16::from(b'B'), 0, 0]);
    }

    #[test]
    fn multi_string_refuses_empty_or_nul_entries() {
        assert!(multi_string(&[""]).is_err());
        assert!(multi_string(&["a\0b"]).is_err());
    }

    #[test]
    fn dispatcher_from_a_console_fails_cleanly() {
        // A test process is not started by the SCM. Learn: the call fails
        // with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT. Read only: no
        // service is touched, the body never runs.
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = ran.clone();
        let e = run_dispatcher(
            "ntpc-test-not-a-service",
            Box::new(move || r.store(true, std::sync::atomic::Ordering::SeqCst)),
        )
        .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(1063));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn missing_registry_key_reads_as_absent() {
        // Read only: a key name that cannot exist.
        let k =
            r"SYSTEM\CurrentControlSet\Services\EventLog\Application\ntpc-test-no-such-source-7f3a";
        assert!(!hklm_key_exists(k).unwrap());
    }

    #[test]
    fn existing_registry_key_reads_as_present() {
        // Read only: the Application log key exists on every Windows.
        assert!(
            hklm_key_exists(r"SYSTEM\CurrentControlSet\Services\EventLog\Application").unwrap()
        );
    }
}
