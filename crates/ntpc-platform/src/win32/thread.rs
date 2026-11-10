//! Priority of the calling thread. Only ever the current thread, through
//! the `GetCurrentThread` pseudo handle, which needs no closing and carries
//! full access to the own thread.

use std::io;

use windows_sys::Win32::System::Threading::{
    GetCurrentThread, GetThreadPriority, SetThreadPriority,
};

/// `THREAD_PRIORITY_ERROR_RETURN` (`MAXLONG`), what `GetThreadPriority`
/// gives on failure.
const ERROR_RETURN: i32 = i32::MAX;

/// The raw priority of the calling thread. Read only.
///
/// # Errors
/// The OS error if the call fails.
pub(crate) fn current_priority() -> io::Result<i32> {
    // SAFETY: no arguments. The pseudo handle is always valid for the
    // calling thread and must not be closed.
    let thread = unsafe { GetCurrentThread() };
    // SAFETY: `thread` is the pseudo handle above, valid for this call.
    let p = unsafe { GetThreadPriority(thread) };
    if p == ERROR_RETURN {
        return Err(io::Error::last_os_error());
    }
    Ok(p)
}

/// Sets the raw priority of the calling thread. Touches no other thread.
///
/// # Errors
/// The OS error if the call fails.
pub(crate) fn set_current_priority(raw: i32) -> io::Result<()> {
    // SAFETY: as above.
    let thread = unsafe { GetCurrentThread() };
    // SAFETY: `thread` is the calling thread's pseudo handle and `raw` a
    // plain value. The OS rejects a value it does not know.
    if unsafe { SetThreadPriority(thread, raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
