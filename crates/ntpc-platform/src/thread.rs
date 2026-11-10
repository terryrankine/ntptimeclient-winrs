//! Raises the calling thread's priority for the timing path.
//!
//! The spec asks for a timing path at a priority that survives CPU load.
//! A query worker raises its own priority to above normal before it builds
//! the request, so the send and receive stamps are taken promptly. Above
//! normal, not time critical: a busy NTP worker must never starve the rest
//! of the machine.
//!
//! Only the calling thread is touched. Nothing here changes another thread,
//! the process priority class or any system setting.

use std::marker::PhantomData;

/// A thread priority, as `SetThreadPriority` levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// `THREAD_PRIORITY_NORMAL`.
    Normal,
    /// `THREAD_PRIORITY_ABOVE_NORMAL`, what the query workers use.
    AboveNormal,
}

impl Priority {
    /// The Win32 level (Learn, `SetThreadPriority`).
    #[must_use]
    pub const fn to_raw(self) -> i32 {
        match self {
            Self::Normal => 0,
            Self::AboveNormal => 1,
        }
    }

    /// The priority of a Win32 level, `None` for any other level.
    #[must_use]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Normal),
            1 => Some(Self::AboveNormal),
            _ => None,
        }
    }
}

/// Puts the previous priority back when dropped, on the same thread. Not
/// `Send`, so it cannot be dropped on another thread, which would set that
/// thread instead.
#[derive(Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
#[must_use = "dropping the guard restores the old priority at once"]
pub struct PriorityGuard {
    previous: i32,
    armed: bool,
    _same_thread: PhantomData<*const ()>,
}

impl PriorityGuard {
    /// The raw level found before the change.
    #[must_use]
    pub fn previous(&self) -> i32 {
        self.previous
    }

    /// Keeps the new priority for the rest of this thread's life. For a
    /// short worker thread that ends after one job.
    pub fn keep(mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for PriorityGuard {
    fn drop(&mut self) {
        if self.armed {
            // Best effort: Drop cannot report. A failure leaves only this
            // thread above its old level, and the next set retries.
            let _ = crate::win32::thread::set_current_priority(self.previous);
        }
    }
}

/// The calling thread's raw priority level. Read only.
///
/// # Errors
/// The OS error.
#[cfg(windows)]
pub fn current_thread_priority() -> std::io::Result<i32> {
    crate::win32::thread::current_priority()
}

/// Sets the calling thread's priority. The guard restores the previous one.
///
/// # Errors
/// The OS error if the old level cannot be read or the new one not set.
/// Nothing changed then.
#[cfg(windows)]
pub fn set_current_thread_priority(p: Priority) -> std::io::Result<PriorityGuard> {
    let previous = crate::win32::thread::current_priority()?;
    crate::win32::thread::set_current_priority(p.to_raw())?;
    Ok(PriorityGuard {
        previous,
        armed: true,
        _same_thread: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_match_learn_and_round_trip() {
        assert_eq!(Priority::Normal.to_raw(), 0);
        assert_eq!(Priority::AboveNormal.to_raw(), 1);
        for p in [Priority::Normal, Priority::AboveNormal] {
            assert_eq!(Priority::from_raw(p.to_raw()), Some(p));
        }
        for raw in [-15, -2, -1, 2, 3, 15, i32::MAX, i32::MIN] {
            assert_eq!(Priority::from_raw(raw), None, "{raw}");
        }
    }

    /// Touches only the test's own thread: a fresh thread, so the test
    /// runner's threads keep their level whatever happens.
    #[cfg(windows)]
    #[test]
    fn set_then_read_then_restore_on_own_thread() {
        std::thread::spawn(|| {
            let before = current_thread_priority().expect("read");
            let guard = set_current_thread_priority(Priority::AboveNormal).expect("set");
            assert_eq!(guard.previous(), before);
            assert_eq!(current_thread_priority().expect("read"), 1);
            drop(guard);
            assert_eq!(current_thread_priority().expect("read"), before);
            set_current_thread_priority(Priority::AboveNormal)
                .expect("set")
                .keep();
            assert_eq!(current_thread_priority().expect("read"), 1, "kept");
        })
        .join()
        .expect("priority thread");
    }
}
