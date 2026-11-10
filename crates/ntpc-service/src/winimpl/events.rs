//! Network change and resume events, and how they wake the host loop.
//!
//! The host asks [`NetworkEvents::changed`] and [`PowerEvents::resumed`]
//! once per loop turn. Both only read and clear a flag. Whoever sets a flag
//! also calls [`HostControl::wake`], so the loop sees it at once and not
//! only at its next timer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ntpc_platform::dhcp::{DhcpError, DhcpWatcher, WaitOutcome, WatchCanceller};

use crate::host::{HostControl, NetworkEvents, PowerEvents};

/// Name of the address watcher thread.
const WATCH_THREAD: &str = "ntpc-netwatch";

/// Longest single wait of the watcher thread. A timeout only loops, so the
/// value matters only for how often the thread wakes for nothing.
const WATCH_WAIT: Duration = Duration::from_secs(3600);

/// The watcher thread's loop, apart from the OS so it can be tested: wait,
/// on a change set the flag and wake the loop, end on a cancel.
fn pump(mut wait: impl FnMut(Duration) -> WaitOutcome, pending: &AtomicBool, wake: impl Fn()) {
    loop {
        match wait(WATCH_WAIT) {
            WaitOutcome::Changed => {
                pending.store(true, Ordering::SeqCst);
                wake();
            }
            WaitOutcome::TimedOut => {}
            WaitOutcome::Cancelled => return,
        }
    }
}

/// IPv4 address changes from [`DhcpWatcher`] (`NotifyUnicastIpAddressChange`,
/// read only). A watcher thread waits on it, sets a flag and wakes the
/// loop. Any change counts: a lease gained, lost or moved, or any other
/// IPv4 address change (R66, R82 M5 deferred per R100).
///
/// IPv6-only changes do not fire. The host's long DHCP timer and the
/// resolver's own timer still cover them.
pub struct WinNetworkEvents {
    pending: Arc<AtomicBool>,
    canceller: WatchCanceller,
}

impl WinNetworkEvents {
    /// Subscribes and starts the watcher thread. The thread is never
    /// joined. Dropping this cancels the watcher, the thread then ends and
    /// drops the subscription.
    ///
    /// # Errors
    /// [`DhcpError::Watch`] if the OS refuses the subscription or the
    /// thread cannot start.
    pub fn start(control: HostControl) -> Result<Self, DhcpError> {
        let watcher = DhcpWatcher::new()?;
        let canceller = watcher.canceller();
        let pending = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&pending);
        std::thread::Builder::new()
            .name(WATCH_THREAD.to_owned())
            .spawn(move || pump(|d| watcher.wait(d), &flag, || control.wake()))
            .map_err(|e| DhcpError::Watch(e.raw_os_error().unwrap_or(-1)))?;
        Ok(Self { pending, canceller })
    }
}

impl NetworkEvents for WinNetworkEvents {
    /// The host passes a zero timeout. The flag is read and cleared
    /// without waiting, whatever the timeout.
    fn changed(&self, _timeout: Duration) -> bool {
        self.pending.swap(false, Ordering::SeqCst)
    }
}

impl Drop for WinNetworkEvents {
    fn drop(&mut self) {
        self.canceller.cancel();
    }
}

/// No network events: the watcher could not start. The host then sees
/// changes only on its timers.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoNetworkEvents;

impl NetworkEvents for NoNetworkEvents {
    fn changed(&self, _timeout: Duration) -> bool {
        false
    }
}

/// The host's side of resume: read and clear the flag.
#[derive(Debug)]
pub struct WinPowerEvents {
    flag: Arc<AtomicBool>,
}

impl PowerEvents for WinPowerEvents {
    fn resumed(&self) -> bool {
        self.flag.swap(false, Ordering::SeqCst)
    }
}

/// The service control handler's side of resume (14c-B). Cheap to clone,
/// safe to call from the control handler thread: it never blocks.
#[derive(Clone)]
pub struct ResumeNotifier {
    flag: Arc<AtomicBool>,
    control: HostControl,
}

impl ResumeNotifier {
    /// The machine resumed. Sets the flag, then wakes the loop. Several
    /// calls before the loop runs count as one resume.
    pub fn notify_resumed(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.control.wake();
    }
}

/// A connected pair: the host reads what the handler sets.
#[must_use]
pub fn power_events(control: HostControl) -> (WinPowerEvents, ResumeNotifier) {
    let flag = Arc::new(AtomicBool::new(false));
    (
        WinPowerEvents {
            flag: Arc::clone(&flag),
        },
        ResumeNotifier { flag, control },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Inner, Msg, channel};
    use std::cell::Cell;

    fn wakes(inbox: &crate::host::Inbox) -> usize {
        std::iter::from_fn(|| inbox.try_recv())
            .filter(|m| matches!(m, Msg(Inner::Wake)))
            .count()
    }

    #[test]
    fn resume_sets_the_flag_once_and_wakes_the_loop() {
        let (control, inbox) = channel();
        let (power, resume) = power_events(control);
        assert!(!power.resumed());
        resume.notify_resumed();
        resume.clone().notify_resumed();
        assert!(power.resumed());
        assert!(!power.resumed(), "read clears it");
        assert_eq!(wakes(&inbox), 2);
    }

    #[test]
    fn pump_flags_and_wakes_on_each_change_and_ends_on_cancel() {
        let script = [
            WaitOutcome::TimedOut,
            WaitOutcome::Changed,
            WaitOutcome::Changed,
            WaitOutcome::TimedOut,
            WaitOutcome::Cancelled,
            WaitOutcome::Changed,
        ];
        let at = Cell::new(0usize);
        let woken = Cell::new(0u32);
        let pending = AtomicBool::new(false);
        pump(
            |_| {
                let i = at.get();
                at.set(i + 1);
                script[i]
            },
            &pending,
            || woken.set(woken.get() + 1),
        );
        assert_eq!(at.get(), 5, "stopped at the cancel");
        assert_eq!(woken.get(), 2);
        assert!(pending.load(Ordering::SeqCst));
    }

    #[test]
    fn no_network_events_never_fires() {
        assert!(!NoNetworkEvents.changed(Duration::ZERO));
    }

    /// Read only: an address change subscription, no packet. A real change
    /// during the test is allowed, so only the shape is checked.
    #[test]
    fn live_watcher_starts_and_stops() {
        let (control, _inbox) = channel();
        let events = WinNetworkEvents::start(control).expect("subscribe");
        let _ = events.changed(Duration::ZERO);
        drop(events);
    }
}
