//! Network change and resume events, and how they wake the host loop.
//!
//! The host asks [`NetworkEvents::changed`] and [`PowerEvents::resumed`]
//! once per loop turn. Both only read and clear a flag. Whoever sets a flag
//! also calls [`HostControl::wake`], so the loop sees it at once and not
//! only at its next timer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ntpc_platform::dhcp::{DhcpError, DhcpWatcher, WaitOutcome, WatchCanceller};

use crate::host::{HostControl, NetworkEvents, PowerEvents};
use crate::transport::TimeSource;

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

/// Notifications closer together than this count as one resume (R107).
/// Windows sends `PBT_APMRESUMEAUTOMATIC` and often `PBT_APMRESUMESUSPEND`
/// for the same wake, a moment apart.
pub const RESUME_DEBOUNCE: Duration = Duration::from_secs(5);

/// The service control handler's side of resume (14c-B). Cheap to clone,
/// safe to call from the control handler thread: it only takes a short
/// lock and never waits.
///
/// 14c-B calls [`ResumeNotifier::notify_resumed`] on BOTH
/// `PBT_APMRESUMEAUTOMATIC` and `PBT_APMRESUMESUSPEND`. A notification
/// within [`RESUME_DEBOUNCE`] of the last counted one is dropped, so one
/// wake gives one `Resumed` event.
///
/// The debounce uses wall time from the host's [`TimeSource`], not its
/// monotonic time. Monotonic time is awake time only, so two real wakes
/// with a short sleep and under 5 s awake between them would merge. Wall
/// time counts the sleep. A wall clock that went backwards (a step) counts
/// as a new resume, the safe side.
#[derive(Clone)]
pub struct ResumeNotifier {
    flag: Arc<AtomicBool>,
    control: HostControl,
    time: Arc<dyn TimeSource>,
    last: Arc<Mutex<Option<i128>>>,
}

impl std::fmt::Debug for ResumeNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumeNotifier")
            .field("pending", &self.flag.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl ResumeNotifier {
    /// The machine resumed. Unless debounced, sets the flag, then wakes the
    /// loop.
    pub fn notify_resumed(&self) {
        let now = self.time.wall_ns();
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            let window = i128::try_from(RESUME_DEBOUNCE.as_nanos()).unwrap_or(i128::MAX);
            if last.is_some_and(|l| now >= l && now - l < window) {
                return;
            }
            *last = Some(now);
        }
        self.flag.store(true, Ordering::SeqCst);
        self.control.wake();
    }
}

/// A connected pair: the host reads what the handler sets. `time` is the
/// host's time source, for the debounce.
#[must_use]
pub fn power_events(
    control: HostControl,
    time: Arc<dyn TimeSource>,
) -> (WinPowerEvents, ResumeNotifier) {
    let flag = Arc::new(AtomicBool::new(false));
    (
        WinPowerEvents {
            flag: Arc::clone(&flag),
        },
        ResumeNotifier {
            flag,
            control,
            time,
            last: Arc::new(Mutex::new(None)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Inner, Msg, channel};
    use std::cell::Cell;
    use std::sync::atomic::AtomicI64;

    fn wakes(inbox: &crate::host::Inbox) -> usize {
        std::iter::from_fn(|| inbox.try_recv())
            .filter(|m| matches!(m, Msg(Inner::Wake)))
            .count()
    }

    /// Wall time a test moves by hand.
    struct HandTime(AtomicI64);

    impl TimeSource for HandTime {
        fn mono(&self) -> ntpc_core::Mono {
            ntpc_core::Mono::from_nanos(0)
        }
        fn wall_ns(&self) -> i128 {
            i128::from(self.0.load(Ordering::SeqCst))
        }
    }

    const SEC: i64 = 1_000_000_000;

    struct Rig {
        power: WinPowerEvents,
        resume: ResumeNotifier,
        time: Arc<HandTime>,
        inbox: crate::host::Inbox,
    }

    fn rig() -> Rig {
        let (control, inbox) = channel();
        let time = Arc::new(HandTime(AtomicI64::new(1_000 * SEC)));
        let shared: Arc<dyn TimeSource> = time.clone();
        let (power, resume) = power_events(control, shared);
        Rig {
            power,
            resume,
            time,
            inbox,
        }
    }

    #[test]
    fn resume_sets_the_flag_once_and_wakes_the_loop() {
        let r = rig();
        assert!(!r.power.resumed());
        r.resume.notify_resumed();
        assert!(r.power.resumed());
        assert!(!r.power.resumed(), "read clears it");
        assert_eq!(wakes(&r.inbox), 1);
    }

    #[test]
    fn two_notifications_one_second_apart_are_one_resume() {
        let r = rig();
        r.resume.notify_resumed();
        r.time.0.fetch_add(SEC, Ordering::SeqCst);
        r.resume.clone().notify_resumed();
        assert!(r.power.resumed());
        assert!(!r.power.resumed(), "the second one was dropped");
        assert_eq!(wakes(&r.inbox), 1);
    }

    #[test]
    fn two_notifications_ten_seconds_apart_are_two_resumes() {
        let r = rig();
        r.resume.notify_resumed();
        assert!(r.power.resumed());
        r.time.0.fetch_add(10 * SEC, Ordering::SeqCst);
        r.resume.notify_resumed();
        assert!(r.power.resumed());
        assert_eq!(wakes(&r.inbox), 2);
    }

    #[test]
    fn the_window_runs_from_the_last_counted_resume() {
        let r = rig();
        r.resume.notify_resumed();
        let _ = r.power.resumed();
        let mut counted = 0;
        for _ in 0..4 {
            r.time.0.fetch_add(2 * SEC, Ordering::SeqCst);
            r.resume.notify_resumed();
            counted += usize::from(r.power.resumed());
        }
        // At 2 and 4 s dropped, at 6 s counted, at 8 s dropped.
        assert_eq!(counted, 1);
    }

    #[test]
    fn a_clock_that_went_back_counts_as_a_new_resume() {
        let r = rig();
        r.resume.notify_resumed();
        let _ = r.power.resumed();
        r.time.0.fetch_sub(SEC, Ordering::SeqCst);
        r.resume.notify_resumed();
        assert!(r.power.resumed());
    }

    #[test]
    fn the_notifier_debug_names_no_handle() {
        let r = rig();
        assert!(format!("{:?}", r.resume).starts_with("ResumeNotifier"));
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
