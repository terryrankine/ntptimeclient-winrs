//! The system clock and the time source.

use ntpc_core::{Clock, ClockError, Mono, Offset, Ppm};
use ntpc_platform::WindowsClock;
use ntpc_platform::clock::{AdjustmentState, mono_now, wall_now_ns};

use crate::host::ClockControl;
use crate::transport::TimeSource;

/// What [`WinClockControl`] needs beyond the core port. A trait so tests
/// can check the delegation with a fake. The real one is [`WindowsClock`].
pub trait PlatformClock: Clock {
    /// Nominal rate with the OS kept out (R71).
    ///
    /// # Errors
    /// [`ClockError`] if the OS refuses.
    fn take_rate_control(&mut self) -> Result<(), ClockError>;
}

impl PlatformClock for WindowsClock {
    fn take_rate_control(&mut self) -> Result<(), ClockError> {
        WindowsClock::take_rate_control(self)
    }
}

/// The host's clock: [`WindowsClock`] behind [`ClockControl`].
///
/// Every call goes straight to the platform clock, once, with its error
/// unchanged. Platform error text names the operation and the OS message,
/// never a path. `take_rate_control` is `SetSystemTimeAdjustmentPrecise
/// (increment, FALSE)` and `reset_frequency` is `(0, TRUE)`, which hands
/// timekeeping back to the OS (R71, R98).
#[derive(Debug)]
pub struct WinClockControl<C: PlatformClock = WindowsClock>(C);

impl WinClockControl {
    /// Opens the system clock. Reads the rate state and enables
    /// `SeSystemtimePrivilege` in this process's token. Changes neither the
    /// clock nor its rate.
    ///
    /// # Errors
    /// [`ClockError::PermissionDenied`] without the privilege.
    pub fn new() -> Result<Self, ClockError> {
        WindowsClock::new().map(Self)
    }

    /// The rate state found at start, for the start log.
    #[must_use]
    pub fn initial_state(&self) -> AdjustmentState {
        self.0.initial_state()
    }
}

impl<C: PlatformClock> WinClockControl<C> {
    /// Wraps another platform clock. For tests.
    pub fn from_clock(clock: C) -> Self {
        Self(clock)
    }

    /// The wrapped clock.
    pub fn inner(&self) -> &C {
        &self.0
    }
}

impl<C: PlatformClock> Clock for WinClockControl<C> {
    fn mono(&self) -> Mono {
        self.0.mono()
    }

    fn wall_ns(&self) -> i128 {
        self.0.wall_ns()
    }

    fn step(&mut self, by: Offset) -> Result<(), ClockError> {
        self.0.step(by)
    }

    fn set_frequency(&mut self, ppm: Ppm) -> Result<(), ClockError> {
        self.0.set_frequency(ppm)
    }

    fn reset_frequency(&mut self) -> Result<(), ClockError> {
        self.0.reset_frequency()
    }
}

impl<C: PlatformClock> ClockControl for WinClockControl<C> {
    fn take_rate_control(&mut self) -> Result<(), ClockError> {
        self.0.take_rate_control()
    }
}

/// Time for the host and the query workers. Monotonic time is the unbiased
/// interrupt time (`QueryUnbiasedInterruptTimePrecise`): awake time only,
/// not moved by a clock step, which is the engine's contract. Wall time is
/// `GetSystemTimePreciseAsFileTime`. Both are read only.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinTimeSource;

impl TimeSource for WinTimeSource {
    fn mono(&self) -> Mono {
        mono_now()
    }

    fn wall_ns(&self) -> i128 {
        wall_now_ns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Records every call. Changes nothing real.
    #[derive(Debug, Default)]
    struct Fake {
        calls: Vec<&'static str>,
        fail: Option<ClockError>,
    }

    impl Fake {
        fn result(&mut self, name: &'static str) -> Result<(), ClockError> {
            self.calls.push(name);
            self.fail.clone().map_or(Ok(()), Err)
        }
    }

    impl Clock for Fake {
        fn mono(&self) -> Mono {
            Mono::from_nanos(7)
        }
        fn wall_ns(&self) -> i128 {
            11
        }
        fn step(&mut self, _by: Offset) -> Result<(), ClockError> {
            self.result("step")
        }
        fn set_frequency(&mut self, _ppm: Ppm) -> Result<(), ClockError> {
            self.result("set_frequency")
        }
        fn reset_frequency(&mut self) -> Result<(), ClockError> {
            self.result("reset_frequency")
        }
    }

    impl PlatformClock for Fake {
        fn take_rate_control(&mut self) -> Result<(), ClockError> {
            self.result("take_rate_control")
        }
    }

    #[test]
    fn take_and_reset_each_reach_the_platform_once_and_nothing_else() {
        let mut c = WinClockControl::from_clock(Fake::default());
        ClockControl::take_rate_control(&mut c).unwrap();
        c.reset_frequency().unwrap();
        assert_eq!(
            c.inner().calls,
            vec!["take_rate_control", "reset_frequency"]
        );
        assert_eq!(c.mono(), Mono::from_nanos(7));
        assert_eq!(c.wall_ns(), 11);
    }

    #[test]
    fn errors_pass_through_unchanged() {
        let mut c = WinClockControl::from_clock(Fake {
            calls: vec![],
            fail: Some(ClockError::PermissionDenied),
        });
        assert_eq!(
            ClockControl::take_rate_control(&mut c),
            Err(ClockError::PermissionDenied)
        );
        assert_eq!(c.reset_frequency(), Err(ClockError::PermissionDenied));
        assert_eq!(
            c.set_frequency(Ppm::new(1.0)),
            Err(ClockError::PermissionDenied)
        );
        assert_eq!(c.inner().calls.len(), 3, "no retry, no extra call");
    }

    /// Read only: `QueryUnbiasedInterruptTimePrecise`.
    #[test]
    fn mono_is_monotonic_over_many_reads() {
        let t = WinTimeSource;
        let mut last = t.mono();
        for _ in 0..1000 {
            let now = t.mono();
            assert!(now >= last, "mono went backwards");
            last = now;
        }
    }

    /// Read only: `GetSystemTimePreciseAsFileTime`.
    #[test]
    fn wall_is_within_seconds_of_system_time() {
        let std_ns = i128::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("after 1970")
                .as_nanos(),
        )
        .expect("fits");
        let ours = WinTimeSource.wall_ns();
        assert!((ours - std_ns).abs() < 5_000_000_000, "more than 5 s apart");
    }
}
