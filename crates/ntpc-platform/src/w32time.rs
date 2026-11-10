//! Takes over from `w32time`, gives it back, and watches it.
//!
//! The logic works against the [`ServiceControl`] trait, so every rule is
//! tested with a fake and no real service is touched. [`ScmControl`] is the
//! real service control manager behind the same trait (Windows only).
//!
//! Rules (facts and sources in `docs/architecture.md`, "Platform: `w32time`
//! takeover and domain join"):
//! - Order is query, persist the record, stop, disable, verify. A crash
//!   after the record leaves the true original on disk.
//! - A valid existing record wins over the current state, so a second
//!   install never records "disabled" as the original.
//! - Only `w32time` is ever touched. The name is a constant, never read from
//!   a file.
//! - [`is_running`] is true when the state cannot be read. Then the engine
//!   must not adjust the clock.

use std::time::Duration;

use thiserror::Error;

#[cfg(any(test, feature = "fake"))]
pub mod fake;

/// The Windows Time service name.
pub const W32TIME: &str = "w32time";

/// How often the host checks [`is_running`] and re-sends the level.
pub const MONITOR_PERIOD: Duration = Duration::from_secs(30);

/// `ERROR_SERVICE_DOES_NOT_EXIST`.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
/// `ERROR_ACCESS_DENIED`.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_SERVICE_NOT_ACTIVE`.
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
/// `ERROR_SERVICE_ALREADY_RUNNING`.
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
/// `ERROR_DEPENDENT_SERVICES_RUNNING`.
const ERROR_DEPENDENT_SERVICES_RUNNING: i32 = 1051;
/// `ERROR_SERVICE_CANNOT_ACCEPT_CTRL`.
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;
/// `ERROR_SERVICE_DISABLED`.
const ERROR_SERVICE_DISABLED: i32 = 1058;

/// `dwCurrentState` of a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// `SERVICE_STOPPED` (1).
    Stopped,
    /// `SERVICE_START_PENDING` (2).
    StartPending,
    /// `SERVICE_STOP_PENDING` (3).
    StopPending,
    /// `SERVICE_RUNNING` (4).
    Running,
    /// `SERVICE_CONTINUE_PENDING` (5).
    ContinuePending,
    /// `SERVICE_PAUSE_PENDING` (6).
    PausePending,
    /// `SERVICE_PAUSED` (7).
    Paused,
}

impl RunState {
    /// Maps a raw `dwCurrentState`. `None` for any other value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            1 => Self::Stopped,
            2 => Self::StartPending,
            3 => Self::StopPending,
            4 => Self::Running,
            5 => Self::ContinuePending,
            6 => Self::PausePending,
            7 => Self::Paused,
            _ => return None,
        })
    }
}

/// Start type of a service. Driver start types are not representable: a
/// query that returns them is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartType {
    /// `SERVICE_AUTO_START` without the delayed flag.
    Automatic,
    /// `SERVICE_AUTO_START` with the delayed flag.
    AutomaticDelayed,
    /// `SERVICE_DEMAND_START`.
    Manual,
    /// `SERVICE_DISABLED`.
    Disabled,
}

impl StartType {
    /// Every value, for tests and for the record format.
    pub const ALL: [Self; 4] = [
        Self::Automatic,
        Self::AutomaticDelayed,
        Self::Manual,
        Self::Disabled,
    ];

    /// Name in `restore.json` and in the log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::AutomaticDelayed => "automatic_delayed",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        }
    }

    /// Maps a raw `dwStartType` and the delayed flag.
    ///
    /// # Errors
    /// [`SvcError::UnsupportedStartType`] for boot, system or any unknown
    /// value. They are driver-only and `w32time` never has them.
    pub const fn from_raw(raw: u32, delayed: bool) -> Result<Self, SvcError> {
        match (raw, delayed) {
            (2, false) => Ok(Self::Automatic),
            (2, true) => Ok(Self::AutomaticDelayed),
            (3, _) => Ok(Self::Manual),
            (4, _) => Ok(Self::Disabled),
            _ => Err(SvcError::UnsupportedStartType(raw)),
        }
    }

    /// The raw `dwStartType` and, for the auto types, the delayed flag.
    #[must_use]
    pub const fn to_raw(self) -> (u32, Option<bool>) {
        match self {
            Self::Automatic => (2, Some(false)),
            Self::AutomaticDelayed => (2, Some(true)),
            Self::Manual => (3, None),
            Self::Disabled => (4, None),
        }
    }
}

/// What a query sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvcState {
    /// Current run state.
    pub run: RunState,
    /// Start type that applies at the next start.
    pub start: StartType,
}

/// A service control failure. Text names no path, machine or user.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SvcError {
    /// The service does not exist.
    #[error("service is not installed")]
    NotFound,
    /// Access denied. Usually not elevated.
    #[error("access denied by the service control manager")]
    AccessDenied,
    /// The service is not running.
    #[error("service is not running")]
    NotActive,
    /// The service is already running.
    #[error("service is already running")]
    AlreadyRunning,
    /// Running services depend on it. We never stop dependents.
    #[error("other running services depend on this service")]
    DependentsRunning,
    /// The service is in a state that takes no control now.
    #[error("service cannot accept the request in its current state")]
    CannotAcceptControl,
    /// The service is disabled and cannot be started.
    #[error("service is disabled")]
    Disabled,
    /// Boot, system or an unknown start type.
    #[error("service has an unsupported start type {0}")]
    UnsupportedStartType(u32),
    /// An unknown run state value.
    #[error("service reported an unknown state {0}")]
    UnknownState(u32),
    /// Any other OS error.
    #[error("service {op} failed with OS error {code}")]
    Os {
        /// What was being done.
        op: &'static str,
        /// The Win32 error code.
        code: i32,
    },
}

impl SvcError {
    /// Maps a Win32 error code from operation `op`.
    #[must_use]
    pub const fn from_code(op: &'static str, code: i32) -> Self {
        match code {
            ERROR_SERVICE_DOES_NOT_EXIST => Self::NotFound,
            ERROR_ACCESS_DENIED => Self::AccessDenied,
            ERROR_SERVICE_NOT_ACTIVE => Self::NotActive,
            ERROR_SERVICE_ALREADY_RUNNING => Self::AlreadyRunning,
            ERROR_DEPENDENT_SERVICES_RUNNING => Self::DependentsRunning,
            ERROR_SERVICE_CANNOT_ACCEPT_CTRL => Self::CannotAcceptControl,
            ERROR_SERVICE_DISABLED => Self::Disabled,
            _ => Self::Os { op, code },
        }
    }
}

/// Control of one service by name. The real one is [`ScmControl`].
pub trait ServiceControl {
    /// Reads the run state and start type. Read only.
    ///
    /// # Errors
    /// [`SvcError`].
    fn query(&self, name: &str) -> Result<SvcState, SvcError>;

    /// Asks the service to stop. Does not wait.
    ///
    /// # Errors
    /// [`SvcError`], for example [`SvcError::NotActive`].
    fn stop(&mut self, name: &str) -> Result<(), SvcError>;

    /// Starts the service. Does not wait. Added to the brief's trait: an
    /// uninstall must start `w32time` again if it was running.
    ///
    /// # Errors
    /// [`SvcError`], for example [`SvcError::AlreadyRunning`].
    fn start(&mut self, name: &str) -> Result<(), SvcError>;

    /// Sets the start type.
    ///
    /// # Errors
    /// [`SvcError`].
    fn set_start_type(&mut self, name: &str, t: StartType) -> Result<(), SvcError>;

    /// Waits between polls. The fake overrides it, so tests do not sleep.
    fn pause(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// What restore needs: the start type and whether it was running. The
/// service name is not stored. It is always [`W32TIME`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restore {
    start: StartType,
    was_running: bool,
}

/// Why a `restore.json` was refused. Holds no file text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RestoreFormatError {
    /// Larger than [`Restore::MAX_BYTES`].
    #[error("restore record is too large")]
    TooLarge,
    /// Not one of the canonical records.
    #[error("restore record is not in the expected format")]
    NotCanonical,
}

impl Restore {
    /// Largest file read. A real record is under 100 bytes.
    pub const MAX_BYTES: usize = 512;

    /// A record of `start` and `was_running`.
    #[must_use]
    pub const fn new(start: StartType, was_running: bool) -> Self {
        Self { start, was_running }
    }

    /// The record of a queried state. Anything but stopped counts as
    /// running, so a pending service is started again on restore.
    #[must_use]
    pub const fn from_state(s: SvcState) -> Self {
        Self::new(s.start, !matches!(s.run, RunState::Stopped))
    }

    /// The original start type.
    #[must_use]
    pub const fn start_type(&self) -> StartType {
        self.start
    }

    /// Whether `w32time` was running before the takeover.
    #[must_use]
    pub const fn was_running(&self) -> bool {
        self.was_running
    }

    /// The canonical `restore.json` text, newline included.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{{\"version\":1,\"service\":\"{W32TIME}\",\"start_type\":\"{}\",\"was_running\":{}}}\n",
            self.start.as_str(),
            self.was_running
        )
    }

    /// Reads a record. Only the exact canonical text of one of the eight
    /// possible records is accepted, with or without its final newline.
    /// That refuses another service name, an unknown start type, a wrong
    /// version, duplicate keys, extra space and truncation in one rule.
    ///
    /// # Errors
    /// [`RestoreFormatError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RestoreFormatError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(RestoreFormatError::TooLarge);
        }
        for start in StartType::ALL {
            for was_running in [false, true] {
                let r = Self::new(start, was_running);
                let canon = r.encode();
                let canon = canon.as_bytes();
                if bytes == canon || bytes == &canon[..canon.len() - 1] {
                    return Ok(r);
                }
            }
        }
        Err(RestoreFormatError::NotCanonical)
    }
}

/// Polling of a stop. Default: 120 polls of 250 ms, so 30 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Most status polls after a stop.
    pub polls: u32,
    /// Wait between polls.
    pub interval: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            polls: 120,
            interval: Duration::from_millis(250),
        }
    }
}

/// Why a takeover failed. What was changed is in the variant docs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TakeoverError {
    /// The first query failed. Nothing changed.
    #[error("cannot read the w32time state: {0}")]
    Query(SvcError),
    /// The record could not be saved. Nothing changed.
    #[error("cannot save the w32time restore record: {0}")]
    Persist(String),
    /// The stop was refused. Nothing changed.
    #[error("w32time refused to stop: {0}")]
    Stop(SvcError),
    /// The stop was sent and `w32time` did not reach stopped in time. It may
    /// still stop. The start type was not changed.
    #[error("w32time did not stop in time")]
    StopTimeout,
    /// A status poll failed while waiting for the stop.
    #[error("cannot read the w32time state while it stops: {0}")]
    StopQuery(SvcError),
    /// `w32time` stopped and could not be disabled. A rollback start was
    /// tried if it was running. `rollback` holds its error, if any.
    #[error("cannot disable w32time: {error}{}", rollback_text(rollback.as_ref()))]
    Disable {
        /// The disable error.
        error: SvcError,
        /// The rollback start error.
        rollback: Option<SvcError>,
    },
    /// The check after the takeover could not read the state.
    #[error("cannot verify the w32time state: {0}")]
    VerifyQuery(SvcError),
    /// After the takeover `w32time` is not stopped and disabled. Policy or a
    /// trigger may have started it again.
    #[error("w32time is not stopped and disabled after the takeover")]
    VerifyMismatch(SvcState),
}

fn rollback_text(e: Option<&SvcError>) -> String {
    e.map_or_else(String::new, |e| {
        format!(". Starting it again also failed: {e}")
    })
}

/// Takes over with the default [`Timing`]. See [`take_over_with`].
///
/// # Errors
/// [`TakeoverError`].
pub fn take_over<C, P>(
    ctl: &mut C,
    existing: Option<Restore>,
    persist: P,
) -> Result<Restore, TakeoverError>
where
    C: ServiceControl + ?Sized,
    P: FnOnce(&Restore) -> Result<(), String>,
{
    take_over_with(ctl, existing, persist, Timing::default())
}

/// Stops and disables `w32time` and returns the record to restore it.
///
/// `existing` is a record already on disk from an earlier install. It wins
/// over the current state and is not persisted again. Without it the record
/// is built from a query and handed to `persist` before anything changes.
///
/// # Errors
/// [`TakeoverError`]. Each variant says what was changed.
pub fn take_over_with<C, P>(
    ctl: &mut C,
    existing: Option<Restore>,
    persist: P,
    timing: Timing,
) -> Result<Restore, TakeoverError>
where
    C: ServiceControl + ?Sized,
    P: FnOnce(&Restore) -> Result<(), String>,
{
    let now = ctl.query(W32TIME).map_err(TakeoverError::Query)?;
    let record = if let Some(r) = existing {
        r
    } else {
        let r = Restore::from_state(now);
        persist(&r).map_err(TakeoverError::Persist)?;
        r
    };

    if now.run != RunState::Stopped {
        // A stop already in progress needs no second request.
        if now.run != RunState::StopPending {
            match ctl.stop(W32TIME) {
                Ok(()) | Err(SvcError::NotActive) => {}
                Err(e) => return Err(TakeoverError::Stop(e)),
            }
        }
        wait_stopped(ctl, timing)?;
    }

    if let Err(error) = ctl.set_start_type(W32TIME, StartType::Disabled) {
        let rollback = if record.was_running {
            match ctl.start(W32TIME) {
                Ok(()) | Err(SvcError::AlreadyRunning) => None,
                Err(e) => Some(e),
            }
        } else {
            None
        };
        return Err(TakeoverError::Disable { error, rollback });
    }

    let after = ctl.query(W32TIME).map_err(TakeoverError::VerifyQuery)?;
    if after.run != RunState::Stopped || after.start != StartType::Disabled {
        return Err(TakeoverError::VerifyMismatch(after));
    }
    Ok(record)
}

fn wait_stopped<C: ServiceControl + ?Sized>(ctl: &mut C, t: Timing) -> Result<(), TakeoverError> {
    for _ in 0..=t.polls {
        let s = ctl.query(W32TIME).map_err(TakeoverError::StopQuery)?;
        if s.run == RunState::Stopped {
            return Ok(());
        }
        ctl.pause(t.interval);
    }
    Err(TakeoverError::StopTimeout)
}

/// What [`restore`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// `w32time` was started, or was already running.
    pub started: bool,
    /// It was running before, but its original start type is `Disabled`, so
    /// it cannot be started. It was left stopped.
    pub start_skipped_disabled: bool,
}

/// Why a restore failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RestoreError {
    /// The start type could not be set. Nothing else was tried.
    #[error("cannot set the w32time start type: {0}")]
    SetStartType(SvcError),
    /// The start type was set and the start failed.
    #[error("w32time start type restored, but it did not start: {0}")]
    Start(SvcError),
}

/// Puts `w32time` back as the record says. Idempotent.
///
/// The start type is set first. Then `w32time` is started only if it was
/// running and its original start type allows a start. An uninstall puts
/// things back as they were, including a running `w32time`.
///
/// # Errors
/// [`RestoreError`].
pub fn restore<C: ServiceControl + ?Sized>(
    ctl: &mut C,
    record: &Restore,
) -> Result<RestoreOutcome, RestoreError> {
    ctl.set_start_type(W32TIME, record.start)
        .map_err(RestoreError::SetStartType)?;
    if !record.was_running {
        return Ok(RestoreOutcome {
            started: false,
            start_skipped_disabled: false,
        });
    }
    if record.start == StartType::Disabled {
        return Ok(RestoreOutcome {
            started: false,
            start_skipped_disabled: true,
        });
    }
    match ctl.start(W32TIME) {
        Ok(()) | Err(SvcError::AlreadyRunning) => Ok(RestoreOutcome {
            started: true,
            start_skipped_disabled: false,
        }),
        Err(e) => Err(RestoreError::Start(e)),
    }
}

/// Whether `w32time` may be adjusting the clock. True for every state but
/// stopped, and true when the state cannot be read: when we cannot tell, the
/// engine must not adjust.
#[must_use]
pub fn is_running<C: ServiceControl + ?Sized>(ctl: &C) -> bool {
    !matches!(
        ctl.query(W32TIME),
        Ok(SvcState {
            run: RunState::Stopped,
            ..
        })
    )
}

/// What the host does after one monitor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorDecision {
    /// Send `AdjustmentAllowed(adjustment_allowed)`. Always, every period:
    /// the event is a level and the engine expects it re-sent.
    pub adjustment_allowed: bool,
    /// The running state changed since the last check, or this is the first
    /// check. Log it then, and only then.
    pub changed: bool,
}

/// The pure rule behind the 30 s monitor. `prev_running` is the last result
/// of [`is_running`], `None` before the first check.
///
/// After a clock failure the engine latches adjustment off (R39). Only
/// `AdjustmentAllowed(false)` then `AdjustmentAllowed(true)` reopens it. That
/// is the host's job and does not change this rule.
#[must_use]
pub fn monitor_decision(prev_running: Option<bool>, now_running: bool) -> MonitorDecision {
    MonitorDecision {
        adjustment_allowed: !now_running,
        changed: prev_running != Some(now_running),
    }
}

/// The real service control manager. Each call opens its own handle with
/// only the rights it needs. `query` asks for `SERVICE_QUERY_STATUS |
/// SERVICE_QUERY_CONFIG` and nothing more.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ScmControl;

#[cfg(windows)]
fn os_err(op: &'static str, e: &std::io::Error) -> SvcError {
    // An error without a code is not a Win32 error. -1 marks it.
    SvcError::from_code(op, e.raw_os_error().unwrap_or(-1))
}

#[cfg(windows)]
impl ServiceControl for ScmControl {
    fn query(&self, name: &str) -> Result<SvcState, SvcError> {
        use crate::win32::scm;
        let s = scm::open_query(name).map_err(|e| os_err("open", &e))?;
        let raw = scm::current_state(&s).map_err(|e| os_err("status query", &e))?;
        let run = RunState::from_raw(raw).ok_or(SvcError::UnknownState(raw))?;
        let raw_start = scm::start_type(&s).map_err(|e| os_err("config query", &e))?;
        // The delayed flag means something only for auto start (Learn).
        let delayed = if raw_start == StartType::Automatic.to_raw().0 {
            scm::delayed_auto_start(&s).map_err(|e| os_err("delayed start query", &e))?
        } else {
            false
        };
        let start = StartType::from_raw(raw_start, delayed)?;
        Ok(SvcState { run, start })
    }

    fn stop(&mut self, name: &str) -> Result<(), SvcError> {
        use crate::win32::scm;
        let s = scm::open_stop(name).map_err(|e| os_err("open", &e))?;
        scm::send_stop(&s).map_err(|e| os_err("stop", &e))
    }

    fn start(&mut self, name: &str) -> Result<(), SvcError> {
        use crate::win32::scm;
        let s = scm::open_start(name).map_err(|e| os_err("open", &e))?;
        scm::start(&s).map_err(|e| os_err("start", &e))
    }

    fn set_start_type(&mut self, name: &str, t: StartType) -> Result<(), SvcError> {
        use crate::win32::scm;
        let s = scm::open_change_config(name).map_err(|e| os_err("open", &e))?;
        let (raw, delayed) = t.to_raw();
        scm::set_start_type(&s, raw).map_err(|e| os_err("set start type", &e))?;
        if let Some(d) = delayed {
            scm::set_delayed_auto_start(&s, d).map_err(|e| os_err("set delayed start", &e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, windows))]
mod live_tests;
