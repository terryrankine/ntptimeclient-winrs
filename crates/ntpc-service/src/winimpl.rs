//! Windows implementations of the host traits (Task 14c-A), over
//! `ntpc-platform`. No `unsafe` here: every OS call is in the platform
//! crate.
//!
//! [`windows_deps`] builds everything [`crate::host::run`] needs. It does
//! not start the loop. The service wrapper (14c-B) calls it on the thread
//! that will run the host, because [`HostDeps`] holds boxed traits without
//! a `Send` bound, then calls `run(cfg, deps.deps, deps.inbox)`.
//!
//! Order at start, and why:
//! 1. The state directory is secured first, before any file in it is
//!    opened, the log included. A log handle opened in a weak directory
//!    would block its replacement (R78: a delete-pending file still lists).
//!    The host's own [`StateDir::secure`] call then returns that outcome.
//! 2. The log gets the file sink only when the directory is secured (R100:
//!    `service.log` and `service.log.1` live there). With persistence off
//!    the log goes to the caller's sinks only, for example the Event Log.
//! 3. The clock is opened. Failure is fatal: without the right to set the
//!    clock the service has nothing to do.
//!
//! Waking the loop: the host polls [`NetworkEvents`] and [`PowerEvents`]
//! once per loop turn. The address watcher thread wakes it itself. For
//! resume, the service control handler (14c-B) calls
//! [`ResumeNotifier::notify_resumed`] from [`WindowsDeps::resume`] on
//! `SERVICE_CONTROL_POWEREVENT` with `PBT_APMRESUMEAUTOMATIC` (and
//! `PBT_APMRESUMESUSPEND`, which may follow it). That sets the flag the
//! host reads and wakes the loop. A second notify before the loop runs
//! gives one resume, which is what the engine wants.

// Windows only. Declared here so `lib.rs` keeps one plain `mod` line.
#![cfg(windows)]

mod clock;
mod events;
mod monitor;
mod net;
mod state_dir;

#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;

use ntpc_core::ClockError;
use thiserror::Error;

pub use clock::{PlatformClock, WinClockControl, WinTimeSource};
pub use events::{NoNetworkEvents, ResumeNotifier, WinNetworkEvents, WinPowerEvents, power_events};
pub use monitor::{W32TimeMonitor, WinJoinState, join_class};
pub use net::{WinDhcpSource, WinOwnAddresses, WinThreadTuning, dhcp_read};
pub use state_dir::{WinStateDir, refusal_reason, secure_outcome};

use crate::config::Config;
use crate::drift_store::FileDriftStore;
use crate::host::{
    HostControl, HostDeps, Inbox, NetworkEvents, RealWaiter, SecureOutcome, StateDir, ThreadSpawn,
    channel,
};
use crate::logging::{DEFAULT_MAX_FILE_BYTES, FileSink, Level, LineLogger, LogSink, Logger};
use crate::resolver::SystemLookup;
use crate::status::FileStatusWriter;
use crate::transport::{TimeSource, UdpTransport};

/// The log file in the state directory. Rotated once to `service.log.1`.
/// Both names are in `ntpc_platform::KNOWN_CHILDREN` (R100).
pub const LOG_FILE_NAME: &str = "service.log";

/// What [`windows_deps`] built.
pub struct WindowsDeps {
    /// For [`crate::host::run`].
    pub deps: HostDeps,
    /// For [`crate::host::run`].
    pub inbox: Inbox,
    /// Stops or wakes the loop. The service stop handler calls
    /// [`HostControl::shutdown`].
    pub control: HostControl,
    /// The power event hook for the service control handler.
    pub resume: ResumeNotifier,
    /// The state directory was secured. False means no drift, status or
    /// log file. The host logs the reason.
    pub persistence: bool,
}

/// Why the Windows dependencies could not be built.
#[derive(Debug, Error)]
pub enum WinDepsError {
    /// The clock could not be opened, usually for a missing privilege. The
    /// text holds no path.
    #[error("the system clock could not be opened: {0}")]
    Clock(#[from] ClockError),
    /// No log sink was given. Without one even a refusal line would be
    /// lost, so the build stops first.
    #[error("no log sink was given, so nothing could be logged")]
    NoSinks,
    /// The process token gives new files an owner other than SYSTEM or
    /// Administrators (R106). Every second start would then replace the
    /// state directory and lose the log and the drift. Run as SYSTEM.
    #[error(
        "the service account gives new files an owner other than SYSTEM or Administrators. Run the service as LocalSystem"
    )]
    UntrustedAccount,
    /// The process token could not be read. The OS error kind only.
    #[error("the service account could not be checked: {0}")]
    AccountUnreadable(std::io::ErrorKind),
}

/// The R106 decision on the token's default owner, apart from the OS read.
///
/// # Errors
/// [`WinDepsError::UntrustedAccount`] for any other owner,
/// [`WinDepsError::AccountUnreadable`] if it could not be read. Unknown is
/// refused: the cost of a wrong guess is lost data every second start.
pub fn check_account(owner_trusted: std::io::Result<bool>) -> Result<(), WinDepsError> {
    match owner_trusted {
        Ok(true) => Ok(()),
        Ok(false) => Err(WinDepsError::UntrustedAccount),
        Err(e) => Err(WinDepsError::AccountUnreadable(e.kind())),
    }
}

/// Writes every line to each sink in turn.
pub struct TeeSink(Vec<Box<dyn LogSink>>);

impl TeeSink {
    /// A sink over `sinks`, in that order.
    #[must_use]
    pub fn new(sinks: Vec<Box<dyn LogSink>>) -> Self {
        Self(sinks)
    }
}

impl LogSink for TeeSink {
    fn write_line(&self, line: &str) {
        for s in &self.0 {
            s.write_line(line);
        }
    }
}

/// The logger: `sinks` plus the file sink in `state_dir` when the
/// directory is secured.
#[must_use]
pub fn build_logger(
    outcome: SecureOutcome,
    state_dir: &Path,
    mut sinks: Vec<Box<dyn LogSink>>,
    time: Arc<dyn TimeSource>,
) -> Arc<dyn Logger> {
    if !matches!(outcome, SecureOutcome::Refused { .. }) {
        sinks.push(Box::new(FileSink::new(
            state_dir.join(LOG_FILE_NAME),
            DEFAULT_MAX_FILE_BYTES,
        )));
    }
    Arc::new(LineLogger::new(Box::new(TeeSink::new(sinks)), time))
}

/// Builds the host's dependencies on Windows. `sinks` are the log sinks
/// besides the file, for example the Event Log sink of 14c-B.
///
/// Secures the state directory (see the module notes), opens the clock and
/// subscribes to address changes. It changes no clock, rate, service or
/// ACL outside the state directory, and sends no packet.
///
/// # Errors
/// [`WinDepsError::NoSinks`] for an empty `sinks`, then
/// [`WinDepsError::UntrustedAccount`] or [`WinDepsError::AccountUnreadable`]
/// (R106), all before anything is touched. Then [`WinDepsError::Clock`] if
/// the clock cannot be opened.
pub fn windows_deps(
    cfg: &Config,
    sinks: Vec<Box<dyn LogSink>>,
) -> Result<WindowsDeps, WinDepsError> {
    if sinks.is_empty() {
        return Err(WinDepsError::NoSinks);
    }
    check_account(ntpc_platform::default_owner_is_trusted())?;
    let time: Arc<dyn TimeSource> = Arc::new(WinTimeSource);
    let state = WinStateDir::secure_now(&cfg.state_dir);
    let outcome = state.secure();
    let logger = build_logger(outcome, &cfg.state_dir, sinks, Arc::clone(&time));
    let clock = WinClockControl::new()?;
    log_initial_rate(&clock, &*logger);

    let (control, inbox) = channel();
    let network: Box<dyn NetworkEvents> = match WinNetworkEvents::start(control.clone()) {
        Ok(n) => Box::new(n),
        Err(e) => {
            logger.log(
                Level::Warn,
                "network_watch",
                &format!("{e}. Network changes are seen only on the timers"),
            );
            Box::new(NoNetworkEvents)
        }
    };
    let (power, resume) = power_events(control.clone());
    let tuning = Arc::new(WinThreadTuning::new(Arc::clone(&logger)));
    let deps = HostDeps {
        clock: Box::new(clock),
        transport: Arc::new(UdpTransport::new(
            Arc::clone(&time),
            tuning,
            Arc::clone(&logger),
        )),
        drift: Box::new(FileDriftStore::new(&cfg.state_dir)),
        status: Box::new(FileStatusWriter::new(&cfg.state_dir)),
        lookup: Arc::new(SystemLookup),
        own: Arc::new(WinOwnAddresses::new(Arc::clone(&logger))),
        monitor: Box::new(W32TimeMonitor::new()),
        network,
        power: Box::new(power),
        dhcp: Arc::new(WinDhcpSource::new()),
        state_dir: Box::new(state),
        join: Box::new(WinJoinState),
        logger,
        time: Arc::clone(&time),
        spawn: Arc::new(ThreadSpawn),
        waiter: Box::new(RealWaiter::new(time)),
    };
    Ok(WindowsDeps {
        deps,
        inbox,
        control,
        resume,
        persistence: !matches!(outcome, SecureOutcome::Refused { .. }),
    })
}

/// A rate left by a crashed run or another time service shows here. The
/// host takes the rate at nominal before the first adjustment (R71).
fn log_initial_rate(clock: &WinClockControl, logger: &dyn Logger) {
    let state = clock.initial_state();
    if state.is_nominal() {
        logger.log(Level::Info, "clock", "clock rate at start: nominal");
    } else {
        let ppm = state
            .ppm()
            .map_or_else(|| "unknown".to_owned(), |p| format!("{p:+.3} ppm"));
        logger.log(
            Level::Warn,
            "clock",
            &format!(
                "clock rate at start is not nominal ({ppm}). It is taken at nominal before \
                 the first adjustment"
            ),
        );
    }
}
