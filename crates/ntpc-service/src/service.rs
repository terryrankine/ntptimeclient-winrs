//! The Windows service wrapper: status reporting, the control handler and
//! the `ServiceMain` body, all above a [`StatusApi`] seam so the state
//! machine is tested without the SCM.
//!
//! Life of the service (facts and sources: `docs/architecture.md`, "Service
//! wrapper (Task 14c-B)"):
//! 1. `ServiceMain` registers the control handler, then reports
//!    `START_PENDING` with a wait hint. No control is accepted yet (Learn,
//!    `SetServiceStatus` best practices).
//! 2. It checks the config and that the host adapters are built. A failure
//!    reports `STOPPED` with a service-specific exit code
//!    ([`service_exit`]).
//! 3. It starts the host on its own thread and reports `RUNNING`, accepting
//!    STOP, SHUTDOWN and POWEREVENT.
//! 4. STOP or SHUTDOWN: the handler reports `STOP_PENDING`, calls
//!    [`HostControl::shutdown`] and returns at once. It never blocks.
//! 5. `ServiceMain` waits for the host, bumping the checkpoint about once a
//!    second, for at most [`Timing::stop_budget`]. The host joins no
//!    blocked worker, so it returns quickly. If it does not, the wrapper
//!    gives up and stops anyway.
//! 6. It flushes the Event Log and reports `STOPPED` once, with the exit
//!    code. Nothing runs after that.
//!
//! Reports never go backwards and `STOPPED` is sent once. Checkpoints count
//! up while a state is pending and are zero otherwise.
//!
//! Resume: `PBT_APMRESUMEAUTOMATIC` always marks a resume (Learn: "sent
//! every time the system resumes"). `PBT_APMRESUMESUSPEND` follows it when a
//! user woke the machine, so it marks a resume only if no automatic resume
//! was seen since the last suspend. One sleep gives one `Resumed`, so the
//! engine allows one step, not two.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::host::{HostControl, HostError, Inbox, PowerEvents};
use crate::logging::{Level, Logger};

/// Win32 values used here (Learn, `SERVICE_STATUS` and `HandlerEx`).
pub mod raw {
    /// `SERVICE_STOPPED`.
    pub const STOPPED: u32 = 1;
    /// `SERVICE_START_PENDING`.
    pub const START_PENDING: u32 = 2;
    /// `SERVICE_STOP_PENDING`.
    pub const STOP_PENDING: u32 = 3;
    /// `SERVICE_RUNNING`.
    pub const RUNNING: u32 = 4;
    /// `SERVICE_ACCEPT_STOP`.
    pub const ACCEPT_STOP: u32 = 0x1;
    /// `SERVICE_ACCEPT_SHUTDOWN`.
    pub const ACCEPT_SHUTDOWN: u32 = 0x4;
    /// `SERVICE_ACCEPT_POWEREVENT`.
    pub const ACCEPT_POWEREVENT: u32 = 0x40;
    /// `SERVICE_CONTROL_STOP`.
    pub const CONTROL_STOP: u32 = 1;
    /// `SERVICE_CONTROL_INTERROGATE`.
    pub const CONTROL_INTERROGATE: u32 = 4;
    /// `SERVICE_CONTROL_SHUTDOWN`.
    pub const CONTROL_SHUTDOWN: u32 = 5;
    /// `SERVICE_CONTROL_POWEREVENT`.
    pub const CONTROL_POWEREVENT: u32 = 13;
    /// `PBT_APMSUSPEND`.
    pub const PBT_APMSUSPEND: u32 = 4;
    /// `PBT_APMRESUMESUSPEND`.
    pub const PBT_APMRESUMESUSPEND: u32 = 7;
    /// `PBT_APMRESUMEAUTOMATIC`.
    pub const PBT_APMRESUMEAUTOMATIC: u32 = 18;
    /// `NO_ERROR`.
    pub const NO_ERROR: u32 = 0;
    /// `ERROR_CALL_NOT_IMPLEMENTED`: the answer for a control we do not
    /// handle.
    pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    /// `ERROR_SERVICE_SPECIFIC_ERROR`: the exit code is in
    /// `dwServiceSpecificExitCode`.
    pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;
}

/// Service-specific exit codes, reported in `dwServiceSpecificExitCode`.
/// The SCM logs a non-zero stop as event 7023 and, with the failure
/// actions flag set at install, restarts the service.
pub mod service_exit {
    /// Normal stop.
    pub const OK: u32 = 0;
    /// The config file could not be read or breaks a rule.
    pub const CONFIG: u32 = 1;
    /// The Windows host adapters are not built into this exe.
    pub const HOST_NOT_BUILT: u32 = 2;
    /// The host loop or its shutdown panicked.
    pub const PANICKED: u32 = 3;
    /// The host did not finish within the stop budget.
    pub const STOP_TIMEOUT: u32 = 4;
    /// The host ended without being asked to.
    pub const ENDED_UNASKED: u32 = 5;
    /// The host thread could not be started.
    pub const THREAD: u32 = 6;
    /// Building the host adapters failed at run time.
    pub const DEPS_FAILED: u32 = 7;
}

/// A reported state. The order is the only order reports may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// Starting.
    StartPending,
    /// Running.
    Running,
    /// Stopping.
    StopPending,
    /// Stopped.
    Stopped,
}

impl State {
    const fn raw(self) -> u32 {
        match self {
            State::StartPending => raw::START_PENDING,
            State::Running => raw::RUNNING,
            State::StopPending => raw::STOP_PENDING,
            State::Stopped => raw::STOPPED,
        }
    }

    const fn pending(self) -> bool {
        matches!(self, State::StartPending | State::StopPending)
    }
}

/// One status report, in `SERVICE_STATUS` terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The state.
    pub state: State,
    /// `dwCurrentState`.
    pub raw_state: u32,
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

/// Sends a report to the SCM. The real one wraps `SetServiceStatus`.
pub trait StatusApi: Send + Sync {
    /// Sends one report.
    ///
    /// # Errors
    /// The OS error code. The wrapper logs it and goes on.
    fn set(&self, r: &Report) -> Result<(), i32>;
}

/// Wait hints and budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// `dwWaitHint` while starting.
    pub start_hint: Duration,
    /// `dwWaitHint` while stopping.
    pub stop_hint: Duration,
    /// How long the wrapper waits for the host after a stop. Below
    /// `stop_hint` and below the about 20 s Learn gives at shutdown.
    pub stop_budget: Duration,
    /// How often the waiting thread looks up and bumps the checkpoint.
    pub poll: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            start_hint: Duration::from_secs(30),
            stop_hint: Duration::from_secs(20),
            stop_budget: Duration::from_secs(15),
            poll: Duration::from_secs(1),
        }
    }
}

#[derive(Debug)]
struct Inner {
    last: Option<State>,
    checkpoint: u32,
    stop_requested: bool,
    failures: u32,
}

/// Keeps reports in order and counts checkpoints.
pub struct Reporter {
    api: Arc<dyn StatusApi>,
    timing: Timing,
    inner: Mutex<Inner>,
}

fn ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

impl Reporter {
    /// A reporter over `api`.
    #[must_use]
    pub fn new(api: Arc<dyn StatusApi>, timing: Timing) -> Self {
        Self {
            api,
            timing,
            inner: Mutex::new(Inner {
                last: None,
                checkpoint: 0,
                stop_requested: false,
                failures: 0,
            }),
        }
    }

    /// Reports `state`. Refuses to go backwards or to send `Stopped` twice.
    /// The same pending state again bumps the checkpoint. The same
    /// non-pending state again sends nothing. True if a report went out.
    fn send(&self, inner: &mut Inner, state: State, exit: u32) -> bool {
        match inner.last {
            Some(prev) if state < prev => return false,
            Some(prev) if state == prev && !state.pending() => return false,
            Some(prev) if state == prev => inner.checkpoint = inner.checkpoint.saturating_add(1),
            _ => inner.checkpoint = u32::from(state.pending()),
        }
        inner.last = Some(state);
        let accepts = if state == State::Running {
            raw::ACCEPT_STOP | raw::ACCEPT_SHUTDOWN | raw::ACCEPT_POWEREVENT
        } else {
            0
        };
        let wait = match state {
            State::StartPending => ms(self.timing.start_hint),
            State::StopPending => ms(self.timing.stop_hint),
            _ => 0,
        };
        let (win32_exit, specific_exit) = if exit == service_exit::OK {
            (raw::NO_ERROR, 0)
        } else {
            (raw::ERROR_SERVICE_SPECIFIC_ERROR, exit)
        };
        let r = Report {
            state,
            raw_state: state.raw(),
            accepts,
            win32_exit,
            specific_exit,
            checkpoint: if state.pending() { inner.checkpoint } else { 0 },
            wait_hint_ms: wait,
        };
        if self.api.set(&r).is_err() {
            inner.failures += 1;
        }
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `START_PENDING`, or a checkpoint bump while starting.
    pub fn start_pending(&self) {
        let mut i = self.lock();
        self.send(&mut i, State::StartPending, service_exit::OK);
    }

    /// `RUNNING`, unless a stop was asked for already, then `STOP_PENDING`.
    pub fn running(&self) {
        let mut i = self.lock();
        let s = if i.stop_requested {
            State::StopPending
        } else {
            State::Running
        };
        self.send(&mut i, s, service_exit::OK);
    }

    /// Marks a stop. Reports `STOP_PENDING` if running. True the first time.
    pub fn request_stop(&self) -> bool {
        let mut i = self.lock();
        if i.stop_requested {
            return false;
        }
        i.stop_requested = true;
        if i.last == Some(State::Running) {
            self.send(&mut i, State::StopPending, service_exit::OK);
        }
        true
    }

    /// A checkpoint bump while stopping.
    pub fn stop_progress(&self) {
        let mut i = self.lock();
        if i.last == Some(State::StopPending) {
            self.send(&mut i, State::StopPending, service_exit::OK);
        }
    }

    /// `STOPPED` with `exit`. Only the first call reports.
    pub fn stopped(&self, exit: u32) {
        let mut i = self.lock();
        self.send(&mut i, State::Stopped, exit);
    }

    /// Whether a stop was asked for.
    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.lock().stop_requested
    }

    /// Reports the SCM refused.
    #[must_use]
    pub fn failures(&self) -> u32 {
        self.lock().failures
    }
}

/// Resume tracking. Implements [`PowerEvents`] for the host.
#[derive(Debug, Default)]
pub struct PowerTracker {
    pending: AtomicBool,
    auto_seen: AtomicBool,
}

impl PowerTracker {
    /// Applies one power event. True if it marked a resume.
    pub fn on_event(&self, event_type: u32) -> bool {
        match event_type {
            raw::PBT_APMSUSPEND => {
                self.auto_seen.store(false, Ordering::SeqCst);
                false
            }
            raw::PBT_APMRESUMEAUTOMATIC => {
                self.auto_seen.store(true, Ordering::SeqCst);
                self.pending.store(true, Ordering::SeqCst);
                true
            }
            raw::PBT_APMRESUMESUSPEND if !self.auto_seen.load(Ordering::SeqCst) => {
                self.auto_seen.store(true, Ordering::SeqCst);
                self.pending.store(true, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }
}

impl PowerEvents for PowerTracker {
    fn resumed(&self) -> bool {
        self.pending.swap(false, Ordering::SeqCst)
    }
}

/// The [`PowerEvents`] the host gets: a shared [`PowerTracker`].
#[derive(Debug, Clone)]
pub struct SharedPower(pub Arc<PowerTracker>);

impl PowerEvents for SharedPower {
    fn resumed(&self) -> bool {
        self.0.resumed()
    }
}

/// The control handler logic. Never blocks: a report, a channel send and
/// two atomics. The reporter's lock is held only for the report.
pub struct Controller {
    reporter: Arc<Reporter>,
    host: HostControl,
    power: Arc<PowerTracker>,
}

impl Controller {
    /// A controller over these parts.
    #[must_use]
    pub fn new(reporter: Arc<Reporter>, host: HostControl, power: Arc<PowerTracker>) -> Self {
        Self {
            reporter,
            host,
            power,
        }
    }

    /// Handles one control. Returns the `HandlerEx` return code.
    #[must_use]
    pub fn handle(&self, control: u32, event_type: u32) -> u32 {
        match control {
            raw::CONTROL_STOP | raw::CONTROL_SHUTDOWN => {
                // Report first, then ask: the host may finish before the
                // report otherwise, and STOP_PENDING after STOPPED is refused
                // anyway, but the order keeps the log readable.
                self.reporter.request_stop();
                self.host.shutdown();
                raw::NO_ERROR
            }
            raw::CONTROL_INTERROGATE => raw::NO_ERROR,
            raw::CONTROL_POWEREVENT => {
                if self.power.on_event(event_type) {
                    self.host.wake();
                }
                raw::NO_ERROR
            }
            _ => raw::ERROR_CALL_NOT_IMPLEMENTED,
        }
    }
}

/// Why the host job ended with an error.
#[derive(Debug)]
pub enum JobError {
    /// Building the host adapters failed.
    Deps(String),
    /// The host returned an error.
    Host(HostError),
}

/// The host run, built by a [`Launcher`]. Runs on the host thread, which
/// also builds the adapters (they need not be `Send`).
pub type HostJob = Box<dyn FnOnce(Inbox) -> Result<(), JobError> + Send>;

/// Builds the host run. The real one wires the Windows adapters
/// (`windows_deps`, Task 14c-A).
pub trait Launcher: Send + Sync {
    /// Whether the adapters are built into this exe.
    ///
    /// # Errors
    /// Why not.
    fn ready(&self) -> Result<(), String>;

    /// The host run for `cfg`, with these power events and this log.
    fn job(&self, cfg: Config, power: SharedPower, logger: Arc<dyn Logger>) -> HostJob;
}

/// What `ServiceMain` needs besides the reporter.
pub struct ServiceRun {
    /// The loaded config, or why it could not be loaded (no path in it).
    pub config: Result<Config, String>,
    /// Builds the host.
    pub launcher: Arc<dyn Launcher>,
    /// The log (the Event Log in service mode).
    pub logger: Arc<dyn Logger>,
    /// Waits for queued log lines to be written, before `STOPPED`.
    pub drain: Box<dyn Fn(Duration) + Send + Sync>,
}

/// The parts made before the handler is registered.
pub struct ServiceCore {
    /// Shared with the handler.
    pub reporter: Arc<Reporter>,
    /// Shared with the handler.
    pub controller: Arc<Controller>,
    inbox: Inbox,
    power: Arc<PowerTracker>,
    timing: Timing,
}

/// Makes the reporter, controller and host channel.
#[must_use]
pub fn new_core(api: Arc<dyn StatusApi>, timing: Timing) -> ServiceCore {
    let reporter = Arc::new(Reporter::new(api, timing));
    let (control, inbox) = crate::host::channel();
    let power = Arc::new(PowerTracker::default());
    let controller = Arc::new(Controller::new(reporter.clone(), control, power.clone()));
    ServiceCore {
        reporter,
        controller,
        inbox,
        power,
        timing,
    }
}

/// The text of a panic payload.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with no message".to_owned())
}

fn log(logger: &dyn Logger, level: Level, msg: &str) {
    logger.log(level, "service", msg);
}

/// The `ServiceMain` body. Returns the service-specific exit code it
/// reported with `STOPPED`. Takes `run` by value: the run belongs to this
/// one service start.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn run_service(core: ServiceCore, run: ServiceRun) -> u32 {
    let ServiceCore {
        reporter,
        controller: _,
        inbox,
        power,
        timing,
    } = core;
    reporter.start_pending();
    let exit_code = start_and_wait(&reporter, inbox, power, timing, &run);
    log(
        run.logger.as_ref(),
        if exit_code == service_exit::OK {
            Level::Info
        } else {
            Level::Error
        },
        &format!("service stopped, exit code {exit_code}"),
    );
    run.logger.flush();
    (run.drain)(Duration::from_secs(2));
    reporter.stopped(exit_code);
    exit_code
}

fn start_and_wait(
    reporter: &Reporter,
    inbox: Inbox,
    power: Arc<PowerTracker>,
    timing: Timing,
    run: &ServiceRun,
) -> u32 {
    let logger = run.logger.as_ref();
    let cfg = match &run.config {
        Ok(c) => c.clone(),
        Err(e) => {
            log(logger, Level::Error, &format!("cannot start: {e}"));
            return service_exit::CONFIG;
        }
    };
    if let Err(e) = cfg.validate() {
        log(logger, Level::Error, &format!("cannot start: {e}"));
        return service_exit::CONFIG;
    }
    if let Err(e) = run.launcher.ready() {
        log(logger, Level::Error, &format!("cannot start: {e}"));
        return service_exit::HOST_NOT_BUILT;
    }
    if reporter.stop_requested() {
        return service_exit::OK;
    }
    reporter.start_pending();

    let job = run
        .launcher
        .job(cfg, SharedPower(power), run.logger.clone());
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("ntpc-host".to_owned())
        .spawn(move || {
            let r = catch_unwind(AssertUnwindSafe(|| job(inbox))).unwrap_or_else(|p| {
                Err(JobError::Host(HostError::Panicked(panic_text(p.as_ref()))))
            });
            let _ = tx.send(r);
        });
    if let Err(e) = spawned {
        log(
            logger,
            Level::Error,
            &format!("cannot start the host thread: {}", e.kind()),
        );
        return service_exit::THREAD;
    }
    reporter.running();
    log(logger, Level::Info, "service running");

    let mut stop_seen: Option<Instant> = None;
    let result = loop {
        match rx.recv_timeout(timing.poll) {
            Ok(r) => break Some(r),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break None,
        }
        if reporter.stop_requested() {
            let since = *stop_seen.get_or_insert_with(Instant::now);
            if since.elapsed() >= timing.stop_budget {
                log(
                    logger,
                    Level::Error,
                    "the host did not stop in time. Stopping anyway. The next start resets \
                     the clock rate",
                );
                return service_exit::STOP_TIMEOUT;
            }
            reporter.stop_progress();
        }
    };
    match result {
        Some(Ok(())) if reporter.stop_requested() => service_exit::OK,
        Some(Ok(())) => {
            log(logger, Level::Error, "the host ended without being asked");
            service_exit::ENDED_UNASKED
        }
        Some(Err(JobError::Deps(e))) => {
            log(
                logger,
                Level::Error,
                &format!("building the host adapters failed: {e}"),
            );
            service_exit::DEPS_FAILED
        }
        Some(Err(JobError::Host(HostError::Config(e)))) => {
            log(logger, Level::Error, &format!("cannot start: {e}"));
            service_exit::CONFIG
        }
        Some(Err(JobError::Host(HostError::Panicked(m)))) => {
            log(logger, Level::Error, &format!("the host panicked: {m}"));
            service_exit::PANICKED
        }
        None => service_exit::PANICKED,
    }
}

/// Runs a host job in the console (`run` mode): the host on this thread,
/// `shutdown` on Ctrl+C from the caller's handler.
///
/// # Errors
/// [`JobError`].
pub fn run_console(
    launcher: &dyn Launcher,
    cfg: Config,
    logger: Arc<dyn Logger>,
    inbox: Inbox,
) -> Result<(), JobError> {
    launcher.ready().map_err(JobError::Deps)?;
    // No power events in a console: the machine's resume reaches the host
    // only in service mode.
    let job = launcher.job(cfg, SharedPower(Arc::new(PowerTracker::default())), logger);
    job(inbox)
}

mod launcher;
pub use launcher::{BuildDeps, DepsLauncher, NOT_BUILT};

#[cfg(windows)]
pub mod real;

#[cfg(test)]
mod tests;
