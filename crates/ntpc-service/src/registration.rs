//! Our own service registration: `CreateServiceW` and friends.
//!
//! [`ScmRegistration`] implements [`cli::Registration`](crate::cli::Registration)
//! over three seams, so every path is tested with fakes and no test touches
//! the real service control manager or registry:
//! - [`ScmApi`]: create, update, configure, delete, stop, start, query.
//! - [`EventSourceRegistry`]: the Event Log source key.
//! - [`ExeLocator`]: the real path of the running exe and the
//!   administrators-only location check.
//!
//! The service runs as `LocalSystem` with its token cut down to
//! [`REQUIRED_PRIVILEGES`] (R104). Why not `LocalService`: the state
//! directory DACL grants only SYSTEM and Administrators (Task 11), so a
//! low-privilege account could not write its drift, status or restore
//! files. Sources in `docs/architecture.md`, "Service wrapper (Task 14c-B)".

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

use crate::cli::{NotReady, OwnService, Registration};
use crate::event_log::{EventSourceRegistry, register_source, unregister_source};

/// The service name. Pinned with the Task 15 scripts.
pub const SERVICE_NAME: &str = "ntptimeclient-winrs";

/// The display name in `services.msc`.
pub const DISPLAY_NAME: &str = "ntptimeclient-winrs (NTP time client, preview)";

/// The description in `services.msc`. Says what it does and what it
/// replaces, and that it is a preview.
pub const DESCRIPTION: &str = "Keeps the system clock in time with NTP servers: the servers in \
     its config file, then servers offered by DHCP, then pool.ntp.org. Replaces the Windows Time \
     service (w32time) while installed. Unsigned developer preview.";

/// The argument the image path passes, so `main` runs the dispatcher.
pub const SERVICE_ARG: &str = "service";

/// The privileges the service keeps (Learn,
/// `SERVICE_REQUIRED_PRIVILEGES_INFOW`: "the SCM will remove the privileges
/// that are not required from the process token"). `SeChangeNotifyPrivilege`
/// "is never removed", so it is not listed.
pub const REQUIRED_PRIVILEGES: [&str; 1] = ["SeSystemtimePrivilege"];

/// Restart delays after the first, second and later failures. Learn: the
/// last action repeats for every later failure.
pub const RESTART_DELAYS_MS: [u32; 3] = [60_000, 60_000, 300_000];

/// Failure count reset period. One day, a guess: long enough that a crash
/// loop backs off to 5 min, short enough that one crash a week starts at
/// 60 s again.
pub const FAILURE_RESET_S: u32 = 86_400;

/// `SERVICE_SID_TYPE_NONE`. R106: NONE or UNRESTRICTED only, never
/// RESTRICTED. A restricted SID would make the token
/// write-restricted, and the state directory DACL does not name the service
/// SID, so every write would fail. Revisit with the state directory ACL.
pub const SID_TYPE_NONE: u32 = 0;

/// `SERVICE_AUTO_START`.
pub const START_AUTO: u32 = 2;

/// `SERVICE_ERROR_NORMAL`: logged, boot goes on.
pub const ERROR_NORMAL: u32 = 1;

/// Longest exe path accepted, in UTF-16 units. The Windows path limit with
/// the long path prefix is 32,767.
pub const MAX_EXE_PATH: usize = 32_767;

/// How long `stop_service` waits for our service to stop.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting.
const STOP_POLL: Duration = Duration::from_millis(250);

/// Why an exe path cannot become an image path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QuoteError {
    /// Not absolute with a drive letter.
    #[error("the exe path is not an absolute local path")]
    NotLocalAbsolute,
    /// Holds a double quote or a NUL, which would break the quoting.
    #[error("the exe path holds a quote or NUL character")]
    BadCharacter,
    /// Ends in a backslash: inside quotes it would escape the closing quote.
    #[error("the exe path ends in a backslash")]
    TrailingBackslash,
    /// Longer than [`MAX_EXE_PATH`].
    #[error("the exe path is too long")]
    TooLong,
}

/// The image path: the exe in double quotes, then [`SERVICE_ARG`].
///
/// Always quoted: an unquoted path with a space lets Windows try
/// `C:\Program.exe` first (the unquoted service path weakness). Learn
/// (`CreateServiceW`): "If the path contains a space, it must be quoted".
/// Only a plain `X:\...` path is accepted: no UNC share, no `\\?\` prefix
/// (the caller strips it), no relative path.
///
/// # Errors
/// [`QuoteError`].
pub fn quote_image_path(exe: &Path) -> Result<String, QuoteError> {
    let s = exe.to_str().ok_or(QuoteError::BadCharacter)?;
    if s.contains('"') || s.contains('\0') {
        return Err(QuoteError::BadCharacter);
    }
    let b = s.as_bytes();
    let local_abs = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if !local_abs || s.contains('/') {
        return Err(QuoteError::NotLocalAbsolute);
    }
    if s.ends_with('\\') {
        return Err(QuoteError::TrailingBackslash);
    }
    if s.encode_utf16().count() > MAX_EXE_PATH {
        return Err(QuoteError::TooLong);
    }
    Ok(format!("\"{s}\" {SERVICE_ARG}"))
}

/// Strips the `\\?\` prefix that `std::fs::canonicalize` adds to a local
/// drive path. A `\\?\UNC\` or device path stays as it is, so the quoting
/// refuses it.
#[must_use]
pub fn strip_verbatim(p: &Path) -> PathBuf {
    let Some(s) = p.to_str() else {
        return p.to_path_buf();
    };
    match s.strip_prefix(r"\\?\") {
        Some(rest)
            if rest.len() >= 3
                && rest.as_bytes()[0].is_ascii_alphabetic()
                && &rest.as_bytes()[1..3] == br":\" =>
        {
            PathBuf::from(rest)
        }
        _ => p.to_path_buf(),
    }
}

/// Everything the registration passes to the SCM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// Service name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Quoted exe plus [`SERVICE_ARG`].
    pub image_path: String,
    /// Start type.
    pub start_type: u32,
    /// Error control.
    pub error_control: u32,
    /// `None`: `LocalSystem`. The only value used.
    pub account: Option<String>,
    /// Dependencies. None: delayed auto start runs after the network
    /// stack, and the host copes with no network.
    pub dependencies: Vec<String>,
    /// Description.
    pub description: String,
    /// Delayed auto start.
    pub delayed: bool,
    /// Required privileges.
    pub privileges: Vec<String>,
    /// Failure count reset, seconds.
    pub reset_period_s: u32,
    /// Restart delays, milliseconds.
    pub restarts_ms: Vec<u32>,
    /// Failure actions also on a stop with a non-zero exit code.
    pub actions_on_non_crash: bool,
    /// Service SID type.
    pub sid_type: u32,
}

/// Our spec for the exe at `exe`.
///
/// # Errors
/// [`QuoteError`].
pub fn service_spec(exe: &Path) -> Result<ServiceSpec, QuoteError> {
    Ok(ServiceSpec {
        name: SERVICE_NAME.to_owned(),
        display_name: DISPLAY_NAME.to_owned(),
        image_path: quote_image_path(exe)?,
        start_type: START_AUTO,
        error_control: ERROR_NORMAL,
        account: None,
        dependencies: Vec::new(),
        description: DESCRIPTION.to_owned(),
        delayed: true,
        privileges: REQUIRED_PRIVILEGES
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        reset_period_s: FAILURE_RESET_S,
        restarts_ms: RESTART_DELAYS_MS.to_vec(),
        // A host panic or a config error stops with a non-zero code. The
        // flag makes the SCM restart after those too, not only after a crash.
        actions_on_non_crash: true,
        sid_type: SID_TYPE_NONE,
    })
}

/// Run state of a service, as far as registration cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Stopped.
    Stopped,
    /// Running, or starting, stopping, pausing.
    Active,
}

/// A service control failure. No path, machine or user in the text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScmError {
    /// `ERROR_SERVICE_EXISTS` (1073).
    #[error("the service already exists")]
    Exists,
    /// `ERROR_SERVICE_MARKED_FOR_DELETE` (1072).
    #[error("the service is marked for deletion")]
    MarkedForDelete,
    /// `ERROR_SERVICE_DOES_NOT_EXIST` (1060).
    #[error("the service is not installed")]
    NotFound,
    /// `ERROR_SERVICE_NOT_ACTIVE` (1062).
    #[error("the service is not running")]
    NotActive,
    /// `ERROR_SERVICE_ALREADY_RUNNING` (1056).
    #[error("the service is already running")]
    AlreadyRunning,
    /// `ERROR_ACCESS_DENIED` (5).
    #[error("access denied by the service control manager")]
    AccessDenied,
    /// Anything else.
    #[error("{op} failed with OS error {code}")]
    Os {
        /// What was being done.
        op: &'static str,
        /// The Win32 error code.
        code: i32,
    },
}

impl ScmError {
    /// Maps a Win32 error code from operation `op`.
    #[must_use]
    pub const fn from_code(op: &'static str, code: i32) -> Self {
        match code {
            1073 => Self::Exists,
            1072 => Self::MarkedForDelete,
            1060 => Self::NotFound,
            1062 => Self::NotActive,
            1056 => Self::AlreadyRunning,
            5 => Self::AccessDenied,
            _ => Self::Os { op, code },
        }
    }
}

/// The SCM calls registration needs. The real one is [`RealScm`].
pub trait ScmApi {
    /// `CreateServiceW`.
    ///
    /// # Errors
    /// [`ScmError::Exists`] when it is there already.
    fn create(&mut self, spec: &ServiceSpec) -> Result<(), ScmError>;
    /// `ChangeServiceConfigW` on an existing service: path, type, start,
    /// account, display name.
    ///
    /// # Errors
    /// [`ScmError`].
    fn update(&mut self, spec: &ServiceSpec) -> Result<(), ScmError>;
    /// `ChangeServiceConfig2W` for every optional setting in the spec.
    ///
    /// # Errors
    /// The step that failed and why.
    fn configure(&mut self, spec: &ServiceSpec) -> Result<(), (&'static str, ScmError)>;
    /// `DeleteService`.
    ///
    /// # Errors
    /// [`ScmError::NotFound`] when it is not there.
    fn delete(&mut self, name: &str) -> Result<(), ScmError>;
    /// The run state. Read only.
    ///
    /// # Errors
    /// [`ScmError::NotFound`] when it is not there.
    fn run_state(&self, name: &str) -> Result<RunState, ScmError>;
    /// Sends stop. Does not wait.
    ///
    /// # Errors
    /// [`ScmError`].
    fn stop(&mut self, name: &str) -> Result<(), ScmError>;
    /// Starts it. Does not wait.
    ///
    /// # Errors
    /// [`ScmError`].
    fn start(&mut self, name: &str) -> Result<(), ScmError>;
    /// Waits between polls. Fakes override it so tests do not sleep.
    fn pause(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Where the running exe is and whether that place is safe.
pub trait ExeLocator {
    /// The resolved path of the running exe. Never a user-supplied path.
    ///
    /// # Errors
    /// Why it could not be found.
    fn exe(&self) -> Result<PathBuf, String>;
    /// Reasons the location is not administrators-only. Empty means safe.
    fn check(&self, exe: &Path) -> Vec<String>;
}

/// The real [`Registration`].
pub struct ScmRegistration<'a> {
    scm: &'a mut dyn ScmApi,
    events: &'a mut dyn EventSourceRegistry,
    locator: &'a dyn ExeLocator,
    /// Whether the service host itself is built (the Windows adapters).
    /// Installing a service that cannot run would leave the machine with
    /// no time sync, so install refuses until it is.
    host_ready: Result<(), String>,
    stop_timeout: Duration,
}

impl<'a> ScmRegistration<'a> {
    /// A registration over these seams.
    pub fn new(
        scm: &'a mut dyn ScmApi,
        events: &'a mut dyn EventSourceRegistry,
        locator: &'a dyn ExeLocator,
        host_ready: Result<(), String>,
    ) -> Self {
        Self {
            scm,
            events,
            locator,
            host_ready,
            stop_timeout: STOP_TIMEOUT,
        }
    }

    /// Changes the stop wait, for tests.
    #[must_use]
    pub fn with_stop_timeout(mut self, d: Duration) -> Self {
        self.stop_timeout = d;
        self
    }

    fn spec(&self) -> Result<ServiceSpec, String> {
        let exe = self.locator.exe()?;
        service_spec(&exe).map_err(|e| e.to_string())
    }

    /// Deletes a service this run created, after a later step failed.
    fn roll_back(&mut self, created: bool, first: &str) -> String {
        if !created {
            return format!(
                "{first}. The service existed before this run, so it was left registered"
            );
        }
        match self.scm.delete(SERVICE_NAME) {
            Ok(()) | Err(ScmError::NotFound) => {
                format!("{first}. The service this run created was removed again")
            }
            Err(e) => format!(
                "{first}. Removing the service this run created also failed: {e}. Remove it by \
                 hand: sc.exe delete {SERVICE_NAME}"
            ),
        }
    }
}

impl Registration for ScmRegistration<'_> {
    fn ready(&self) -> Result<(), NotReady> {
        self.host_ready.clone().map_err(NotReady::NotBuilt)?;
        let exe = self.locator.exe().map_err(NotReady::NotBuilt)?;
        service_spec(&exe).map_err(|e| NotReady::UnsafeLocation(vec![e.to_string()]))?;
        let reasons = self.locator.check(&exe);
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(NotReady::UnsafeLocation(reasons))
        }
    }

    fn register(&mut self) -> Result<(), String> {
        let spec = self.spec()?;
        let created = match self.scm.create(&spec) {
            Ok(()) => true,
            Err(ScmError::Exists) => {
                // A re-install. Point the existing entry at this exe.
                self.scm
                    .update(&spec)
                    .map_err(|e| format!("updating the existing service failed: {e}"))?;
                false
            }
            Err(ScmError::MarkedForDelete) => {
                return Err(
                    "an earlier removal of the service is still pending. Close the Services \
                     window and any tool that has the service open, or reboot, then run \
                     install again"
                        .to_owned(),
                );
            }
            Err(e) => return Err(format!("creating the service failed: {e}")),
        };
        if let Err((step, e)) = self.scm.configure(&spec) {
            return Err(self.roll_back(created, &format!("setting the {step} failed: {e}")));
        }
        if let Err(e) = register_source(self.events) {
            return Err(self.roll_back(
                created,
                &format!("registering the Event Log source failed: {e}"),
            ));
        }
        Ok(())
    }

    fn stop_service(&mut self) -> Result<OwnService, String> {
        match self.scm.run_state(SERVICE_NAME) {
            Err(ScmError::NotFound) => return Ok(OwnService::Absent),
            Err(e) => return Err(format!("reading the service state failed: {e}")),
            Ok(RunState::Stopped) => return Ok(OwnService::WasStopped),
            Ok(RunState::Active) => {}
        }
        match self.scm.stop(SERVICE_NAME) {
            Ok(()) | Err(ScmError::NotActive) => {}
            Err(e) => return Err(format!("stopping the service failed: {e}")),
        }
        let mut waited = Duration::ZERO;
        loop {
            match self.scm.run_state(SERVICE_NAME) {
                Ok(RunState::Stopped) | Err(ScmError::NotFound) => return Ok(OwnService::Present),
                Ok(RunState::Active) => {}
                Err(e) => return Err(format!("reading the service state failed: {e}")),
            }
            if waited >= self.stop_timeout {
                return Err(format!(
                    "the service did not stop within {} s",
                    self.stop_timeout.as_secs()
                ));
            }
            self.scm.pause(STOP_POLL);
            waited += STOP_POLL;
        }
    }

    fn unregister(&mut self) -> Result<OwnService, String> {
        let service = match self.scm.delete(SERVICE_NAME) {
            Ok(()) | Err(ScmError::MarkedForDelete) => Ok(OwnService::Present),
            Err(ScmError::NotFound) => Ok(OwnService::Absent),
            Err(e) => Err(format!("deleting the service failed: {e}")),
        };
        // The source goes too, even when the service was already gone, so a
        // half-done earlier uninstall is finished.
        let source = unregister_source(self.events);
        match (service, source) {
            (Ok(s), Ok(_)) => Ok(s),
            (Err(e), Ok(_)) => Err(e),
            (Ok(_), Err(e)) => Err(format!("removing the Event Log source failed: {e}")),
            (Err(a), Err(b)) => Err(format!(
                "{a}. Removing the Event Log source also failed: {b}"
            )),
        }
    }

    fn start_service(&mut self) -> Result<(), String> {
        match self.scm.start(SERVICE_NAME) {
            Ok(()) | Err(ScmError::AlreadyRunning) => Ok(()),
            Err(e) => Err(format!("starting the service failed: {e}")),
        }
    }
}

// ---------------------------------------------------------------- real

/// The real SCM, over `ntpc_platform::service_host` and the `w32time`
/// wrappers for stop, start and query.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RealScm;

#[cfg(windows)]
fn scm_err(op: &'static str, e: &std::io::Error) -> ScmError {
    ScmError::from_code(op, e.raw_os_error().unwrap_or(-1))
}

#[cfg(windows)]
fn raw_spec(spec: &ServiceSpec) -> ntpc_platform::service_host::RawServiceSpec {
    ntpc_platform::service_host::RawServiceSpec {
        name: spec.name.clone(),
        display_name: spec.display_name.clone(),
        image_path: spec.image_path.clone(),
        start_type: spec.start_type,
        error_control: spec.error_control,
    }
}

#[cfg(windows)]
impl ScmApi for RealScm {
    fn create(&mut self, spec: &ServiceSpec) -> Result<(), ScmError> {
        // R106: LocalSystem only. The FFI always passes a null account
        // (LocalSystem) and no dependencies. Refuse a spec that asks for
        // anything else, or for a restricted SID, rather than ignore it.
        if spec.account.is_some() || !spec.dependencies.is_empty() || spec.sid_type == 3 {
            return Err(ScmError::Os {
                op: "create (unsupported account or dependencies)",
                code: -1,
            });
        }
        ntpc_platform::service_host::create_service(&raw_spec(spec))
            .map_err(|e| scm_err("create", &e))
    }

    fn update(&mut self, spec: &ServiceSpec) -> Result<(), ScmError> {
        ntpc_platform::service_host::update_service(&raw_spec(spec))
            .map_err(|e| scm_err("update", &e))
    }

    fn configure(&mut self, spec: &ServiceSpec) -> Result<(), (&'static str, ScmError)> {
        use ntpc_platform::service_host::{RawExtras, RestartAfter, configure_service};
        let x = RawExtras {
            description: spec.description.clone(),
            delayed: spec.delayed,
            privileges: spec.privileges.clone(),
            reset_period_s: spec.reset_period_s,
            restarts: spec.restarts_ms.iter().map(|&d| RestartAfter(d)).collect(),
            actions_on_non_crash: spec.actions_on_non_crash,
            sid_type: spec.sid_type,
        };
        configure_service(&spec.name, &x).map_err(|(step, e)| (step, scm_err(step, &e)))
    }

    fn delete(&mut self, name: &str) -> Result<(), ScmError> {
        ntpc_platform::service_host::delete_service(name).map_err(|e| scm_err("delete", &e))
    }

    fn run_state(&self, name: &str) -> Result<RunState, ScmError> {
        use ntpc_platform::w32time::{RunState as W, ServiceControl, SvcError};
        match ntpc_platform::ScmControl.query(name) {
            Ok(s) if s.run == W::Stopped => Ok(RunState::Stopped),
            Err(SvcError::NotFound) => Err(ScmError::NotFound),
            Err(SvcError::AccessDenied) => Err(ScmError::AccessDenied),
            // Our own service may also be in a start type the w32time
            // mapper refuses. Fall back to "active", the safe reading.
            Ok(_) | Err(SvcError::UnsupportedStartType(_)) => Ok(RunState::Active),
            Err(e) => Err(ScmError::Os {
                op: "query",
                code: os_code(&e),
            }),
        }
    }

    fn stop(&mut self, name: &str) -> Result<(), ScmError> {
        use ntpc_platform::w32time::{ServiceControl, SvcError};
        ntpc_platform::ScmControl.stop(name).map_err(|e| match e {
            SvcError::NotActive => ScmError::NotActive,
            SvcError::NotFound => ScmError::NotFound,
            SvcError::AccessDenied => ScmError::AccessDenied,
            other => ScmError::Os {
                op: "stop",
                code: os_code(&other),
            },
        })
    }

    fn start(&mut self, name: &str) -> Result<(), ScmError> {
        use ntpc_platform::w32time::{ServiceControl, SvcError};
        ntpc_platform::ScmControl.start(name).map_err(|e| match e {
            SvcError::AlreadyRunning => ScmError::AlreadyRunning,
            SvcError::NotFound => ScmError::NotFound,
            SvcError::AccessDenied => ScmError::AccessDenied,
            other => ScmError::Os {
                op: "start",
                code: os_code(&other),
            },
        })
    }
}

#[cfg(windows)]
fn os_code(e: &ntpc_platform::w32time::SvcError) -> i32 {
    match e {
        ntpc_platform::w32time::SvcError::Os { code, .. } => *code,
        _ => -1,
    }
}

/// The real exe locator: `current_exe`, resolved by `canonicalize`, then
/// `ntpc_platform::install_location::check_exe_location`.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RealExeLocator;

#[cfg(windows)]
impl ExeLocator for RealExeLocator {
    fn exe(&self) -> Result<PathBuf, String> {
        let raw = std::env::current_exe()
            .map_err(|e| format!("cannot find the running exe: {}", e.kind()))?;
        // Resolves links and short names, so the registered path is the
        // real file and the location check sees the real folders.
        let real = std::fs::canonicalize(&raw)
            .map_err(|e| format!("cannot resolve the running exe path: {}", e.kind()))?;
        Ok(strip_verbatim(&real))
    }

    fn check(&self, exe: &Path) -> Vec<String> {
        ntpc_platform::install_location::check_exe_location(exe)
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, windows))]
mod vm_tests;
