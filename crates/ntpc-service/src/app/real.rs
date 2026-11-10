//! Runs a parsed [`Command`] on the real system. Only glue: the decisions
//! are in `app.rs`, `cli`, `service` and `registration`, each tested with
//! fakes. Nothing here runs in a test.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use super::{Command, HELP, USAGE, default_config_path, exit, load_config, status_command};
use crate::cli::{self, Registration};
use crate::config::Config;
use crate::event_log::{DiscardSink, EventLogSink, RealEventApi, RealRegistry};
use crate::logging::{ConsoleSink, LineLogger, LogSink, Logger};
use crate::registration::{ExeLocator, RealExeLocator, RealScm, SERVICE_NAME, ScmRegistration};
use crate::service::{
    DepsLauncher, JobError, Launcher, ServiceRun, Started, preflight_then_config,
    real::service_main,
};
use crate::transport::StdTimeSource;
use crate::winimpl::{ResumeNotifier, WinDepsError, windows_deps};

/// The host launcher: 14c-A's `windows_deps(cfg, sinks)` and `host::run`
/// on one thread. `windows_deps` is called once per process.
fn launcher() -> DepsLauncher {
    DepsLauncher::new(Arc::new(|cfg, sinks, started| {
        // 14c-A takes boxed sinks. Each shared sink goes in through the
        // `LogSink for Arc<T>` impl in `event_log`.
        let boxed: Vec<Box<dyn LogSink>> = sinks
            .into_iter()
            .map(|s| Box::new(s) as Box<dyn LogSink>)
            .collect();
        let w = windows_deps(cfg, boxed).map_err(job_error)?;
        if !started(Started {
            control: w.control,
            resume: Arc::new(w.resume),
        }) {
            return Ok(());
        }
        crate::host::run(cfg.clone(), w.deps, w.inbox).map_err(JobError::Host)
    }))
}

/// Each 14c-A refusal with its own service exit code (R111).
#[allow(clippy::needless_pass_by_value)]
fn job_error(e: WinDepsError) -> JobError {
    match e {
        WinDepsError::Clock(_) => JobError::Clock(e.to_string()),
        WinDepsError::UntrustedAccount | WinDepsError::AccountUnreadable(_) => {
            JobError::Account(e.to_string())
        }
        WinDepsError::NoSinks => JobError::Deps(e.to_string()),
    }
}

impl crate::service::Resume for ResumeNotifier {
    fn notify_resumed(&self) {
        // The inherent method, named in full: a plain call here would pick
        // this trait method again and recurse.
        ResumeNotifier::notify_resumed(self);
    }
}

/// The folder of the running exe, resolved.
fn exe_dir() -> Result<PathBuf, String> {
    let exe = RealExeLocator.exe()?;
    exe.parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "the running exe has no folder".to_owned())
}

/// `path`, or the default config path next to the exe.
fn config_path(path: Option<PathBuf>) -> Result<PathBuf, String> {
    match path {
        Some(p) => Ok(p),
        None => exe_dir().map(|d| default_config_path(&d)),
    }
}

/// The config at `path`, or the default location. Prints its warnings.
fn config_for(path: Option<PathBuf>, err: &mut dyn Write) -> Result<Config, u8> {
    let path = match path {
        Some(p) => p,
        None => match exe_dir() {
            Ok(d) => default_config_path(&d),
            Err(e) => {
                let _ = writeln!(err, "{e}");
                return Err(exit::CONFIG);
            }
        },
    };
    match load_config(&path) {
        Ok(c) => {
            for w in c.warnings() {
                let _ = writeln!(err, "config warning: {w}");
            }
            Ok(c)
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            Err(exit::CONFIG)
        }
    }
}

/// Runs `cmd`. Returns the process exit code.
pub fn execute(cmd: Command, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match cmd {
        Command::Help => {
            let _ = writeln!(out, "{HELP}");
            cli::exit::OK
        }
        Command::Install(args) => match config_for(None, err) {
            Ok(cfg) => with_registration(|reg| cli::run_install(&args, &cfg, reg)),
            Err(code) => code,
        },
        Command::Uninstall(args) => match config_for(None, err) {
            Ok(cfg) => with_registration(|reg| cli::run_uninstall(&args, &cfg, reg)),
            Err(code) => code,
        },
        Command::Status { config } => match config_for(config, err) {
            Ok(cfg) => status_command(&cfg, out, err),
            Err(code) => code,
        },
        Command::Run { config } => run(config, err),
        Command::Service => service(err),
    }
}

fn with_registration(f: impl FnOnce(&mut dyn Registration) -> u8) -> u8 {
    let mut scm = RealScm;
    let mut events = RealRegistry;
    let locator = RealExeLocator;
    let mut reg = ScmRegistration::new(&mut scm, &mut events, &locator, launcher().ready());
    f(&mut reg)
}

/// Whether our service is running. Read only. An error counts as running:
/// two instances must never adjust one clock.
fn own_service_running() -> Result<bool, String> {
    use ntpc_platform::w32time::{RunState, ServiceControl, SvcError};
    match ntpc_platform::ScmControl.query(SERVICE_NAME) {
        Ok(s) => Ok(s.run != RunState::Stopped),
        Err(SvcError::NotFound) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

/// R111 and the courtesy SCM check. The guard must live until `run` ends.
fn run_guards(err: &mut dyn Write) -> Result<ntpc_platform::instance::InstanceGuard, u8> {
    let guard = match ntpc_platform::instance::acquire() {
        Ok((guard, None)) => guard,
        Ok((guard, Some(why))) => {
            let _ = writeln!(
                err,
                "Warning: {why}. Going on without the lock. The service check below still runs."
            );
            guard
        }
        Err(e) => {
            let _ = writeln!(err, "Not starting: {e}.");
            return Err(exit::RUN_CONFLICT);
        }
    };
    // A courtesy check on top of the lock, for a service from an older
    // build that did not take it.
    match own_service_running() {
        Ok(false) => {}
        Ok(true) => {
            let _ = writeln!(
                err,
                "The {SERVICE_NAME} service is running. Stop it first: two instances must not \
                 adjust one clock."
            );
            return Err(exit::RUN_CONFLICT);
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "Cannot tell whether the {SERVICE_NAME} service runs ({e}). Not starting."
            );
            return Err(exit::RUN_CONFLICT);
        }
    }
    Ok(guard)
}

/// I1 for `run`: the config file must be administrators-only. Then loads it.
fn run_config(config: Option<PathBuf>, err: &mut dyn Write) -> Result<Config, u8> {
    // I1: the config decides the time sources, so it must be
    // administrators-only like the exe.
    let path = match config_path(config) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return Err(exit::CONFIG);
        }
    };
    // m8: resolve first, so a relative --config is checked where it really
    // is, links and short names included.
    let path = match std::fs::canonicalize(&path) {
        Ok(p) => crate::registration::strip_verbatim(&p),
        Err(_) => std::path::absolute(&path).unwrap_or(path),
    };
    let reasons = ntpc_platform::install_location::check_config_location(&path);
    if !reasons.is_empty() {
        let _ = writeln!(
            err,
            "Not starting: the config file must be changeable by administrators only."
        );
        for r in reasons {
            let _ = writeln!(err, "  {r}");
        }
        return Err(exit::RUN_LOCATION);
    }
    config_for(Some(path), err)
}

fn run(config: Option<PathBuf>, err: &mut dyn Write) -> u8 {
    let _instance = match run_guards(err) {
        Ok(g) => g,
        Err(code) => return code,
    };
    let cfg = match run_config(config, err) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let launcher = launcher();
    if let Err(e) = launcher.ready() {
        let _ = writeln!(err, "Cannot run: {e}.");
        return exit::HOST_NOT_BUILT;
    }
    // The host's control exists only once the launcher built it, so the
    // Ctrl+C handler reads it from a slot. A Ctrl+C before that sets a flag
    // that the hand-over checks, so the host never starts.
    let slot: Arc<OnceLock<crate::host::HostControl>> = Arc::new(OnceLock::new());
    let early = Arc::new(AtomicBool::new(false));
    let done = Arc::new((Mutex::new(false), Condvar::new()));
    let (h_slot, h_early, d) = (slot.clone(), early.clone(), done.clone());
    let handler = move |ctrl: u32| {
        h_early.store(true, Ordering::SeqCst);
        if let Some(c) = h_slot.get() {
            c.shutdown();
        }
        // CTRL_CLOSE_EVENT, LOGOFF and SHUTDOWN end the process when the
        // handler returns (Learn, HandlerRoutine). Wait for the host to
        // reset the clock rate first, inside the 5 s close timeout.
        if matches!(ctrl, 2 | 5 | 6) {
            let (lock, cv) = &*d;
            let g = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = cv.wait_timeout_while(g, Duration::from_secs(4), |finished| !*finished);
        }
    };
    if let Err(e) = ntpc_platform::service_host::set_console_handler(Box::new(handler)) {
        let _ = writeln!(
            err,
            "Cannot install the Ctrl+C handler (OS error {}). Not starting: Ctrl+C would skip \
             the clock rate reset.",
            e.raw_os_error().unwrap_or(-1)
        );
        return exit::RUN_FAILED;
    }
    let started = move |s: Started| {
        let _ = slot.set(s.control);
        if early.load(Ordering::SeqCst) {
            if let Some(c) = slot.get() {
                c.shutdown();
            }
            return false;
        }
        true
    };
    // No power events in a console: resumes reach the host only in service
    // mode. The console sink is the host's only sink.
    let sinks: Vec<Arc<dyn LogSink>> = vec![Arc::new(ConsoleSink::new())];
    let result = launcher.run(cfg, sinks, &started);
    {
        let (lock, cv) = &*done;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        cv.notify_all();
    }
    match result {
        Ok(()) => cli::exit::OK,
        Err(JobError::Host(crate::host::HostError::Config(e))) => {
            let _ = writeln!(err, "{e}");
            exit::CONFIG
        }
        Err(e) => {
            let _ = writeln!(err, "The host ended with an error: {e}");
            exit::RUN_FAILED
        }
    }
}

fn service(err: &mut dyn Write) -> u8 {
    let make = || {
        // I1 and R111, before the config is read: the exe, its folder,
        // every file in it (the config included) must be
        // administrators-only, and no other instance may run.
        let exe = RealExeLocator.exe();
        let reasons = match &exe {
            Ok(p) => RealExeLocator.check(p),
            Err(e) => vec![e.clone()],
        };
        let (instance, unguarded) = match ntpc_platform::instance::acquire() {
            Ok((g, why)) => (Some(g), why),
            Err(_) => (None, None),
        };
        let (preflight, config) =
            preflight_then_config(reasons, instance.is_none(), || match exe {
                Ok(p) => match p.parent() {
                    Some(d) => load_config(&default_config_path(d)),
                    None => Err("the running exe has no folder".to_owned()),
                },
                Err(e) => Err(e),
            });
        let event_sink = RealEventApi::open()
            .and_then(|api| EventLogSink::start(Box::new(api)))
            .ok()
            .map(Arc::new);
        // 14c-A refuses an empty sink list, so a failed Event Log open
        // still passes a sink. The service then runs without a log.
        let sink: Arc<dyn LogSink> = match &event_sink {
            Some(s) => s.clone(),
            None => Arc::new(DiscardSink::default()),
        };
        let logger: Arc<dyn Logger> = Arc::new(LineLogger::new(
            Box::new(sink.clone()),
            Arc::new(StdTimeSource::new()),
        ));
        let drain: Box<dyn Fn(Duration) + Send + Sync> = match event_sink {
            Some(s) => Box::new(move |d| {
                let _ = s.drain(d);
            }),
            None => Box::new(|_| {}),
        };
        if let Some(why) = unguarded {
            logger.log(
                crate::logging::Level::Warn,
                "instance_lock",
                &format!("{why}. Running without the instance lock"),
            );
        }
        ServiceRun {
            config,
            launcher: Arc::new(launcher()),
            logger,
            sinks: vec![sink],
            drain,
            preflight,
            hold: instance.map(|g| Box::new(g) as Box<dyn std::any::Any + Send + Sync>),
        }
    };
    match ntpc_platform::service_host::run_dispatcher(
        SERVICE_NAME,
        Box::new(move || service_main(make)),
    ) {
        Ok(()) => cli::exit::OK,
        Err(e)
            if e.raw_os_error() == Some(ntpc_platform::service_host::ERROR_NOT_STARTED_BY_SCM) =>
        {
            let _ = writeln!(
                err,
                "The service command is for the service control manager. To run in this \
                 console use: run. {USAGE}"
            );
            exit::NOT_SCM
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "The service dispatcher failed: OS error {}.",
                e.raw_os_error().unwrap_or(-1)
            );
            exit::SERVICE_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_deps_refusal_gets_its_own_job_error() {
        assert!(matches!(
            job_error(WinDepsError::UntrustedAccount),
            JobError::Account(_)
        ));
        assert!(matches!(
            job_error(WinDepsError::AccountUnreadable(std::io::ErrorKind::Other)),
            JobError::Account(_)
        ));
        assert!(matches!(
            job_error(WinDepsError::NoSinks),
            JobError::Deps(_)
        ));
        assert!(matches!(
            job_error(WinDepsError::Clock(ntpc_core::ClockError::PermissionDenied)),
            JobError::Clock(_)
        ));
    }

    #[test]
    fn the_real_launcher_is_ready() {
        assert_eq!(launcher().ready(), Ok(()));
    }
}
