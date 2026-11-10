//! The [`Launcher`] that runs the real host.
//!
//! Coupling with Task 14c-A: the Windows adapters come from
//! `windows_deps(&cfg, sinks)`, which returns the host deps, the inbox, the
//! host control and the resume notifier. This launcher takes one function
//! that does the whole run on the calling thread (build, hand over, run),
//! so this crate does not name 14c-A's types. Until it is wired in,
//! [`DepsLauncher::pending`] says the host is not built: `run` and
//! `service` stop with a clear code, and `install` refuses (exit 9), so no
//! machine loses `w32time` to a service that cannot run.
//!
//! The function the merge wires in, in outline:
//!
//! ```text
//! |cfg, sinks, started| {
//!     let w = windows_deps(cfg, sinks).map_err(|e| JobError::Deps(e.to_string()))?;
//!     if !started(Started { control: w.control, resume: Arc::new(w.resume) }) {
//!         return Ok(());
//!     }
//!     host::run(cfg.clone(), w.deps, w.inbox).map_err(JobError::Host)
//! }
//! ```

use std::sync::Arc;

use super::{JobError, Launcher, StartedFn};
use crate::config::Config;
use crate::logging::LogSink;

/// Why a pending launcher is not ready.
pub const NOT_BUILT: &str = "the Windows host adapters are not built into this exe yet";

/// One whole host run: build the adapters with these sinks, call `started`,
/// run unless it said no. Runs on one thread.
pub type RunFn = Arc<
    dyn Fn(&Config, Vec<Arc<dyn LogSink>>, StartedFn<'_>) -> Result<(), JobError> + Send + Sync,
>;

/// Runs the host through a [`RunFn`].
#[derive(Clone)]
pub struct DepsLauncher {
    run: Option<RunFn>,
}

impl DepsLauncher {
    /// A launcher over `run`.
    #[must_use]
    pub fn new(run: RunFn) -> Self {
        Self { run: Some(run) }
    }

    /// A launcher with no adapters. Never ready.
    #[must_use]
    pub fn pending() -> Self {
        Self { run: None }
    }
}

impl Launcher for DepsLauncher {
    fn ready(&self) -> Result<(), String> {
        if self.run.is_some() {
            Ok(())
        } else {
            Err(NOT_BUILT.to_owned())
        }
    }

    fn run(
        &self,
        cfg: Config,
        sinks: Vec<Arc<dyn LogSink>>,
        started: StartedFn<'_>,
    ) -> Result<(), JobError> {
        let Some(run) = &self.run else {
            return Err(JobError::Deps(NOT_BUILT.to_owned()));
        };
        // 14c-A refuses an empty list. Catch it here with a clear message.
        if sinks.is_empty() {
            return Err(JobError::Deps("no log sink was given".to_owned()));
        }
        run(&cfg, sinks, started)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::MemorySink;

    fn sinks() -> Vec<Arc<dyn LogSink>> {
        vec![Arc::new(MemorySink::new())]
    }

    #[test]
    fn pending_is_never_ready_and_its_run_fails_cleanly() {
        let l = DepsLauncher::pending();
        assert_eq!(l.ready(), Err(NOT_BUILT.to_owned()));
        let r = l.run(Config::default(), sinks(), &|_| true);
        assert!(matches!(r, Err(JobError::Deps(_))));
    }

    #[test]
    fn a_failing_builder_is_a_deps_error() {
        let l = DepsLauncher::new(Arc::new(|_cfg, _s, _st| {
            Err(JobError::Deps("no clock".to_owned()))
        }));
        assert_eq!(l.ready(), Ok(()));
        match l.run(Config::default(), sinks(), &|_| true) {
            Err(JobError::Deps(e)) => assert_eq!(e, "no clock"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_sink_list_is_refused_before_building() {
        let l = DepsLauncher::new(Arc::new(|_cfg, _s, _st| panic!("must not build")));
        assert!(matches!(
            l.run(Config::default(), Vec::new(), &|_| true),
            Err(JobError::Deps(_))
        ));
    }
}
