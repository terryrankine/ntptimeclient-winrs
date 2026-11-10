//! The [`Launcher`] that runs the real host.
//!
//! Coupling with Task 14c-A: the Windows adapters (`windows_deps(cfg)`)
//! are built by the other half of Task 14c. This launcher takes the builder
//! as a function. Until the builder is wired in,
//! [`DepsLauncher::pending`] says the host is not built: `run` and
//! `service` stop with a clear code, and `install` refuses (exit 9), so no
//! machine loses `w32time` to a service that cannot run.

use std::sync::Arc;

use super::{HostJob, JobError, Launcher, SharedPower};
use crate::config::Config;
use crate::host::{HostDeps, Inbox};
use crate::logging::Logger;

/// Why a pending launcher is not ready.
pub const NOT_BUILT: &str = "the Windows host adapters are not built into this exe yet";

/// Builds the host's adapters for a config. Runs on the host thread.
pub type BuildDeps = Arc<dyn Fn(&Config) -> Result<HostDeps, String> + Send + Sync>;

/// Runs `host::run` with adapters from a [`BuildDeps`]. The power events
/// and the log are the wrapper's, whatever the builder put there.
#[derive(Clone)]
pub struct DepsLauncher {
    build: Option<BuildDeps>,
}

impl DepsLauncher {
    /// A launcher over `build`.
    #[must_use]
    pub fn new(build: BuildDeps) -> Self {
        Self { build: Some(build) }
    }

    /// A launcher with no adapters. Never ready.
    #[must_use]
    pub fn pending() -> Self {
        Self { build: None }
    }
}

impl Launcher for DepsLauncher {
    fn ready(&self) -> Result<(), String> {
        if self.build.is_some() {
            Ok(())
        } else {
            Err(NOT_BUILT.to_owned())
        }
    }

    fn job(&self, cfg: Config, power: SharedPower, logger: Arc<dyn Logger>) -> HostJob {
        let build = self.build.clone();
        Box::new(move |inbox: Inbox| {
            let build = build.ok_or_else(|| JobError::Deps(NOT_BUILT.to_owned()))?;
            let mut deps = build(&cfg).map_err(JobError::Deps)?;
            deps.power = Box::new(power);
            deps.logger = logger;
            crate::host::run(cfg, deps, inbox).map_err(JobError::Host)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LineLogger, MemorySink};
    use crate::service::PowerTracker;
    use crate::transport::StdTimeSource;

    fn logger() -> Arc<dyn Logger> {
        Arc::new(LineLogger::new(
            Box::new(MemorySink::new()),
            Arc::new(StdTimeSource::new()),
        ))
    }

    #[test]
    fn pending_is_never_ready_and_its_job_fails_cleanly() {
        let l = DepsLauncher::pending();
        assert_eq!(l.ready(), Err(NOT_BUILT.to_owned()));
        let (_c, inbox) = crate::host::channel();
        let job = l.job(
            Config::default(),
            SharedPower(Arc::new(PowerTracker::default())),
            logger(),
        );
        assert!(matches!(job(inbox), Err(JobError::Deps(_))));
    }

    #[test]
    fn a_failing_builder_is_a_deps_error() {
        let l = DepsLauncher::new(Arc::new(|_cfg: &Config| Err("no clock".to_owned())));
        assert_eq!(l.ready(), Ok(()));
        let (_c, inbox) = crate::host::channel();
        let job = l.job(
            Config::default(),
            SharedPower(Arc::new(PowerTracker::default())),
            logger(),
        );
        match job(inbox) {
            Err(JobError::Deps(e)) => assert_eq!(e, "no clock"),
            other => panic!("{other:?}"),
        }
    }
}
