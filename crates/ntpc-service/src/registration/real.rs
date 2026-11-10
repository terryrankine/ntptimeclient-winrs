//! The real SCM and exe locator. Only glue over `ntpc_platform`.

use std::path::{Path, PathBuf};

use super::{ExeLocator, RunState, ScmApi, ScmError, ServiceSpec, SvcStatus, strip_verbatim};

/// `SERVICE_SID_TYPE_RESTRICTED`.
const SID_TYPE_RESTRICTED: u32 = 3;

/// The real SCM, over `ntpc_platform::service_host` and the `w32time`
/// wrappers for stop and start.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealScm;

fn scm_err(op: &'static str, e: &std::io::Error) -> ScmError {
    ScmError::from_code(op, e.raw_os_error().unwrap_or(-1))
}

fn raw_spec(spec: &ServiceSpec) -> ntpc_platform::service_host::RawServiceSpec {
    ntpc_platform::service_host::RawServiceSpec {
        name: spec.name.clone(),
        display_name: spec.display_name.clone(),
        image_path: spec.image_path.clone(),
        start_type: spec.start_type,
        error_control: spec.error_control,
    }
}

/// R106: `LocalSystem` only (the FFI always passes a null account and no
/// dependencies), never a restricted SID. Checked on create and update
/// alike (M7).
fn refuse_unsupported(spec: &ServiceSpec) -> Result<(), ScmError> {
    if spec.account.is_some() || !spec.dependencies.is_empty() {
        return Err(ScmError::Os {
            op: "register (unsupported account or dependencies)",
            code: -1,
        });
    }
    if spec.sid_type == SID_TYPE_RESTRICTED {
        return Err(ScmError::Os {
            op: "register (restricted service SID)",
            code: -1,
        });
    }
    Ok(())
}

impl ScmApi for RealScm {
    fn create(&mut self, spec: &ServiceSpec) -> Result<(), ScmError> {
        refuse_unsupported(spec)?;
        ntpc_platform::service_host::create_service(&raw_spec(spec))
            .map_err(|e| scm_err("create", &e))
    }

    fn update(&mut self, spec: &ServiceSpec) -> Result<(), ScmError> {
        refuse_unsupported(spec)?;
        ntpc_platform::service_host::update_service(&raw_spec(spec))
            .map_err(|e| scm_err("update", &e))
    }

    fn configure(&mut self, spec: &ServiceSpec) -> Result<(), (&'static str, ScmError)> {
        use ntpc_platform::service_host::{RawExtras, RestartAfter, configure_service};
        refuse_unsupported(spec).map_err(|e| ("service SID type", e))?;
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

    fn park(&mut self, name: &str) -> Result<(), (&'static str, ScmError)> {
        ntpc_platform::service_host::park_service(name)
            .map_err(|(step, e)| (step, scm_err(step, &e)))
    }

    fn delete(&mut self, name: &str) -> Result<(), ScmError> {
        ntpc_platform::service_host::delete_service(name).map_err(|e| scm_err("delete", &e))
    }

    fn status(&self, name: &str) -> Result<SvcStatus, ScmError> {
        let s = ntpc_platform::service_host::query_status(name)
            .map_err(|e| scm_err("status query", &e))?;
        // SERVICE_STOPPED 1, START_PENDING 2, STOP_PENDING 3, RUNNING 4,
        // the rest are pause states (Learn, SERVICE_STATUS).
        let state = match s.state {
            1 => RunState::Stopped,
            2 => RunState::Starting,
            4 => RunState::Running,
            _ => RunState::Stopping,
        };
        Ok(SvcStatus {
            state,
            win32_exit: s.win32_exit,
            specific_exit: s.specific_exit,
        })
    }

    fn image_path(&self, name: &str) -> Result<Option<String>, ScmError> {
        match ntpc_platform::service_host::query_config(name) {
            Ok(c) => Ok(Some(c.image_path)),
            Err(e) => match scm_err("config query", &e) {
                ScmError::NotFound => Ok(None),
                other => Err(other),
            },
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

fn os_code(e: &ntpc_platform::w32time::SvcError) -> i32 {
    match e {
        ntpc_platform::w32time::SvcError::Os { code, .. } => *code,
        _ => -1,
    }
}

/// The real exe locator: `current_exe`, resolved by `canonicalize`, then
/// `ntpc_platform::install_location::check_exe_location`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealExeLocator;

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

    fn owner_trusted(&self) -> Result<bool, String> {
        ntpc_platform::default_owner_is_trusted()
            .map_err(|e| format!("the token owner could not be read: {}", e.kind()))
    }
}
