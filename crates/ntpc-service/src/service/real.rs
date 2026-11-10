//! The service wrapper on the real SCM. Only glue: every decision is in
//! `service.rs` and tested there with fakes. Nothing here runs in a test,
//! because a test process is not started by the SCM.

use std::sync::{Arc, OnceLock};

use ntpc_platform::service_host::{RawStatus, StatusHandle, register_handler, set_status};

use super::{Controller, Report, ServiceRun, StatusApi, Timing, new_core, raw, run_service};
use crate::registration::SERVICE_NAME;

/// `SetServiceStatus` through the handle the handler registration gave.
struct ScmStatus(StatusHandle);

impl StatusApi for ScmStatus {
    fn set(&self, r: &Report) -> Result<(), i32> {
        set_status(
            self.0,
            RawStatus {
                state: r.raw_state,
                accepts: r.accepts,
                win32_exit: r.win32_exit,
                specific_exit: r.specific_exit,
                checkpoint: r.checkpoint,
                wait_hint_ms: r.wait_hint_ms,
            },
        )
        .map_err(|e| e.raw_os_error().unwrap_or(-1))
    }
}

/// The `ServiceMain` body: register the handler, report `START_PENDING`,
/// then build the run (config and log) and hand over to [`run_service`].
pub fn service_main(make: impl FnOnce() -> ServiceRun) {
    // The handler is registered before the controller exists, so it reads
    // the controller from a slot. Until the slot is set no control is
    // accepted anyway (START_PENDING accepts none).
    let slot: Arc<OnceLock<Arc<Controller>>> = Arc::new(OnceLock::new());
    let s = slot.clone();
    let handler = Box::new(move |control: u32, event_type: u32| {
        s.get()
            .map_or(raw::NO_ERROR, |c| c.handle(control, event_type))
    });
    let Ok(handle) = register_handler(SERVICE_NAME, handler) else {
        // No status handle: nothing can be reported. Returning lets the
        // dispatcher end, and the SCM sees the process exit.
        return;
    };
    let core = new_core(Arc::new(ScmStatus(handle)), Timing::default());
    let _ = slot.set(core.controller.clone());
    core.reporter.start_pending();
    let run = make();
    // The code went out with SERVICE_STOPPED. Nothing more may run.
    let _ = run_service(core, run);
}
