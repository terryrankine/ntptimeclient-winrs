//! The service wrapper on the real SCM. Only glue: every decision is in
//! `service.rs` and tested there with fakes. Nothing here runs in a test,
//! because a test process is not started by the SCM.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, OnceLock};

use ntpc_platform::service_host::{RawStatus, StatusHandle, register_handler, set_status};

use super::{
    Controller, Report, ServiceRun, StatusApi, Timing, new_core, raw, run_service, service_exit,
};
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
    let handle = match register_handler(SERVICE_NAME, handler) {
        Ok(h) => h,
        Err(e) => {
            // M1: no status handle, so no STOPPED can be reported. Say why
            // in the Event Log. Returning lets the dispatcher end, and the
            // SCM sees the process exit (a crash for the failure actions).
            report_direct(&format!(
                "cannot start: registering the service control handler failed with OS error \
                 {}",
                e.raw_os_error().unwrap_or(-1)
            ));
            return;
        }
    };
    let core = new_core(Arc::new(ScmStatus(handle)), Timing::default());
    let _ = slot.set(core.controller.clone());
    core.reporter.start_pending();
    let reporter = core.reporter.clone();
    // M1: a panic while building the run or inside it must still end in
    // one STOPPED report with a code, not in a silent hang.
    if let Ok(run) = catch_unwind(AssertUnwindSafe(make)) {
        if catch_unwind(AssertUnwindSafe(|| run_service(core, run))).is_err() {
            report_direct("the service wrapper panicked while running");
            reporter.stopped(service_exit::INTERNAL);
        }
    } else {
        report_direct("cannot start: building the service run panicked");
        reporter.stopped(service_exit::INTERNAL);
    }
}

/// One Event Log line written straight through the API, for the paths
/// where the normal logger does not exist.
fn report_direct(text: &str) {
    if let Ok(api) = crate::event_log::RealEventApi::open() {
        use crate::event_log::EventApi;
        let _ = api.report(
            crate::event_log::TYPE_ERROR,
            crate::event_log::ID_ERROR,
            &crate::event_log::event_text(text),
        );
    }
}
