//! Safe face of the service process calls in `win32/service.rs`.
//!
//! The service crate (`forbid(unsafe_code)`) builds its state machine,
//! registration and Event Log sink on these. Windows only.

pub use crate::win32::service::{
    ControlFn, EventSource, RawExtras, RawServiceSpec, RawStatus, RestartAfter, StatusHandle,
    configure_service, create_service, delete_hklm_key, delete_service, hklm_key_exists,
    register_handler, run_dispatcher, set_console_handler, set_status, update_service,
    write_event_source,
};

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: the process was not started
/// by the service control manager (Learn, `StartServiceCtrlDispatcherW`).
pub const ERROR_NOT_STARTED_BY_SCM: i32 = 1063;
