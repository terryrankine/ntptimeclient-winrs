//! Mutating tests on the real SCM and registry. VM ONLY.
//!
//! Every test is `#[ignore]` and also refuses to run unless both
//! `NTPC_ALLOW_SERVICE_TESTS=1` and `NTPC_I_AM_ON_A_VM=1` are set and the
//! process is elevated. A drop guard deletes the service and the Event Log
//! source again, whatever the test did. No test here touches `w32time` or
//! the clock. The registered image path is `cmd.exe` from System32, a file
//! that passes the location check and is never started by these tests.
//!
//! Run on a throwaway VM only, one at a time:
//! `cargo test -p ntpc-service --lib registration::vm_tests -- --ignored --test-threads=1`

use std::path::PathBuf;

use super::*;
use crate::event_log::{EVENT_SOURCE_KEY, EventSourceRegistry, RealRegistry};

fn allowed() -> bool {
    let on = |k: &str| std::env::var(k).is_ok_and(|v| v == "1");
    if !(on("NTPC_ALLOW_SERVICE_TESTS") && on("NTPC_I_AM_ON_A_VM")) {
        eprintln!("refused: set NTPC_ALLOW_SERVICE_TESTS=1 and NTPC_I_AM_ON_A_VM=1 on a VM");
        return false;
    }
    if !ntpc_platform::is_elevated().unwrap_or(false) {
        eprintln!("refused: not elevated");
        return false;
    }
    true
}

/// Deletes our service and source on drop, so a failed assert leaves the
/// VM clean.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let mut scm = RealScm;
        let _ = scm.stop(SERVICE_NAME);
        let _ = scm.delete(SERVICE_NAME);
        let mut reg = RealRegistry;
        if reg.exists(EVENT_SOURCE_KEY).unwrap_or(false) {
            let _ = reg.delete(EVENT_SOURCE_KEY);
        }
    }
}

struct SystemExe;

impl ExeLocator for SystemExe {
    fn exe(&self) -> Result<PathBuf, String> {
        let root = std::env::var_os("SystemRoot").ok_or("no SystemRoot")?;
        Ok(PathBuf::from(root).join("System32").join("cmd.exe"))
    }
    fn check(&self, exe: &Path) -> Vec<String> {
        ntpc_platform::install_location::check_exe_location(exe)
    }
}

#[test]
#[ignore = "VM only: creates and deletes a real service and registry key"]
fn vm_register_then_unregister_leaves_nothing() {
    if !allowed() {
        return;
    }
    let _guard = Cleanup;
    let mut scm = RealScm;
    let mut reg = RealRegistry;
    let loc = SystemExe;
    let mut r = ScmRegistration::new(&mut scm, &mut reg, &loc, Ok(()));
    assert_eq!(r.ready(), Ok(()));
    r.register().unwrap();
    // Registering twice updates in place.
    r.register().unwrap();
    assert_eq!(r.stop_service(), Ok(OwnService::WasStopped));
    assert_eq!(r.unregister(), Ok(OwnService::Present));
    drop(r);
    assert_eq!(RealScm.run_state(SERVICE_NAME), Err(ScmError::NotFound));
    assert!(!RealRegistry.exists(EVENT_SOURCE_KEY).unwrap());
}

#[test]
#[ignore = "VM only: writes and deletes a real registry key"]
fn vm_event_source_round_trip() {
    if !allowed() {
        return;
    }
    let _guard = Cleanup;
    let mut reg = RealRegistry;
    assert!(crate::event_log::register_source(&mut reg).is_ok());
    assert!(reg.exists(EVENT_SOURCE_KEY).unwrap());
    assert_eq!(crate::event_log::unregister_source(&mut reg), Ok(true));
    assert!(!reg.exists(EVENT_SOURCE_KEY).unwrap());
}

#[test]
#[ignore = "VM only: writes one event to the real Application log"]
fn vm_event_log_line_is_readable() {
    if !allowed() {
        return;
    }
    let _guard = Cleanup;
    let mut reg = RealRegistry;
    crate::event_log::register_source(&mut reg).unwrap();
    let api = crate::event_log::RealEventApi::open().unwrap();
    let sink = crate::event_log::EventLogSink::start(Box::new(api)).unwrap();
    sink.event(
        crate::event_log::TYPE_INFORMATION,
        crate::event_log::ID_SERVICE,
        "ntpc VM test event: check the Event Viewer shows this text",
    );
    assert!(sink.drain(std::time::Duration::from_secs(5)));
    assert_eq!(
        sink.counts()
            .written
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}
