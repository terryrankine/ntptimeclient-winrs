//! Registration over a fake SCM, a fake registry and a fake exe locator.
//! Every parameter the real `CreateServiceW` would get is asserted here.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::event_log::{EVENT_SOURCE_KEY, MESSAGE_FILE, TYPES_SUPPORTED};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Create(ServiceSpec),
    Update(ServiceSpec),
    Configure(ServiceSpec),
    Delete(String),
    State(String),
    Stop(String),
    Start(String),
    RegExists,
    RegWrite(String, String, u32),
    RegDelete(String),
}

type Log = Rc<RefCell<Vec<Call>>>;

#[derive(Debug)]
struct FakeScm {
    log: Log,
    exists: bool,
    running: bool,
    create_error: Option<ScmError>,
    update_error: Option<ScmError>,
    configure_error: Option<(&'static str, ScmError)>,
    delete_error: Option<ScmError>,
    stop_error: Option<ScmError>,
    start_error: Option<ScmError>,
    state_error: Option<ScmError>,
    /// Polls that still read Active after a stop. `u32::MAX`: never stops.
    stop_lag: u32,
    pauses: u32,
}

impl FakeScm {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            exists: false,
            running: false,
            create_error: None,
            update_error: None,
            configure_error: None,
            delete_error: None,
            stop_error: None,
            start_error: None,
            state_error: None,
            stop_lag: 0,
            pauses: 0,
        }
    }
    fn push(&self, c: Call) {
        self.log.borrow_mut().push(c);
    }
}

impl ScmApi for FakeScm {
    fn create(&mut self, spec: &ServiceSpec) -> Result<(), ScmError> {
        self.push(Call::Create(spec.clone()));
        if let Some(e) = self.create_error.clone() {
            return Err(e);
        }
        if self.exists {
            return Err(ScmError::Exists);
        }
        self.exists = true;
        Ok(())
    }
    fn update(&mut self, spec: &ServiceSpec) -> Result<(), ScmError> {
        self.push(Call::Update(spec.clone()));
        self.update_error.clone().map_or(Ok(()), Err)
    }
    fn configure(&mut self, spec: &ServiceSpec) -> Result<(), (&'static str, ScmError)> {
        self.push(Call::Configure(spec.clone()));
        self.configure_error.clone().map_or(Ok(()), Err)
    }
    fn delete(&mut self, name: &str) -> Result<(), ScmError> {
        self.push(Call::Delete(name.to_owned()));
        if let Some(e) = self.delete_error.clone() {
            return Err(e);
        }
        if !self.exists {
            return Err(ScmError::NotFound);
        }
        self.exists = false;
        Ok(())
    }
    fn run_state(&self, name: &str) -> Result<RunState, ScmError> {
        self.push(Call::State(name.to_owned()));
        if let Some(e) = self.state_error.clone() {
            return Err(e);
        }
        if !self.exists {
            return Err(ScmError::NotFound);
        }
        Ok(if self.running {
            RunState::Active
        } else {
            RunState::Stopped
        })
    }
    fn stop(&mut self, name: &str) -> Result<(), ScmError> {
        self.push(Call::Stop(name.to_owned()));
        if let Some(e) = self.stop_error.clone() {
            return Err(e);
        }
        if self.stop_lag == 0 {
            self.running = false;
        }
        Ok(())
    }
    fn start(&mut self, name: &str) -> Result<(), ScmError> {
        self.push(Call::Start(name.to_owned()));
        if let Some(e) = self.start_error.clone() {
            return Err(e);
        }
        if self.running {
            return Err(ScmError::AlreadyRunning);
        }
        self.running = true;
        Ok(())
    }
    fn pause(&mut self, _d: Duration) {
        self.pauses += 1;
        if self.stop_lag != u32::MAX {
            self.stop_lag = self.stop_lag.saturating_sub(1);
            if self.stop_lag == 0 {
                self.running = false;
            }
        }
    }
}

#[derive(Debug)]
struct FakeReg {
    log: Log,
    present: bool,
    write_error: Option<String>,
    delete_error: Option<String>,
}

impl FakeReg {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            present: false,
            write_error: None,
            delete_error: None,
        }
    }
}

impl EventSourceRegistry for FakeReg {
    fn exists(&self, key: &str) -> Result<bool, String> {
        assert_eq!(key, EVENT_SOURCE_KEY);
        self.log.borrow_mut().push(Call::RegExists);
        Ok(self.present)
    }
    fn write(&mut self, key: &str, file: &str, types: u32) -> Result<(), String> {
        self.log
            .borrow_mut()
            .push(Call::RegWrite(key.to_owned(), file.to_owned(), types));
        if let Some(e) = &self.write_error {
            // A failed write may still have created the key.
            self.present = true;
            return Err(e.clone());
        }
        self.present = true;
        Ok(())
    }
    fn delete(&mut self, key: &str) -> Result<(), String> {
        self.log.borrow_mut().push(Call::RegDelete(key.to_owned()));
        if let Some(e) = &self.delete_error {
            return Err(e.clone());
        }
        self.present = false;
        Ok(())
    }
}

struct FakeLocator {
    exe: Result<PathBuf, String>,
    reasons: Vec<String>,
}

impl ExeLocator for FakeLocator {
    fn exe(&self) -> Result<PathBuf, String> {
        self.exe.clone()
    }
    fn check(&self, _exe: &Path) -> Vec<String> {
        self.reasons.clone()
    }
}

const EXE: &str = r"C:\Program Files\ntptimeclient-winrs\ntptimeclient-winrs.exe";

fn locator() -> FakeLocator {
    FakeLocator {
        exe: Ok(PathBuf::from(EXE)),
        reasons: Vec::new(),
    }
}

struct World {
    log: Log,
    scm: FakeScm,
    reg: FakeReg,
    loc: FakeLocator,
    host: Result<(), String>,
}

impl World {
    fn new() -> Self {
        let log: Log = Rc::default();
        Self {
            scm: FakeScm::new(&log),
            reg: FakeReg::new(&log),
            loc: locator(),
            host: Ok(()),
            log,
        }
    }
    fn with<T>(&mut self, f: impl FnOnce(&mut ScmRegistration<'_>) -> T) -> T {
        let mut r =
            ScmRegistration::new(&mut self.scm, &mut self.reg, &self.loc, self.host.clone())
                .with_stop_timeout(Duration::from_secs(2));
        f(&mut r)
    }
    fn calls(&self) -> Vec<Call> {
        self.log.borrow().clone()
    }
}

// ---- Quoting ----

#[test]
fn image_path_is_always_quoted() {
    assert_eq!(
        quote_image_path(Path::new(EXE)).unwrap(),
        format!("\"{EXE}\" service")
    );
    assert_eq!(
        quote_image_path(Path::new(r"C:\x\a.exe")).unwrap(),
        r#""C:\x\a.exe" service"#
    );
}

#[test]
fn quoting_handles_unicode_and_long_paths() {
    let p = r"D:\Zeitdienst Ünïcødé 時間\ntp.exe";
    assert_eq!(
        quote_image_path(Path::new(p)).unwrap(),
        format!("\"{p}\" service")
    );
    let long = format!(r"C:\{}\a.exe", "d".repeat(30_000));
    assert!(quote_image_path(Path::new(&long)).is_ok());
    let too_long = format!(r"C:\{}\a.exe", "d".repeat(MAX_EXE_PATH));
    assert_eq!(
        quote_image_path(Path::new(&too_long)),
        Err(QuoteError::TooLong)
    );
}

#[test]
fn quoting_refuses_what_would_break_it() {
    for (p, e) in [
        (r#""C:\x\a.exe""#, QuoteError::BadCharacter),
        (r#"C:\x"y\a.exe"#, QuoteError::BadCharacter),
        ("C:\\x\\a\0.exe", QuoteError::BadCharacter),
        (r"C:\x\dir\", QuoteError::TrailingBackslash),
        (r"x\a.exe", QuoteError::NotLocalAbsolute),
        (r"\\server\share\a.exe", QuoteError::NotLocalAbsolute),
        (r"\\?\C:\x\a.exe", QuoteError::NotLocalAbsolute),
        (r"\\?\UNC\server\share\a.exe", QuoteError::NotLocalAbsolute),
        ("C:/x/a.exe", QuoteError::NotLocalAbsolute),
        (r"C:a.exe", QuoteError::NotLocalAbsolute),
        ("", QuoteError::NotLocalAbsolute),
    ] {
        assert_eq!(quote_image_path(Path::new(p)), Err(e), "{p:?}");
    }
}

#[test]
fn verbatim_prefix_is_stripped_only_for_drive_paths() {
    assert_eq!(
        strip_verbatim(Path::new(r"\\?\C:\x\a.exe")),
        PathBuf::from(r"C:\x\a.exe")
    );
    assert_eq!(
        strip_verbatim(Path::new(r"\\?\UNC\s\h\a.exe")),
        PathBuf::from(r"\\?\UNC\s\h\a.exe")
    );
    assert_eq!(
        strip_verbatim(Path::new(r"C:\x\a.exe")),
        PathBuf::from(r"C:\x\a.exe")
    );
}

// ---- The spec ----

#[test]
fn every_create_parameter_is_what_the_design_says() {
    let mut w = World::new();
    w.with(|r| r.register()).unwrap();
    let Call::Create(spec) = &w.calls()[0] else {
        panic!("{:?}", w.calls());
    };
    assert_eq!(spec.name, "ntptimeclient-winrs");
    assert_eq!(spec.image_path, format!("\"{EXE}\" service"));
    assert_eq!(spec.start_type, 2, "SERVICE_AUTO_START");
    assert!(spec.delayed, "delayed auto start");
    assert_eq!(spec.error_control, 1, "SERVICE_ERROR_NORMAL");
    assert_eq!(spec.account, None, "LocalSystem");
    assert_eq!(spec.dependencies, Vec::<String>::new());
    assert_eq!(spec.privileges, vec!["SeSystemtimePrivilege".to_owned()]);
    assert_eq!(spec.restarts_ms, vec![60_000, 60_000, 300_000]);
    assert_eq!(spec.reset_period_s, 86_400);
    assert!(spec.actions_on_non_crash);
    assert_eq!(spec.sid_type, 0, "SERVICE_SID_TYPE_NONE");
    assert!(spec.description.contains("w32time"));
    assert!(spec.description.contains("preview"));
}

#[test]
fn register_creates_configures_and_registers_the_source_in_that_order() {
    let mut w = World::new();
    w.with(|r| r.register()).unwrap();
    let c = w.calls();
    assert!(matches!(c[0], Call::Create(_)));
    assert!(matches!(c[1], Call::Configure(_)));
    assert_eq!(c[2], Call::RegExists);
    assert_eq!(
        c[3],
        Call::RegWrite(
            EVENT_SOURCE_KEY.to_owned(),
            MESSAGE_FILE.to_owned(),
            TYPES_SUPPORTED
        )
    );
    assert_eq!(c.len(), 4);
}

#[test]
fn reinstall_updates_the_existing_service() {
    let mut w = World::new();
    w.scm.exists = true;
    w.with(|r| r.register()).unwrap();
    let c = w.calls();
    assert!(matches!(c[0], Call::Create(_)));
    assert!(matches!(c[1], Call::Update(_)));
    assert!(matches!(c[2], Call::Configure(_)));
}

#[test]
fn a_service_marked_for_delete_refuses_with_advice() {
    let mut w = World::new();
    w.scm.create_error = Some(ScmError::MarkedForDelete);
    let e = w.with(|r| r.register()).unwrap_err();
    assert!(e.contains("reboot"), "{e}");
    assert_eq!(w.calls().len(), 1);
}

#[test]
fn a_failed_configure_removes_the_service_this_run_created() {
    let mut w = World::new();
    w.scm.configure_error = Some(("required privileges", ScmError::Os { op: "x", code: 87 }));
    let e = w.with(|r| r.register()).unwrap_err();
    assert!(e.contains("required privileges"), "{e}");
    assert!(e.contains("removed again"), "{e}");
    assert!(!w.scm.exists);
    assert!(w.calls().contains(&Call::Delete(SERVICE_NAME.to_owned())));
}

#[test]
fn a_failed_configure_on_reinstall_keeps_the_earlier_service() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.configure_error = Some(("description", ScmError::AccessDenied));
    let e = w.with(|r| r.register()).unwrap_err();
    assert!(e.contains("existed before"), "{e}");
    assert!(w.scm.exists);
    assert!(!w.calls().iter().any(|c| matches!(c, Call::Delete(_))));
}

#[test]
fn a_failed_rollback_reports_both_errors() {
    let mut w = World::new();
    w.scm.configure_error = Some(("failure actions", ScmError::AccessDenied));
    w.scm.delete_error = Some(ScmError::Os {
        op: "delete",
        code: 1072,
    });
    let e = w.with(|r| r.register()).unwrap_err();
    assert!(e.contains("failure actions"), "{e}");
    assert!(e.contains("also failed"), "{e}");
    assert!(e.contains("sc.exe delete ntptimeclient-winrs"), "{e}");
}

#[test]
fn a_failed_source_registration_removes_the_service_and_the_half_key() {
    let mut w = World::new();
    w.reg.write_error = Some("writing the registry failed: OS error 5".to_owned());
    let e = w.with(|r| r.register()).unwrap_err();
    assert!(e.contains("Event Log source"), "{e}");
    assert!(!w.scm.exists);
    assert!(!w.reg.present, "the half-written key is removed");
}

#[test]
fn an_existing_source_is_kept_when_its_write_fails() {
    let mut w = World::new();
    w.reg.present = true;
    w.reg.write_error = Some("x".to_owned());
    assert!(w.with(|r| r.register()).is_err());
    assert!(w.reg.present);
}

// ---- ready ----

#[test]
fn ready_needs_the_host_the_exe_and_a_safe_location() {
    let mut w = World::new();
    assert_eq!(w.with(|r| r.ready()), Ok(()));

    let mut w = World::new();
    w.host = Err("platform adapters are not built".to_owned());
    assert!(matches!(w.with(|r| r.ready()), Err(NotReady::NotBuilt(_))));

    let mut w = World::new();
    w.loc.exe = Err("cannot find the running exe".to_owned());
    assert!(matches!(w.with(|r| r.ready()), Err(NotReady::NotBuilt(_))));

    let mut w = World::new();
    w.loc.reasons = vec!["the exe folder lets an account change it".to_owned()];
    assert_eq!(
        w.with(|r| r.ready()),
        Err(NotReady::UnsafeLocation(vec![
            "the exe folder lets an account change it".to_owned()
        ]))
    );

    let mut w = World::new();
    w.loc.exe = Ok(PathBuf::from(r"\\server\share\a.exe"));
    assert!(matches!(
        w.with(|r| r.ready()),
        Err(NotReady::UnsafeLocation(_))
    ));
    assert!(w.calls().is_empty(), "ready changes nothing");
}

// ---- stop, start, unregister ----

#[test]
fn stop_waits_for_stopped() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.running = true;
    w.scm.stop_lag = 3;
    assert_eq!(w.with(|r| r.stop_service()), Ok(OwnService::Present));
    assert!(!w.scm.running);
    assert!(w.scm.pauses >= 3);
}

#[test]
fn stop_of_a_missing_or_stopped_service() {
    let mut w = World::new();
    assert_eq!(w.with(|r| r.stop_service()), Ok(OwnService::Absent));
    let mut w = World::new();
    w.scm.exists = true;
    assert_eq!(w.with(|r| r.stop_service()), Ok(OwnService::WasStopped));
    assert!(!w.calls().iter().any(|c| matches!(c, Call::Stop(_))));
}

#[test]
fn stop_that_never_finishes_times_out() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.running = true;
    w.scm.stop_lag = u32::MAX;
    let e = w.with(|r| r.stop_service()).unwrap_err();
    assert!(e.contains("did not stop"), "{e}");
}

#[test]
fn stop_refused_is_an_error() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.running = true;
    w.scm.stop_error = Some(ScmError::AccessDenied);
    assert!(w.with(|r| r.stop_service()).is_err());
}

#[test]
fn start_counts_already_running_as_success() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.running = true;
    assert_eq!(w.with(|r| r.start_service()), Ok(()));
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.start_error = Some(ScmError::AccessDenied);
    assert!(w.with(|r| r.start_service()).is_err());
}

#[test]
fn unregister_deletes_the_service_and_the_source() {
    let mut w = World::new();
    w.scm.exists = true;
    w.reg.present = true;
    assert_eq!(w.with(|r| r.unregister()), Ok(OwnService::Present));
    assert!(!w.scm.exists);
    assert!(!w.reg.present);
}

#[test]
fn unregister_of_a_missing_service_still_removes_a_left_over_source() {
    let mut w = World::new();
    w.reg.present = true;
    assert_eq!(w.with(|r| r.unregister()), Ok(OwnService::Absent));
    assert!(!w.reg.present);
}

#[test]
fn unregister_reports_both_failures() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.delete_error = Some(ScmError::AccessDenied);
    w.reg.present = true;
    w.reg.delete_error = Some("deleting the registry key failed: OS error 5".to_owned());
    let e = w.with(|r| r.unregister()).unwrap_err();
    assert!(e.contains("deleting the service failed"), "{e}");
    assert!(e.contains("also failed"), "{e}");
}

#[test]
fn marked_for_delete_counts_as_removed() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.delete_error = Some(ScmError::MarkedForDelete);
    assert_eq!(w.with(|r| r.unregister()), Ok(OwnService::Present));
}

#[test]
fn only_our_service_name_is_ever_used() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.running = true;
    let _ = w.with(|r| r.stop_service());
    let _ = w.with(|r| r.register());
    let _ = w.with(|r| r.start_service());
    let _ = w.with(|r| r.unregister());
    for c in w.calls() {
        match c {
            Call::Delete(n) | Call::State(n) | Call::Stop(n) | Call::Start(n) => {
                assert_eq!(n, SERVICE_NAME);
            }
            Call::Create(s) | Call::Update(s) | Call::Configure(s) => {
                assert_eq!(s.name, SERVICE_NAME);
            }
            _ => {}
        }
    }
}

#[test]
fn scm_error_codes_map() {
    assert_eq!(ScmError::from_code("x", 1073), ScmError::Exists);
    assert_eq!(ScmError::from_code("x", 1072), ScmError::MarkedForDelete);
    assert_eq!(ScmError::from_code("x", 1060), ScmError::NotFound);
    assert_eq!(ScmError::from_code("x", 1062), ScmError::NotActive);
    assert_eq!(ScmError::from_code("x", 1056), ScmError::AlreadyRunning);
    assert_eq!(ScmError::from_code("x", 5), ScmError::AccessDenied);
    assert_eq!(
        ScmError::from_code("x", 87),
        ScmError::Os { op: "x", code: 87 }
    );
}
