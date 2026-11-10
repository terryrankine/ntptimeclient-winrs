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

// Each flag is one scripted fault or one observed effect.
#[allow(clippy::struct_excessive_bools)]
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
    /// The registered image path, when it exists. `None`: ours.
    image: Option<String>,
    /// After a start: stopped again with these exit codes.
    dies_after_start: Option<(u32, u32)>,
    /// After a start: stays start pending for ever.
    start_hangs: bool,
    starting: bool,
    /// After a start: Running for this many status reads, then Stopped.
    dies_after_reads: Option<u32>,
    reads: std::cell::Cell<u32>,
    parked: bool,
    /// A stop was sent and is still lagging.
    stopping: bool,
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
            image: None,
            dies_after_start: None,
            start_hangs: false,
            starting: false,
            dies_after_reads: None,
            reads: std::cell::Cell::new(0),
            parked: false,
            stopping: false,
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
    fn status(&self, name: &str) -> Result<SvcStatus, ScmError> {
        self.push(Call::State(name.to_owned()));
        if let Some(e) = self.state_error.clone() {
            return Err(e);
        }
        if !self.exists {
            return Err(ScmError::NotFound);
        }
        if self.starting {
            return Ok(SvcStatus::of(RunState::Starting));
        }
        if let Some(n) = self.dies_after_reads
            && self.running
        {
            self.reads.set(self.reads.get() + 1);
            if self.reads.get() > n {
                return Ok(SvcStatus {
                    state: RunState::Stopped,
                    win32_exit: 1066,
                    specific_exit: 10,
                });
            }
        }
        if self.running {
            return Ok(SvcStatus::of(RunState::Running));
        }
        let (w, sp) = self.dies_after_start.unwrap_or((0, 0));
        Ok(SvcStatus {
            state: RunState::Stopped,
            win32_exit: w,
            specific_exit: sp,
        })
    }
    fn park(&mut self, _name: &str) -> Result<(), (&'static str, ScmError)> {
        self.parked = true;
        Ok(())
    }
    fn image_path(&self, _name: &str) -> Result<Option<String>, ScmError> {
        if !self.exists {
            return Ok(None);
        }
        Ok(Some(
            self.image
                .clone()
                .unwrap_or_else(|| format!("\"{EXE}\" service")),
        ))
    }
    fn stop(&mut self, name: &str) -> Result<(), ScmError> {
        self.push(Call::Stop(name.to_owned()));
        if let Some(e) = self.stop_error.clone() {
            return Err(e);
        }
        if self.stop_lag == 0 {
            self.running = false;
        } else {
            self.stopping = true;
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
        if self.start_hangs {
            self.starting = true;
        } else if self.dies_after_start.is_none() {
            self.running = true;
        }
        Ok(())
    }
    fn pause(&mut self, _d: Duration) {
        self.pauses += 1;
        if self.stopping && self.stop_lag != u32::MAX {
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
    owner: Result<bool, String>,
}

impl ExeLocator for FakeLocator {
    fn exe(&self) -> Result<PathBuf, String> {
        self.exe.clone()
    }
    fn check(&self, _exe: &Path) -> Vec<String> {
        self.reasons.clone()
    }
    fn owner_trusted(&self) -> Result<bool, String> {
        self.owner.clone()
    }
}

const EXE: &str = r"C:\Program Files\ntptimeclient-winrs\ntptimeclient-winrs.exe";

fn locator() -> FakeLocator {
    FakeLocator {
        exe: Ok(PathBuf::from(EXE)),
        reasons: Vec::new(),
        owner: Ok(true),
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
                .with_timeouts(Duration::from_secs(2), Duration::from_secs(2))
                .with_soak(Duration::from_secs(2));
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
    // R106: never SERVICE_SID_TYPE_RESTRICTED (3). A write-restricted token
    // would fail every write to the SY and BA only state directory.
    assert_ne!(spec.sid_type, 3);
    assert!(spec.sid_type == 0 || spec.sid_type == 1);
    assert!(spec.description.contains("w32time"));
    assert!(spec.description.contains("preview"));
}

#[test]
fn the_update_on_reinstall_also_names_localsystem_and_no_restricted_sid() {
    let mut w = World::new();
    w.scm.exists = true;
    w.with(|r| r.register()).unwrap();
    for c in w.calls() {
        if let Call::Update(spec) | Call::Configure(spec) = c {
            assert_eq!(spec.account, None);
            assert_ne!(spec.sid_type, 3);
        }
    }
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
    // A stopped service is only queried, then updated and configured.
    assert_eq!(c[1], Call::State(SERVICE_NAME.to_owned()));
    assert!(matches!(c[2], Call::Update(_)));
    assert!(matches!(c[3], Call::Configure(_)));
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

// ---- R109: start waits for RUNNING ----

#[test]
fn start_waits_for_running() {
    let mut w = World::new();
    w.scm.exists = true;
    assert_eq!(w.with(|r| r.start_service()), Ok(()));
    assert!(w.scm.running);
}

#[test]
fn a_service_that_stops_right_after_start_is_a_failure_with_its_code() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.dies_after_start = Some((1066, 8));
    let e = w.with(|r| r.start_service()).unwrap_err();
    assert!(e.contains("service exit code 8"), "{e}");
    assert!(e.contains("event log"), "{e}");
}

#[test]
fn a_service_that_never_runs_times_out() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.start_hangs = true;
    let e = w.with(|r| r.start_service()).unwrap_err();
    assert!(e.contains("did not report running"), "{e}");
    assert!(w.scm.pauses >= 8, "the wait used the injected pause");
}

#[test]
fn reinstall_stops_a_running_service_before_updating_it() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.running = true;
    w.with(|r| r.register()).unwrap();
    let c = w.calls();
    let stop = c.iter().position(|x| matches!(x, Call::Stop(_))).unwrap();
    let update = c.iter().position(|x| matches!(x, Call::Update(_))).unwrap();
    assert!(stop < update, "{c:?}");
    assert!(!w.scm.running);
}

// ---- R110: never touch a service of our name that is not ours ----

#[test]
fn our_image_path_form() {
    assert!(is_our_image_path(&format!("\"{EXE}\" service")));
    assert!(is_our_image_path(
        r#""D:\x\NTPTIMECLIENT-WINRS.EXE" service"#
    ));
    for bad in [
        r"C:\x\ntptimeclient-winrs.exe service",
        r#""C:\x\ntptimeclient-winrs.exe""#,
        r#""C:\x\other.exe" service"#,
        r#""C:\x\ntptimeclient-winrs.exe" service --evil"#,
        r#""C:\x\a" "C:\x\ntptimeclient-winrs.exe" service"#,
        r"C:\Windows\System32\svchost.exe -k LocalService",
        r#""\ntptimeclient-winrs.exe" service"#,
        "",
    ] {
        assert!(!is_our_image_path(bad), "{bad}");
    }
}

#[test]
fn a_foreign_service_of_our_name_refuses_install_and_uninstall() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.image = Some(r"C:\Windows\System32\svchost.exe -k netsvcs".to_owned());
    assert!(matches!(w.with(|r| r.ready()), Err(NotReady::Foreign(_))));
    assert!(w.with(|r| r.check_ours()).is_err());
    assert!(!w.calls().iter().any(|c| matches!(
        c,
        Call::Create(_) | Call::Update(_) | Call::Delete(_) | Call::Stop(_) | Call::Start(_)
    )));
}

#[test]
fn an_untrusted_token_owner_refuses_install() {
    let mut w = World::new();
    w.loc.owner = Ok(false);
    assert!(matches!(
        w.with(|r| r.ready()),
        Err(NotReady::TokenOwner(_))
    ));
    let mut w = World::new();
    w.loc.owner = Err("unreadable".to_owned());
    assert!(matches!(
        w.with(|r| r.ready()),
        Err(NotReady::TokenOwner(_))
    ));
}

#[test]
fn a_percent_in_the_exe_path_is_refused() {
    assert_eq!(
        quote_image_path(Path::new(r"C:\%TEMP%\a.exe")),
        Err(QuoteError::BadCharacter)
    );
}

// ---- R113 soak, R112 park ----

#[test]
fn start_soaks_after_the_first_running() {
    let mut w = World::new();
    w.scm.exists = true;
    assert_eq!(w.with(|r| r.start_service()), Ok(()));
    // The 2 s test soak at 250 ms polls is at least 8 pauses.
    assert!(w.scm.pauses >= 8, "{}", w.scm.pauses);
}

#[test]
fn a_stop_within_the_soak_is_a_failure() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.dies_after_reads = Some(2);
    let e = w.with(|r| r.start_service()).unwrap_err();
    assert!(e.contains("service exit code 10"), "{e}");
}

#[test]
fn park_goes_through_the_scm() {
    let mut w = World::new();
    w.scm.exists = true;
    assert_eq!(w.with(|r| r.park()), Ok(()));
    assert!(w.scm.parked);
}

#[test]
fn reinstall_after_a_park_sets_auto_start_and_failure_actions_again() {
    let mut w = World::new();
    w.scm.exists = true;
    w.scm.parked = true;
    w.with(|r| r.register()).unwrap();
    let specs: Vec<ServiceSpec> = w
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Update(s) | Call::Configure(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(specs.len(), 2);
    for s in specs {
        assert_eq!(s.start_type, START_AUTO);
        assert!(s.delayed);
        assert_eq!(s.restarts_ms, RESTART_DELAYS_MS.to_vec());
    }
}
