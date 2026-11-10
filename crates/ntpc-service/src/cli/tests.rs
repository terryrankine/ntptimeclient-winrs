use std::collections::BTreeSet;

use ntpc_platform::w32time::fake::{Call, FakeScm, Script};
use ntpc_platform::w32time::{RunState, StartType, SvcError, SvcState};

use super::*;

// ---- Fakes ----

#[derive(Debug)]
struct FakeHost {
    elevated: Result<bool, String>,
    join: JoinState,
    terminal: bool,
    answer: bool,
    asked: u32,
    lines: Vec<String>,
}

impl FakeHost {
    fn new(join: JoinState) -> Self {
        Self {
            elevated: Ok(true),
            join,
            terminal: false,
            answer: false,
            asked: 0,
            lines: Vec::new(),
        }
    }
    fn text(&self) -> String {
        self.lines.join("\n")
    }
}

impl Host for FakeHost {
    fn is_elevated(&self) -> Result<bool, String> {
        self.elevated.clone()
    }
    fn join_state(&self) -> JoinState {
        self.join
    }
    fn stdin_is_terminal(&self) -> bool {
        self.terminal
    }
    fn ask_yes_no(&mut self, question: &str) -> bool {
        self.asked += 1;
        self.lines.push(format!("ASK {question}"));
        self.answer
    }
    fn say(&mut self, line: &str) {
        self.lines.push(line.to_owned());
    }
}

#[derive(Debug, Default)]
struct MemStore {
    record: Option<Result<Restore, LoadError>>,
    secure_error: Option<String>,
    save_error: Option<String>,
    remove_error: Option<String>,
    secured: bool,
    saves: u32,
}

impl MemStore {
    fn with(r: Restore) -> Self {
        Self {
            record: Some(Ok(r)),
            ..Self::default()
        }
    }
    fn invalid() -> Self {
        Self {
            record: Some(Err(LoadError::Invalid(RestoreFormatError::NotCanonical))),
            ..Self::default()
        }
    }
    fn saved(&self) -> Option<Restore> {
        match &self.record {
            Some(Ok(r)) => Some(*r),
            _ => None,
        }
    }
}

impl RecordStore for MemStore {
    fn secure(&mut self) -> Result<(), String> {
        if let Some(e) = &self.secure_error {
            return Err(e.clone());
        }
        self.secured = true;
        Ok(())
    }
    fn load(&self) -> Result<Option<Restore>, LoadError> {
        match &self.record {
            None => Ok(None),
            Some(Ok(r)) => Ok(Some(*r)),
            Some(Err(e)) => Err(e.clone()),
        }
    }
    fn save(&mut self, r: &Restore) -> Result<(), String> {
        if let Some(e) = &self.save_error {
            return Err(e.clone());
        }
        self.saves += 1;
        self.record = Some(Ok(*r));
        Ok(())
    }
    fn remove(&mut self) -> Result<(), String> {
        if let Some(e) = &self.remove_error {
            return Err(e.clone());
        }
        self.record = None;
        Ok(())
    }
}

// Each flag is one scripted fault or one observed effect.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct FakeReg {
    not_ready: bool,
    register_error: Option<String>,
    unregister_error: Option<String>,
    present: bool,
    registered: bool,
    stopped: bool,
}

impl Registration for FakeReg {
    fn ready(&self) -> Result<(), String> {
        if self.not_ready {
            Err("registration not built".to_owned())
        } else {
            Ok(())
        }
    }
    fn register(&mut self) -> Result<(), String> {
        if let Some(e) = &self.register_error {
            return Err(e.clone());
        }
        self.registered = true;
        Ok(())
    }
    fn stop_service(&mut self) -> Result<OwnService, String> {
        self.stopped = true;
        Ok(if self.present {
            OwnService::Present
        } else {
            OwnService::Absent
        })
    }
    fn unregister(&mut self) -> Result<OwnService, String> {
        if let Some(e) = &self.unregister_error {
            return Err(e.clone());
        }
        Ok(if self.present {
            OwnService::Present
        } else {
            OwnService::Absent
        })
    }
}

struct World {
    host: FakeHost,
    store: MemStore,
    scm: FakeScm,
    reg: FakeReg,
}

impl World {
    fn new(join: JoinState) -> Self {
        Self {
            host: FakeHost::new(join),
            store: MemStore::default(),
            scm: FakeScm::new(Script::running(StartType::AutomaticDelayed)),
            reg: FakeReg::default(),
        }
    }
    fn install(&mut self, opts: InstallOptions) -> u8 {
        install(
            &opts,
            &mut Deps {
                host: &mut self.host,
                store: &mut self.store,
                scm: &mut self.scm,
                reg: &mut self.reg,
            },
        )
    }
    fn uninstall(&mut self) -> u8 {
        uninstall(&mut Deps {
            host: &mut self.host,
            store: &mut self.store,
            scm: &mut self.scm,
            reg: &mut self.reg,
        })
    }
    fn w32time(&self) -> Option<SvcState> {
        self.scm.state()
    }
    fn untouched(&self) -> bool {
        !self.scm.mutated() && self.store.saves == 0 && !self.reg.registered
    }
}

const SILENT: InstallOptions = InstallOptions {
    silent: true,
    confirm_domain_joined: false,
};
const SILENT_CONFIRMED: InstallOptions = InstallOptions {
    silent: true,
    confirm_domain_joined: true,
};
const PLAIN: InstallOptions = InstallOptions {
    silent: false,
    confirm_domain_joined: false,
};

// Compared against `FakeScm::state`, which is an Option.
#[allow(clippy::unnecessary_wraps)]
fn taken_over() -> Option<SvcState> {
    Some(SvcState {
        run: RunState::Stopped,
        start: StartType::Disabled,
    })
}

#[allow(clippy::unnecessary_wraps)]
fn original() -> Option<SvcState> {
    Some(SvcState {
        run: RunState::Running,
        start: StartType::AutomaticDelayed,
    })
}

// ---- The three from the brief ----

#[test]
fn install_aborts_on_domain_joined_silent_without_flag() {
    let mut w = World::new(JoinState::Domain);
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert!(w.untouched());
    assert!(!w.store.secured, "the state directory is not touched");
    assert_eq!(w.w32time(), original());
    assert!(w.host.text().contains("--confirm-domain-joined"));
}

#[test]
fn install_proceeds_on_domain_joined_with_flag() {
    let mut w = World::new(JoinState::Domain);
    assert_eq!(w.install(SILENT_CONFIRMED), exit::OK);
    assert_eq!(w.w32time(), taken_over());
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::AutomaticDelayed, true))
    );
    assert!(w.reg.registered);
    assert!(w.host.text().contains("domain"));
}

#[test]
fn uninstall_restores_w32time_even_if_service_missing() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = false;
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(
        w.w32time(),
        Some(SvcState {
            run: RunState::Running,
            start: StartType::Manual
        })
    );
    assert_eq!(w.store.saved(), None, "record removed after restore");
}

// ---- Domain rule ----

#[test]
fn non_terminal_stdin_counts_as_silent() {
    let mut w = World::new(JoinState::Domain);
    w.host.terminal = false;
    assert_eq!(w.install(PLAIN), exit::DOMAIN_JOINED);
    assert_eq!(w.host.asked, 0);
    assert!(w.untouched());
}

#[test]
fn unknown_join_state_aborts_a_silent_install() {
    let mut w = World::new(JoinState::Unknown);
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert!(w.untouched());
}

#[test]
fn interactive_decline_aborts_without_change() {
    let mut w = World::new(JoinState::Domain);
    w.host.terminal = true;
    w.host.answer = false;
    assert_eq!(w.install(PLAIN), exit::DECLINED);
    assert_eq!(w.host.asked, 1);
    assert!(w.untouched());
    assert!(!w.store.secured);
}

#[test]
fn interactive_yes_proceeds() {
    let mut w = World::new(JoinState::Unknown);
    w.host.terminal = true;
    w.host.answer = true;
    assert_eq!(w.install(PLAIN), exit::OK);
    assert_eq!(w.w32time(), taken_over());
}

#[test]
fn silent_flag_wins_over_a_terminal() {
    let mut w = World::new(JoinState::Domain);
    w.host.terminal = true;
    w.host.answer = true;
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert_eq!(w.host.asked, 0);
}

#[test]
fn workgroup_installs_without_asking() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.terminal = true;
    assert_eq!(w.install(PLAIN), exit::OK);
    assert_eq!(w.host.asked, 0);
}

// ---- Install refusals ----

#[test]
fn install_refuses_when_not_elevated() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Ok(false);
    assert_eq!(w.install(SILENT), exit::NOT_ELEVATED);
    assert!(w.untouched());
}

#[test]
fn install_refuses_when_elevation_cannot_be_read() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Err("token unreadable".to_owned());
    assert_eq!(w.install(SILENT), exit::NOT_ELEVATED);
    assert!(w.untouched());
}

#[test]
fn install_refuses_before_any_change_when_registration_is_not_built() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.not_ready = true;
    assert_eq!(w.install(SILENT), exit::REGISTER);
    assert!(w.untouched());
    assert!(!w.store.secured);
    assert_eq!(w.scm.calls(), Vec::<Call>::new());
}

#[test]
fn install_refuses_when_the_state_dir_cannot_be_secured() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.secure_error = Some("unexpected entry".to_owned());
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert!(w.untouched());
}

#[test]
fn install_refuses_when_the_record_cannot_be_saved() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.save_error = Some("disk full".to_owned());
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert!(!w.scm.mutated());
    assert_eq!(w.w32time(), original());
}

#[test]
fn install_refuses_on_a_tampered_record_and_changes_nothing() {
    let mut w = World::new(JoinState::Workgroup);
    w.store = MemStore::invalid();
    assert_eq!(w.install(SILENT), exit::RECORD_INVALID);
    assert!(!w.scm.mutated());
    assert_eq!(w.w32time(), original());
}

#[test]
fn install_refuses_on_an_unreadable_record() {
    let mut w = World::new(JoinState::Workgroup);
    w.store.record = Some(Err(LoadError::Io(io::ErrorKind::PermissionDenied)));
    assert_eq!(w.install(SILENT), exit::STATE_DIR);
    assert!(!w.scm.mutated());
}

#[test]
fn install_reports_a_refused_stop() {
    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::running(StartType::Automatic);
    s.refuse_stop = Some(SvcError::DependentsRunning);
    w.scm = FakeScm::new(s);
    assert_eq!(w.install(SILENT), exit::TAKEOVER);
    assert!(!w.reg.registered);
    // The record stays, so uninstall can still restore.
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Automatic, true))
    );
}

#[test]
fn register_failure_rolls_w32time_back_and_removes_the_record() {
    let mut w = World::new(JoinState::Workgroup);
    w.reg.register_error = Some("create failed".to_owned());
    assert_eq!(w.install(SILENT), exit::REGISTER);
    assert_eq!(w.w32time(), original());
    assert_eq!(w.store.saved(), None);
}

#[test]
fn rerun_install_keeps_the_true_original_record() {
    let mut w = World::new(JoinState::Workgroup);
    assert_eq!(w.install(SILENT), exit::OK);
    assert_eq!(w.install(SILENT), exit::OK);
    assert_eq!(w.store.saves, 1, "second install must not overwrite");
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::AutomaticDelayed, true))
    );
    assert_eq!(w.uninstall(), exit::OK);
    assert_eq!(w.w32time(), original());
}

#[test]
fn only_w32time_is_touched_by_install_and_uninstall() {
    let mut w = World::new(JoinState::Workgroup);
    w.install(SILENT);
    w.uninstall();
    for c in w.scm.calls() {
        if let Call::Query(n) | Call::Stop(n) | Call::Start(n) | Call::SetStartType(n, _) = c {
            assert_eq!(n, "w32time");
        }
    }
}

// ---- Uninstall ----

#[test]
fn uninstall_refuses_when_not_elevated() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Ok(false);
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    assert_eq!(w.uninstall(), exit::NOT_ELEVATED);
    assert!(!w.scm.mutated());
    assert!(!w.reg.stopped);
}

#[test]
fn uninstall_without_a_record_leaves_w32time_alone() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.uninstall(), exit::OK);
    assert!(!w.scm.mutated());
    assert!(w.host.text().contains("no restore record"));
}

#[test]
fn uninstall_with_a_tampered_record_leaves_w32time_alone() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::invalid();
    assert_eq!(w.uninstall(), exit::RECORD_INVALID);
    assert!(!w.scm.mutated());
    // The file stays for the administrator to inspect.
    assert!(matches!(w.store.record, Some(Err(_))));
}

#[test]
fn uninstall_keeps_the_record_when_restore_fails() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::missing());
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    assert_eq!(w.uninstall(), exit::RESTORE);
    assert_eq!(w.store.saved(), Some(Restore::new(StartType::Manual, true)));
}

#[test]
fn uninstall_restores_even_when_unregister_fails() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Automatic, false));
    w.reg.present = true;
    w.reg.unregister_error = Some("delete failed".to_owned());
    assert_eq!(w.uninstall(), exit::UNREGISTER);
    assert_eq!(w.w32time().unwrap().start, StartType::Automatic);
}

#[test]
fn uninstall_reports_a_record_that_cannot_be_removed() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, false));
    w.store.remove_error = Some("locked".to_owned());
    assert_eq!(w.uninstall(), exit::STATE_DIR);
    assert_eq!(w.w32time().unwrap().start, StartType::Manual);
}

#[test]
fn uninstall_stops_our_service_before_restoring() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    w.reg.present = true;
    assert_eq!(w.uninstall(), exit::OK);
    assert!(w.reg.stopped);
}

// ---- Arguments and exit codes ----

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn install_args_parse() {
    assert_eq!(parse_install_args(&args(&[])), Ok(PLAIN));
    assert_eq!(parse_install_args(&args(&["--silent"])), Ok(SILENT));
    assert_eq!(
        parse_install_args(&args(&["--confirm-domain-joined", "--silent"])),
        Ok(SILENT_CONFIRMED)
    );
    assert!(parse_install_args(&args(&["--silnet"])).is_err());
    assert!(parse_install_args(&args(&["--silent", "--silent"])).is_err());
}

#[test]
fn uninstall_args_parse() {
    assert_eq!(parse_uninstall_args(&args(&[])), Ok(()));
    assert_eq!(parse_uninstall_args(&args(&["--silent"])), Ok(()));
    assert!(parse_uninstall_args(&args(&["--force"])).is_err());
}

#[test]
fn bad_arguments_exit_with_usage_and_change_nothing() {
    assert_eq!(run_install(&args(&["--nope"])), exit::USAGE);
    assert_eq!(run_uninstall(&args(&["--nope"])), exit::USAGE);
}

#[test]
fn every_exit_code_is_reachable() {
    let mut seen = BTreeSet::new();
    let mut w = World::new(JoinState::Workgroup);
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.host.elevated = Ok(false);
    seen.insert(w.install(SILENT));

    seen.insert(World::new(JoinState::Domain).install(SILENT));

    let mut w = World::new(JoinState::Domain);
    w.host.terminal = true;
    seen.insert(w.install(PLAIN));

    let mut w = World::new(JoinState::Workgroup);
    w.store.secure_error = Some("x".to_owned());
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.store = MemStore::invalid();
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::running(StartType::Manual);
    s.refuse_stop = Some(SvcError::AccessDenied);
    w.scm = FakeScm::new(s);
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.reg.not_ready = true;
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::missing());
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    seen.insert(w.uninstall());

    let mut w = World::new(JoinState::Workgroup);
    w.reg.unregister_error = Some("x".to_owned());
    seen.insert(w.uninstall());

    seen.insert(run_install(&args(&["--bad"])));

    let all: BTreeSet<u8> = exit::ALL.iter().copied().collect();
    assert_eq!(seen, all);
}

#[test]
fn exit_codes_are_distinct() {
    let all: BTreeSet<u8> = exit::ALL.iter().copied().collect();
    assert_eq!(all.len(), exit::ALL.len());
}

#[test]
fn messages_name_no_path() {
    let mut w = World::new(JoinState::Domain);
    w.install(SILENT);
    let mut w2 = World::new(JoinState::Workgroup);
    w2.store = MemStore::invalid();
    w2.uninstall();
    for t in [w.host.text(), w2.host.text()] {
        assert!(!t.contains('\\'), "{t}");
        assert!(!t.to_lowercase().contains("programdata"), "{t}");
    }
}

// ---- The file store ----

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ntpc-restore-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).expect("temp dir");
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn file_store_round_trips() {
    let d = TempDir::new("rt");
    let mut s = FileRecordStore::new(&d.0);
    assert_eq!(s.load(), Ok(None));
    let r = Restore::new(StartType::AutomaticDelayed, true);
    s.save(&r).unwrap();
    assert_eq!(s.load(), Ok(Some(r)));
    // A second save replaces the first.
    let r2 = Restore::new(StartType::Manual, false);
    s.save(&r2).unwrap();
    assert_eq!(s.load(), Ok(Some(r2)));
    assert!(!d.0.join(RECORD_TEMP_NAME).exists());
    s.remove().unwrap();
    assert_eq!(s.load(), Ok(None));
    s.remove().unwrap();
}

#[test]
fn file_store_refuses_a_tampered_file() {
    let d = TempDir::new("bad");
    let text = Restore::new(StartType::Manual, true)
        .encode()
        .replace("w32time", "WinDefend");
    fs::write(d.0.join(RECORD_FILE_NAME), text).unwrap();
    assert_eq!(
        FileRecordStore::new(&d.0).load(),
        Err(LoadError::Invalid(RestoreFormatError::NotCanonical))
    );
}

#[test]
fn file_store_refuses_a_huge_file() {
    let d = TempDir::new("huge");
    fs::write(d.0.join(RECORD_FILE_NAME), vec![b' '; 1 << 20]).unwrap();
    assert_eq!(
        FileRecordStore::new(&d.0).load(),
        Err(LoadError::Invalid(RestoreFormatError::TooLarge))
    );
}

#[test]
fn file_store_overwrites_a_stale_temp_file() {
    let d = TempDir::new("tmp");
    fs::write(d.0.join(RECORD_TEMP_NAME), b"junk").unwrap();
    let mut s = FileRecordStore::new(&d.0);
    let r = Restore::new(StartType::Disabled, false);
    s.save(&r).unwrap();
    assert_eq!(s.load(), Ok(Some(r)));
}

#[test]
fn file_store_errors_name_no_path() {
    let d = TempDir::new("err");
    // A directory where the record should be: reads fail.
    fs::create_dir(d.0.join(RECORD_FILE_NAME)).unwrap();
    let e = FileRecordStore::new(&d.0).load().unwrap_err();
    let t = e.to_string();
    assert!(!t.contains('\\') && !t.contains("ntpc-restore"), "{t}");
}
