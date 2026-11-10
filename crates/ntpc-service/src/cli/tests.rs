use std::collections::BTreeSet;

use ntpc_platform::w32time::fake::{Call, FakeScm, Script};
use ntpc_platform::w32time::{RunState, StartType, SvcError, SvcState};

use super::*;

// ---- Fakes ----

#[derive(Debug)]
struct FakeHost {
    elevated: Result<bool, String>,
    join: JoinState,
    stdin_console: bool,
    stderr_console: bool,
    answer: bool,
    asked: u32,
    lines: Vec<String>,
}

impl FakeHost {
    fn new(join: JoinState) -> Self {
        Self {
            elevated: Ok(true),
            join,
            stdin_console: false,
            stderr_console: false,
            answer: false,
            asked: 0,
            lines: Vec::new(),
        }
    }
    fn text(&self) -> String {
        self.lines.join("\n")
    }
    fn consoles(&mut self, both: bool) {
        self.stdin_console = both;
        self.stderr_console = both;
    }
}

impl Host for FakeHost {
    fn is_elevated(&self) -> Result<bool, String> {
        self.elevated.clone()
    }
    fn join_state(&self) -> JoinState {
        self.join
    }
    fn is_interactive(&self) -> bool {
        self.stdin_console && self.stderr_console
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
    accept_disabled_original: false,
};
const SILENT_CONFIRMED: InstallOptions = InstallOptions {
    silent: true,
    confirm_domain_joined: true,
    accept_disabled_original: false,
};
const PLAIN: InstallOptions = InstallOptions {
    silent: false,
    confirm_domain_joined: false,
    accept_disabled_original: false,
};
const PLAIN_CONFIRMED: InstallOptions = InstallOptions {
    silent: false,
    confirm_domain_joined: true,
    accept_disabled_original: false,
};
const ACCEPT_DISABLED: InstallOptions = InstallOptions {
    silent: true,
    confirm_domain_joined: false,
    accept_disabled_original: true,
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
    assert!(w.host.text().contains("-ConfirmDomainJoined"));
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
    w.host.stdin_console = false;
    w.host.stderr_console = true;
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
    w.host.consoles(true);
    w.host.answer = false;
    assert_eq!(w.install(PLAIN), exit::DECLINED);
    assert_eq!(w.host.asked, 1);
    assert!(w.untouched());
    assert!(!w.store.secured);
}

#[test]
fn interactive_yes_proceeds() {
    let mut w = World::new(JoinState::Unknown);
    w.host.consoles(true);
    w.host.answer = true;
    assert_eq!(w.install(PLAIN), exit::OK);
    assert_eq!(w.w32time(), taken_over());
}

#[test]
fn silent_flag_wins_over_a_terminal() {
    let mut w = World::new(JoinState::Domain);
    w.host.consoles(true);
    w.host.answer = true;
    assert_eq!(w.install(SILENT), exit::DOMAIN_JOINED);
    assert_eq!(w.host.asked, 0);
}

#[test]
fn workgroup_installs_without_asking() {
    let mut w = World::new(JoinState::Workgroup);
    w.host.consoles(true);
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
    // M8: nothing changed, so the record this run wrote is gone again.
    assert_eq!(w.store.saved(), None);
    assert!(w.host.text().contains("new restore record was removed"));
}

#[test]
fn a_refused_stop_keeps_a_pre_existing_record() {
    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::with(RunState::Running, StartType::Manual);
    s.refuse_stop = Some(SvcError::DependentsRunning);
    w.scm = FakeScm::new(s);
    w.store = MemStore::with(Restore::new(StartType::Automatic, true));
    assert_eq!(w.install(SILENT), exit::TAKEOVER);
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Automatic, true))
    );
    assert!(w.host.text().contains("earlier restore record is kept"));
}

#[test]
fn a_failure_after_a_change_keeps_the_new_record() {
    let mut w = World::new(JoinState::Workgroup);
    let mut s = Script::running(StartType::Automatic);
    s.stop_pending_polls = u32::MAX;
    w.scm = FakeScm::new(s);
    // The default timing would poll for 30 s of fake pauses, which cost
    // nothing in the fake.
    assert_eq!(w.install(SILENT), exit::TAKEOVER);
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Automatic, true))
    );
    assert!(w.host.text().contains("Run uninstall"));
}

// ---- R84: already disabled, no record ----

#[test]
fn already_disabled_without_a_record_is_refused() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.install(SILENT), exit::DISABLED_ORIGINAL);
    assert!(w.untouched());
    assert_eq!(w.store.saved(), None);
    assert!(w.host.text().contains("--accept-disabled-original"));
}

#[test]
fn already_disabled_with_the_flag_records_disabled() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    assert_eq!(w.install(ACCEPT_DISABLED), exit::OK);
    assert_eq!(
        w.store.saved(),
        Some(Restore::new(StartType::Disabled, false))
    );
}

#[test]
fn already_disabled_with_a_record_is_not_affected() {
    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    w.store = MemStore::with(Restore::new(StartType::Manual, true));
    assert_eq!(w.install(SILENT), exit::OK);
    assert_eq!(w.store.saved(), Some(Restore::new(StartType::Manual, true)));
}

#[test]
fn disabled_original_code_is_outside_the_other_ranges() {
    assert!(!(2..=11).contains(&exit::DISABLED_ORIGINAL));
    assert!(!(40..=47).contains(&exit::DISABLED_ORIGINAL));
    assert_ne!(exit::DISABLED_ORIGINAL, exit::OK);
    for c in exit::ALL {
        assert!(!(40..=47).contains(&c), "{c}");
    }
}

// ---- R83: every console and flag combination ----

#[test]
fn console_flag_and_join_matrix() {
    for join in [JoinState::Workgroup, JoinState::Domain, JoinState::Unknown] {
        for stdin_console in [false, true] {
            for stderr_console in [false, true] {
                for flag in [false, true] {
                    let mut w = World::new(join);
                    w.host.stdin_console = stdin_console;
                    w.host.stderr_console = stderr_console;
                    // The user would say no if asked.
                    w.host.answer = false;
                    let opts = if flag { PLAIN_CONFIRMED } else { PLAIN };
                    let code = w.install(opts);
                    let interactive = stdin_console && stderr_console;
                    let case =
                        format!("{join:?} in={stdin_console} err={stderr_console} flag={flag}");
                    let (want, asked) = match (join, flag, interactive) {
                        (JoinState::Workgroup, _, _) | (_, true, _) => (exit::OK, 0),
                        (_, false, true) => (exit::DECLINED, 1),
                        (_, false, false) => (exit::DOMAIN_JOINED, 0),
                    };
                    assert_eq!(code, want, "{case}");
                    assert_eq!(w.host.asked, asked, "{case}");
                }
            }
        }
    }
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
    assert_eq!(
        parse_install_args(&args(&["--accept-disabled-original", "--silent"])),
        Ok(ACCEPT_DISABLED)
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
    w.host.consoles(true);
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

    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    seen.insert(w.install(SILENT));

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

// ---- Dispatch (R85, M6) ----

fn run(a: &[&str]) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = dispatch(&args(a), &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn no_arguments_keeps_the_stub_and_exits_zero() {
    let (code, out, err) = run(&[]);
    assert_eq!(code, exit::OK);
    assert!(out.contains("pre-alpha"));
    assert_eq!(err, "");
}

#[test]
fn help_does_not_list_install_or_uninstall_yet() {
    for h in ["--help", "-h"] {
        let (code, out, _) = run(&[h]);
        assert_eq!(code, exit::OK);
        assert!(!out.contains("install"), "{out}");
    }
}

#[test]
fn unknown_subcommand_or_argument_exits_non_zero_with_one_line() {
    for a in [
        &["status"][..],
        &["--version"],
        &["--help", "x"],
        &["frobnicate", "--silent"],
    ] {
        let (code, out, err) = run(a);
        assert_eq!(code, exit::USAGE, "{a:?}");
        assert_eq!(out, "");
        assert_eq!(err.lines().count(), 1, "{err}");
    }
}

#[test]
fn dispatch_bad_install_and_uninstall_arguments_exit_with_usage() {
    // Only invalid arguments: they stop at parsing, before any real call.
    assert_eq!(run(&["install", "--nope"]).0, exit::USAGE);
    assert_eq!(run(&["uninstall", "--nope"]).0, exit::USAGE);
}
