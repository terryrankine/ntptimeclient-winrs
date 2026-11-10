use std::collections::BTreeSet;

use ntpc_platform::w32time::fake::{Call, FakeScm, Script};
use ntpc_platform::w32time::{RunState, StartType, SvcError, SvcState};

use super::*;
use crate::config::Config;

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
    warnings: Vec<String>,
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
            warnings: Vec::new(),
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
    fn warn(&mut self, line: &str) {
        self.warnings.push(line.to_owned());
        self.lines.push(format!("WARN {line}"));
    }
}

#[derive(Debug, Default)]
struct MemStore {
    dir: Option<DirState>,
    record: Option<Result<Restore, LoadError>>,
    secure_error: Option<SecureRefusal>,
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
    fn dir_state(&self) -> DirState {
        self.dir.unwrap_or(DirState::Present)
    }
    fn secure(&mut self) -> Result<(), SecureRefusal> {
        if let Some(e) = &self.secure_error {
            return Err(e.clone());
        }
        self.secured = true;
        Ok(())
    }
    fn load(&self) -> Result<Option<Restore>, LoadError> {
        // N8: every reader must secure the directory first.
        assert!(self.secured, "load before secure");
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
    unsafe_location: bool,
    foreign: bool,
    bad_owner: bool,
    parked: bool,
    start_error: Option<String>,
    start_calls: u32,
    register_error: Option<String>,
    unregister_error: Option<String>,
    present: bool,
    registered: bool,
    stopped: bool,
    unregister_calls: u32,
}

impl Registration for FakeReg {
    fn ready(&self) -> Result<(), NotReady> {
        if self.not_ready {
            Err(NotReady::NotBuilt("registration not built".to_owned()))
        } else if self.bad_owner {
            Err(NotReady::TokenOwner("untrusted owner".to_owned()))
        } else if self.foreign {
            Err(NotReady::Foreign("not ours".to_owned()))
        } else if self.unsafe_location {
            Err(NotReady::UnsafeLocation(vec![
                "the exe folder lets an account other than SYSTEM or Administrators change it"
                    .to_owned(),
            ]))
        } else {
            Ok(())
        }
    }
    fn park(&mut self) -> Result<(), String> {
        self.parked = true;
        Ok(())
    }
    fn check_ours(&self) -> Result<(), String> {
        if self.foreign {
            Err("not ours".to_owned())
        } else {
            Ok(())
        }
    }
    fn start_service(&mut self) -> Result<(), String> {
        self.start_calls += 1;
        match &self.start_error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
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
        self.unregister_calls += 1;
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

// ---- R86: refusals while securing, per class ----

fn refusals() -> Vec<SecureRefusal> {
    vec![
        SecureRefusal::Directory("untrusted parent".to_owned()),
        SecureRefusal::BadPath("reserved name".to_owned()),
        SecureRefusal::RollbackFailed("rollback failed".to_owned()),
        SecureRefusal::CarryFailed("carry failed".to_owned()),
        SecureRefusal::RecordDropped,
    ]
}

mod install;
mod uninstall;

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
    assert_eq!(
        run_install(
            &args(&["--nope"]),
            &Config::default(),
            &mut PendingRegistration
        ),
        exit::USAGE
    );
    assert_eq!(
        run_uninstall(
            &args(&["--nope"]),
            &Config::default(),
            &mut PendingRegistration
        ),
        exit::USAGE
    );
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

    for r in refusals() {
        let mut w = World::new(JoinState::Workgroup);
        w.store.secure_error = Some(r);
        seen.insert(w.install(SILENT));
    }

    let mut w = World::new(JoinState::Workgroup);
    w.store.secure_error = Some(SecureRefusal::RecordDropped);
    seen.insert(w.uninstall());

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
    seen.insert(w.uninstall());

    let mut w = World::new(JoinState::Workgroup);
    w.reg.register_error = Some("x".to_owned());
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.scm = FakeScm::new(Script::with(RunState::Stopped, StartType::Disabled));
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.reg.unsafe_location = true;
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.reg.start_error = Some("x".to_owned());
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.reg.foreign = true;
    seen.insert(w.install(SILENT));

    let mut w = World::new(JoinState::Workgroup);
    w.reg.bad_owner = true;
    seen.insert(w.install(SILENT));

    seen.insert(run_install(
        &args(&["--bad"]),
        &Config::default(),
        &mut PendingRegistration,
    ));

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
