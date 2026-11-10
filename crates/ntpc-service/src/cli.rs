//! The `install` and `uninstall` subcommands.
//!
//! They own the `w32time` takeover and the domain join rule. The packaging
//! scripts only call them. All logic runs against traits, so every path is
//! tested with fakes and no real service is touched by a test.
//!
//! Install, in order:
//! 1. Refuse unless the service registration hook is ready (Task 14).
//! 2. Refuse unless elevated.
//! 3. Domain join rule. `Unknown` counts as domain joined. A silent install
//!    (`--silent`, or stdin not a terminal) aborts unless
//!    `--confirm-domain-joined` is given. An interactive install warns and
//!    asks, default no.
//! 4. Secure the state directory. Refuse if it cannot be secured: a
//!    stopped `w32time` with no restore record is worse than no install.
//! 5. Load an existing record. A tampered one refuses and changes nothing.
//! 6. Take over `w32time`. The record is written before anything changes.
//! 7. Register our service (Task 14 hook). On failure `w32time` is put back.
//!
//! Uninstall: stop our service (hook), restore `w32time` from the record,
//! remove the registration (hook). It restores even if our service is
//! missing. Without a record `w32time` is left as it is: guessing a start
//! type could undo an administrator's choice. The state directory stays.
//!
//! Messages carry no paths, machine names, user names or domain names.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use ntpc_platform::JoinState;
use ntpc_platform::w32time::{
    Restore, RestoreFormatError, ServiceControl, TakeoverError, restore, take_over,
};
use thiserror::Error;

use crate::safe_open;

/// Process exit codes. Stable: the packaging scripts read them.
pub mod exit {
    /// Done.
    pub const OK: u8 = 0;
    /// Bad arguments. Nothing changed.
    pub const USAGE: u8 = 2;
    /// Not elevated, or elevation could not be read. Nothing changed.
    pub const NOT_ELEVATED: u8 = 3;
    /// Domain joined (or join state unknown), silent, no
    /// `--confirm-domain-joined`. Nothing changed.
    pub const DOMAIN_JOINED: u8 = 4;
    /// The user answered no. Nothing changed.
    pub const DECLINED: u8 = 5;
    /// The state directory or the record could not be secured, read, written
    /// or removed. Install: nothing changed.
    pub const STATE_DIR: u8 = 6;
    /// `restore.json` exists and is not a valid record. Nothing changed. An
    /// administrator must check `w32time` and remove the file.
    pub const RECORD_INVALID: u8 = 7;
    /// The `w32time` takeover failed. The message says what changed. The
    /// record stays so uninstall can restore.
    pub const TAKEOVER: u8 = 8;
    /// Our service could not be registered, or registration is not built
    /// yet. `w32time` was put back.
    pub const REGISTER: u8 = 9;
    /// Uninstall could not restore `w32time`. The record stays.
    pub const RESTORE: u8 = 10;
    /// Uninstall could not stop or remove our service registration.
    pub const UNREGISTER: u8 = 11;

    /// Every code, for tests.
    pub const ALL: [u8; 11] = [
        OK,
        USAGE,
        NOT_ELEVATED,
        DOMAIN_JOINED,
        DECLINED,
        STATE_DIR,
        RECORD_INVALID,
        TAKEOVER,
        REGISTER,
        RESTORE,
        UNREGISTER,
    ];
}

/// Name of the restore record in the state directory.
pub const RECORD_FILE_NAME: &str = "restore.json";
/// Temp name for the atomic write. Same directory, so the rename stays on
/// one volume.
pub const RECORD_TEMP_NAME: &str = "restore.json.tmp";

/// Install flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallOptions {
    /// Never ask. Also implied when stdin is not a terminal.
    pub silent: bool,
    /// Proceed on a domain-joined machine without asking.
    pub confirm_domain_joined: bool,
}

const INSTALL_USAGE: &str = "usage: install [--silent] [--confirm-domain-joined]";
const UNINSTALL_USAGE: &str = "usage: uninstall [--silent]";

/// Parses the arguments after `install`. Each flag at most once.
///
/// # Errors
/// The usage text with the offending argument.
pub fn parse_install_args(args: &[String]) -> Result<InstallOptions, String> {
    let mut o = InstallOptions {
        silent: false,
        confirm_domain_joined: false,
    };
    for a in args {
        let slot = match a.as_str() {
            "--silent" => &mut o.silent,
            "--confirm-domain-joined" => &mut o.confirm_domain_joined,
            _ => return Err(format!("unknown argument. {INSTALL_USAGE}")),
        };
        if *slot {
            return Err(format!("argument given twice. {INSTALL_USAGE}"));
        }
        *slot = true;
    }
    Ok(o)
}

/// Parses the arguments after `uninstall`. Only `--silent`, which changes
/// nothing because uninstall never asks. Accepted so scripts can pass it.
///
/// # Errors
/// The usage text.
pub fn parse_uninstall_args(args: &[String]) -> Result<(), String> {
    match args {
        [] => Ok(()),
        [a] if a == "--silent" => Ok(()),
        _ => Err(format!("unknown argument. {UNINSTALL_USAGE}")),
    }
}

/// The console and the OS facts install needs.
pub trait Host {
    /// Whether the process is elevated.
    ///
    /// # Errors
    /// Why it could not be read.
    fn is_elevated(&self) -> Result<bool, String>;
    /// The classic domain join state.
    fn join_state(&self) -> JoinState;
    /// Whether stdin is an interactive terminal.
    fn stdin_is_terminal(&self) -> bool;
    /// Asks a yes or no question. Anything but yes is no.
    fn ask_yes_no(&mut self, question: &str) -> bool;
    /// Prints one line for the user.
    fn say(&mut self, line: &str);
}

/// Why a record could not be loaded. Holds no file text and no path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoadError {
    /// The file is there and is not a valid record.
    #[error("{0}")]
    Invalid(RestoreFormatError),
    /// The file is there and could not be read.
    #[error("cannot read the restore record: {0}")]
    Io(io::ErrorKind),
}

/// Where the restore record lives.
pub trait RecordStore {
    /// Secures the state directory before anything is written there.
    ///
    /// # Errors
    /// Why it could not be secured.
    fn secure(&mut self) -> Result<(), String>;
    /// The record, `None` if there is none.
    ///
    /// # Errors
    /// [`LoadError`].
    fn load(&self) -> Result<Option<Restore>, LoadError>;
    /// Writes the record atomically.
    ///
    /// # Errors
    /// Why it could not be written.
    fn save(&mut self, r: &Restore) -> Result<(), String>;
    /// Removes the record. A missing record is not an error.
    ///
    /// # Errors
    /// Why it could not be removed.
    fn remove(&mut self) -> Result<(), String>;
}

/// Whether our own service registration existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnService {
    /// It was there.
    Present,
    /// It was not there.
    Absent,
}

/// Our own service registration. Task 14 implements it with
/// `CreateServiceW` and friends. Task 12 only defines the hook.
pub trait Registration {
    /// Whether registration is available at all. Checked before any change.
    ///
    /// # Errors
    /// Why not.
    fn ready(&self) -> Result<(), String>;
    /// Registers our service.
    ///
    /// # Errors
    /// Why it failed.
    fn register(&mut self) -> Result<(), String>;
    /// Stops our service if it is there.
    ///
    /// # Errors
    /// Why it failed.
    fn stop_service(&mut self) -> Result<OwnService, String>;
    /// Removes our service registration if it is there.
    ///
    /// # Errors
    /// Why it failed.
    fn unregister(&mut self) -> Result<OwnService, String>;
}

/// Everything install and uninstall act on.
pub struct Deps<'a> {
    /// Console and OS facts.
    pub host: &'a mut dyn Host,
    /// The restore record.
    pub store: &'a mut dyn RecordStore,
    /// The service control manager.
    pub scm: &'a mut dyn ServiceControl,
    /// Our own service registration.
    pub reg: &'a mut dyn Registration,
}

const DOMAIN_WARNING: &str = "This machine is joined to a domain. Domain members normally take \
     their time from a domain controller through the Windows Time service (w32time). \
     Installing stops and disables w32time.";
const UNKNOWN_WARNING: &str = "The domain join state could not be read. It is treated as \
     domain joined. Installing stops and disables the Windows Time service (w32time).";

/// Runs the install steps. Returns an [`exit`] code.
pub fn install(opts: &InstallOptions, d: &mut Deps<'_>) -> u8 {
    if let Err(e) = d.reg.ready() {
        d.host
            .say(&format!("Install refused, nothing changed: {e}"));
        return exit::REGISTER;
    }
    if let Some(code) = require_elevated(d.host, "Install") {
        return code;
    }
    if let Some(code) = domain_rule(*opts, d.host) {
        return code;
    }
    install_after_checks(d)
}

/// `None` when elevated. Else says why and gives the exit code.
fn require_elevated(host: &mut dyn Host, verb: &str) -> Option<u8> {
    match host.is_elevated() {
        Ok(true) => None,
        Ok(false) => {
            host.say(&format!(
                "{verb} needs an elevated (administrator) prompt. Nothing changed."
            ));
            Some(exit::NOT_ELEVATED)
        }
        Err(e) => {
            host.say(&format!(
                "Cannot tell whether this prompt is elevated ({e}). Nothing changed."
            ));
            Some(exit::NOT_ELEVATED)
        }
    }
}

/// The domain join rule. `None` to proceed, else the exit code.
fn domain_rule(opts: InstallOptions, host: &mut dyn Host) -> Option<u8> {
    let join = host.join_state();
    host.say(&format!("Domain join state: {}.", join.as_str()));
    if !join.counts_as_domain() {
        return None;
    }
    let warning = if join == JoinState::Domain {
        DOMAIN_WARNING
    } else {
        UNKNOWN_WARNING
    };
    if opts.confirm_domain_joined {
        host.say(&format!(
            "{warning} Proceeding: --confirm-domain-joined was given."
        ));
        None
    } else if !opts.silent && host.stdin_is_terminal() {
        host.say(warning);
        if host.ask_yes_no("Take over from w32time on this machine?") {
            None
        } else {
            host.say("Install cancelled. Nothing changed.");
            Some(exit::DECLINED)
        }
    } else {
        host.say(&format!(
            "{warning} A silent install stops here. Nothing changed. \
             Pass --confirm-domain-joined to install anyway."
        ));
        Some(exit::DOMAIN_JOINED)
    }
}

/// Install steps 4 to 7, after the checks that change nothing.
fn install_after_checks(d: &mut Deps<'_>) -> u8 {
    if let Err(e) = d.store.secure() {
        d.host.say(&format!(
            "Cannot secure the state directory ({e}). The w32time restore record cannot be kept safely. Nothing changed."
        ));
        return exit::STATE_DIR;
    }
    let existing = match d.store.load() {
        Ok(r) => r,
        Err(LoadError::Invalid(e)) => {
            d.host.say(&format!(
                "The existing w32time restore record is not valid ({e}). Nothing changed. \
                 Check the w32time start type by hand, then delete the record file."
            ));
            return exit::RECORD_INVALID;
        }
        Err(e) => {
            d.host.say(&format!("{e}. Nothing changed."));
            return exit::STATE_DIR;
        }
    };
    if existing.is_some() {
        d.host.say(
            "Found the restore record of an earlier install. It is kept as the original state.",
        );
    }

    let store = &mut *d.store;
    let record = match take_over(&mut *d.scm, existing, |r| store.save(r)) {
        Ok(r) => r,
        Err(TakeoverError::Persist(e)) => {
            d.host.say(&format!(
                "Cannot save the w32time restore record ({e}). Nothing changed."
            ));
            return exit::STATE_DIR;
        }
        Err(e) => {
            d.host
                .say(&format!("Taking over from w32time failed: {e}."));
            d.host
                .say("The restore record is kept. Run uninstall to put w32time back.");
            return exit::TAKEOVER;
        }
    };
    d.host.say(&format!(
        "w32time stopped and disabled. Original start type {}, {}.",
        record.start_type().as_str(),
        if record.was_running() {
            "was running"
        } else {
            "was stopped"
        }
    ));

    if let Err(e) = d.reg.register() {
        d.host.say(&format!(
            "Registering the service failed: {e}. Putting w32time back."
        ));
        match restore(&mut *d.scm, &record) {
            Ok(_) => match d.store.remove() {
                Ok(()) => d.host.say("w32time is back as it was."),
                Err(e) => d.host.say(&format!(
                    "w32time is back as it was. The restore record could not be removed ({e})."
                )),
            },
            Err(e) => d.host.say(&format!(
                "Putting w32time back failed: {e}. The restore record is kept. Run uninstall."
            )),
        }
        return exit::REGISTER;
    }
    d.host.say("Installed.");
    exit::OK
}

/// Runs the uninstall steps. Returns an [`exit`] code. Later steps run even
/// when an earlier one failed. The code is the most important failure:
/// `w32time` problems first.
pub fn uninstall(d: &mut Deps<'_>) -> u8 {
    if let Some(code) = require_elevated(d.host, "Uninstall") {
        return code;
    }
    let mut codes = Vec::new();

    match d.reg.stop_service() {
        Ok(OwnService::Present) => d.host.say("Service stopped."),
        Ok(OwnService::Absent) => d.host.say("Service is not installed. Continuing."),
        Err(e) => {
            // Keep going. With w32time back, a still running service sees it
            // in its 30 s check and stops adjusting the clock.
            d.host.say(&format!("Stopping the service failed: {e}."));
            codes.push(exit::UNREGISTER);
        }
    }

    match d.store.load() {
        Ok(Some(record)) => match restore(&mut *d.scm, &record) {
            Ok(out) => {
                d.host.say(&format!(
                    "w32time start type set back to {}.",
                    record.start_type().as_str()
                ));
                if out.started {
                    d.host.say("w32time started.");
                } else if out.start_skipped_disabled {
                    d.host
                        .say("w32time was running but its original start type is disabled. Left stopped.");
                }
                if let Err(e) = d.store.remove() {
                    d.host
                        .say(&format!("The restore record could not be removed ({e})."));
                    codes.push(exit::STATE_DIR);
                }
            }
            Err(e) => {
                d.host.say(&format!(
                    "Restoring w32time failed: {e}. The restore record is kept. Run uninstall again."
                ));
                codes.push(exit::RESTORE);
            }
        },
        Ok(None) => d.host.say(
            "Found no restore record. w32time is left as it is. If it is disabled, set its \
             start type in the Services console.",
        ),
        Err(LoadError::Invalid(e)) => {
            d.host.say(&format!(
                "The w32time restore record is not valid ({e}). w32time is left as it is. \
                 Check its start type by hand, then delete the record file."
            ));
            codes.push(exit::RECORD_INVALID);
        }
        Err(e) => {
            d.host.say(&format!("{e}. w32time is left as it is."));
            codes.push(exit::RESTORE);
        }
    }

    match d.reg.unregister() {
        Ok(OwnService::Present) => d.host.say("Service registration removed."),
        Ok(OwnService::Absent) => {}
        Err(e) => {
            d.host
                .say(&format!("Removing the service registration failed: {e}."));
            codes.push(exit::UNREGISTER);
        }
    }

    // Most important first: w32time, then our files, then our service.
    [
        exit::RESTORE,
        exit::RECORD_INVALID,
        exit::STATE_DIR,
        exit::UNREGISTER,
    ]
    .into_iter()
    .find(|c| codes.contains(c))
    .unwrap_or_else(|| {
        d.host.say("Uninstalled. The state directory is kept.");
        exit::OK
    })
}

/// The restore record as a file in one directory.
#[derive(Debug)]
pub struct FileRecordStore {
    dir: PathBuf,
}

impl FileRecordStore {
    /// A store in `dir`. Nothing is touched until a call.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(RECORD_FILE_NAME)
    }

    fn temp_path(&self) -> PathBuf {
        self.dir.join(RECORD_TEMP_NAME)
    }
}

/// OS error text without a path. `std` does not add paths to `io::Error`.
fn io_text(step: &str, e: &io::Error) -> String {
    format!("{step}: {e}")
}

impl RecordStore for FileRecordStore {
    #[cfg(windows)]
    fn secure(&mut self) -> Result<(), String> {
        ntpc_platform::secure_state_dir(&self.dir).map_err(|e| e.to_string())
    }

    #[cfg(not(windows))]
    fn secure(&mut self) -> Result<(), String> {
        Err("the state directory can be secured on Windows only".to_owned())
    }

    fn load(&self) -> Result<Option<Restore>, LoadError> {
        let file = match safe_open::open_read(&self.path()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(LoadError::Io(e.kind())),
        };
        let mut bytes = Vec::new();
        // One byte over the limit is enough to know it is too large.
        file.take(Restore::MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| LoadError::Io(e.kind()))?;
        Restore::decode(&bytes)
            .map(Some)
            .map_err(LoadError::Invalid)
    }

    /// Temp file, flush, rename over the target. A crash leaves the old
    /// record or the new one, never half of either.
    fn save(&mut self, r: &Restore) -> Result<(), String> {
        let temp = self.temp_path();
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_text("remove old record temp file", &e)),
        }
        let mut f =
            safe_open::create_new(&temp).map_err(|e| io_text("create record temp file", &e))?;
        if let Err(e) = f
            .write_all(r.encode().as_bytes())
            .and_then(|()| f.sync_all())
        {
            drop(f);
            let _ = fs::remove_file(&temp);
            return Err(io_text("write record temp file", &e));
        }
        drop(f);
        fs::rename(&temp, self.path()).map_err(|e| {
            let _ = fs::remove_file(&temp);
            io_text("replace record file", &e)
        })
    }

    fn remove(&mut self) -> Result<(), String> {
        match fs::remove_file(self.path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_text("remove record file", &e)),
        }
    }
}

/// The registration hook until Task 14 builds it.
///
/// TODO(Task 14): replace with a real implementation over `CreateServiceW`,
/// `ControlService` and `DeleteService`. Until then install refuses before
/// any change, and uninstall treats our service as absent so it can still
/// restore `w32time`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingRegistration;

impl Registration for PendingRegistration {
    fn ready(&self) -> Result<(), String> {
        Err("service registration is not built yet (it arrives with the service host)".to_owned())
    }
    fn register(&mut self) -> Result<(), String> {
        self.ready()
    }
    fn stop_service(&mut self) -> Result<OwnService, String> {
        Ok(OwnService::Absent)
    }
    fn unregister(&mut self) -> Result<OwnService, String> {
        Ok(OwnService::Absent)
    }
}

/// The real console.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ConsoleHost;

#[cfg(windows)]
impl Host for ConsoleHost {
    fn is_elevated(&self) -> Result<bool, String> {
        ntpc_platform::is_elevated().map_err(|e| e.to_string())
    }
    fn join_state(&self) -> JoinState {
        ntpc_platform::join_state()
    }
    fn stdin_is_terminal(&self) -> bool {
        use std::io::IsTerminal;
        io::stdin().is_terminal()
    }
    fn ask_yes_no(&mut self, question: &str) -> bool {
        print!("{question} [y/N] ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        // A read error or end of input is a no.
        if io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
    fn say(&mut self, line: &str) {
        println!("{line}");
    }
}

/// The default state directory. The record always lives here, whatever the
/// config says, so uninstall finds it even when the config is gone.
fn state_dir() -> PathBuf {
    crate::config::Config::default().state_dir
}

/// `install` from the command line. Returns an [`exit`] code.
#[must_use]
pub fn run_install(args: &[String]) -> u8 {
    let opts = match parse_install_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return exit::USAGE;
        }
    };
    run_install_real(opts)
}

/// `uninstall` from the command line. Returns an [`exit`] code.
#[must_use]
pub fn run_uninstall(args: &[String]) -> u8 {
    if let Err(e) = parse_uninstall_args(args) {
        eprintln!("{e}");
        return exit::USAGE;
    }
    run_uninstall_real()
}

#[cfg(windows)]
fn run_install_real(opts: InstallOptions) -> u8 {
    install(
        &opts,
        &mut Deps {
            host: &mut ConsoleHost,
            store: &mut FileRecordStore::new(state_dir()),
            scm: &mut ntpc_platform::ScmControl,
            reg: &mut PendingRegistration,
        },
    )
}

#[cfg(windows)]
fn run_uninstall_real() -> u8 {
    uninstall(&mut Deps {
        host: &mut ConsoleHost,
        store: &mut FileRecordStore::new(state_dir()),
        scm: &mut ntpc_platform::ScmControl,
        reg: &mut PendingRegistration,
    })
}

#[cfg(not(windows))]
fn run_install_real(_opts: InstallOptions) -> u8 {
    let _ = state_dir();
    eprintln!("install runs on Windows only");
    exit::USAGE
}

#[cfg(not(windows))]
fn run_uninstall_real() -> u8 {
    eprintln!("uninstall runs on Windows only");
    exit::USAGE
}

#[cfg(test)]
mod tests;
