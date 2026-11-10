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
//!    (`--silent`, or stdin or stderr not a console, R83) aborts unless
//!    `--confirm-domain-joined` is given. An interactive install warns and
//!    asks on stderr, default no.
//! 4. Secure the state directory. Refuse if it cannot be secured: a
//!    stopped `w32time` with no restore record is worse than no install.
//!    Each refusal class has its own exit code. A dropped restore record
//!    (it failed the provenance checks and stays in the quarantine) refuses
//!    too (R86): recording the current state would lose the real original.
//! 5. Load an existing record. A tampered one refuses and changes nothing.
//!    With no record and `w32time` already disabled, refuse unless
//!    `--accept-disabled-original` (R84): a lost record must not turn
//!    "disabled" into the original for ever. This check needs to know
//!    whether a record exists, so it runs after step 4. On exit 12 the state
//!    directory may therefore have been created and secured. `w32time` is
//!    not changed and no record is written.
//! 6. Take over `w32time`. The record is written before anything changes.
//!    If the takeover fails before any change, the record this run wrote is
//!    removed again (M8).
//! 7. Register our service (Task 14 hook). On failure `w32time` is put back.
//!
//! Uninstall: stop our service (hook), secure the state directory and read
//! the record with the provenance checks (R86), restore `w32time` from it,
//! remove the registration (hook). A directory or record that cannot be
//! trusted leaves `w32time` alone (exit 17) with a manual restore hint that
//! guesses no start type. It restores even if our service is
//! missing. Without a record `w32time` is left as it is: guessing a start
//! type could undo an administrator's choice. The state directory stays.
//!
//! Messages carry no paths, machine names, user names or domain names.

use std::io::{self, Write};
use std::path::Path;

use crate::config::Config;

use ntpc_platform::JoinState;
use ntpc_platform::w32time::{
    Restore, RestoreFormatError, ServiceControl, StartType, TakeoverError, W32TIME, restore,
    take_over,
};
use thiserror::Error;

mod console;
mod record_file;

#[cfg(windows)]
pub use console::ConsoleHost;
pub use console::{Console, MAX_ANSWER_BYTES, read_answer};
pub use record_file::{FileRecordStore, RECORD_FILE_NAME, RECORD_TEMP_NAME};

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
    /// Our service registration is not built yet: install refused before
    /// any change. Or registering failed after the takeover: `w32time` was
    /// put back (the message says whether that worked).
    pub const REGISTER: u8 = 9;
    /// Uninstall could not restore `w32time`. The record stays.
    pub const RESTORE: u8 = 10;
    /// Uninstall could not stop or remove our service registration.
    pub const UNREGISTER: u8 = 11;
    /// No restore record and `w32time` is already disabled, without
    /// `--accept-disabled-original`. `w32time` was not changed. Distinct from
    /// the packaging wrapper's own codes 40 to 47.
    pub const DISABLED_ORIGINAL: u8 = 12;
    /// Install: a previous restore record existed but could not be trusted
    /// and stays in the quarantine directory. Nothing changed.
    pub const RECORD_DROPPED: u8 = 13;
    /// Install: replacing a weak state directory failed and so did moving
    /// the old one back. A restore record may be in a sibling quarantine
    /// directory. Nothing changed. See the recovery steps in the docs.
    pub const ROLLBACK_FAILED: u8 = 14;
    /// Install: the restore record could not be carried into the fresh
    /// state directory. Nothing on `w32time` changed.
    pub const CARRY_FAILED: u8 = 15;
    /// Install: the configured state directory path is not acceptable
    /// (reserved name, colon, trailing dot or space, not absolute, not a
    /// fixed drive). Nothing changed.
    pub const BAD_STATE_PATH: u8 = 16;
    /// Install or uninstall: the state directory or the restore record could
    /// not be trusted (R86). `w32time` was left alone.
    pub const RECORD_NOT_TRUSTED: u8 = 17;

    /// Every code, for tests.
    pub const ALL: [u8; 17] = [
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
        DISABLED_ORIGINAL,
        RECORD_DROPPED,
        ROLLBACK_FAILED,
        CARRY_FAILED,
        BAD_STATE_PATH,
        RECORD_NOT_TRUSTED,
    ];
}

/// Install flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallOptions {
    /// Never ask. Also implied when stdin or stderr is not a console.
    pub silent: bool,
    /// Proceed on a domain-joined machine without asking.
    pub confirm_domain_joined: bool,
    /// Proceed with no restore record while `w32time` is already disabled,
    /// and record "disabled" as the original.
    pub accept_disabled_original: bool,
}

const INSTALL_USAGE: &str =
    "usage: install [--silent] [--confirm-domain-joined] [--accept-disabled-original]";
const UNINSTALL_USAGE: &str = "usage: uninstall [--silent]";

/// Parses the arguments after `install`. Each flag at most once.
///
/// # Errors
/// The usage text with the offending argument.
pub fn parse_install_args(args: &[String]) -> Result<InstallOptions, String> {
    let mut o = InstallOptions {
        silent: false,
        confirm_domain_joined: false,
        accept_disabled_original: false,
    };
    for a in args {
        let slot = match a.as_str() {
            "--silent" => &mut o.silent,
            "--confirm-domain-joined" => &mut o.confirm_domain_joined,
            "--accept-disabled-original" => &mut o.accept_disabled_original,
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
    /// Whether a question can be asked and seen: stdin and stderr are both
    /// consoles (R83).
    fn is_interactive(&self) -> bool;
    /// Asks a yes or no question on stderr. Anything but yes is no.
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
    /// The file failed a provenance check before it was read (R86).
    #[error("the restore record cannot be trusted: {0}")]
    NotTrusted(TrustFailure),
}

/// Which provenance check a restore record file failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrustFailure {
    /// It is a directory.
    #[error("it is not a plain file")]
    NotAFile,
    /// It is a reparse point.
    #[error("it is a link or reparse point")]
    Reparse,
    /// It has more than one hard link.
    #[error("it has more than one hard link")]
    Links,
    /// It is larger than the record cap.
    #[error("it is larger than a restore record can be")]
    TooLarge,
    /// It is not owned by SYSTEM or Administrators.
    #[error("it is not owned by SYSTEM or Administrators")]
    Owner,
}

/// Why the state directory was not accepted, by class. Text holds no path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SecureRefusal {
    /// The directory or a parent failed a check, or an OS call failed.
    #[error("the state directory cannot be secured: {0}")]
    Directory(String),
    /// The configured path is not acceptable.
    #[error("the state directory path is not acceptable: {0}")]
    BadPath(String),
    /// Replacing a weak directory failed and moving the old one back failed.
    #[error("{0}")]
    RollbackFailed(String),
    /// The restore record could not be carried into a fresh directory.
    #[error("{0}")]
    CarryFailed(String),
    /// A previous restore record failed its checks and stays in quarantine.
    #[error("a previous restore record could not be trusted")]
    RecordDropped,
}

impl SecureRefusal {
    /// The install exit code for this class.
    #[must_use]
    pub const fn install_code(&self) -> u8 {
        match self {
            Self::Directory(_) => exit::STATE_DIR,
            Self::BadPath(_) => exit::BAD_STATE_PATH,
            Self::RollbackFailed(_) => exit::ROLLBACK_FAILED,
            Self::CarryFailed(_) => exit::CARRY_FAILED,
            Self::RecordDropped => exit::RECORD_DROPPED,
        }
    }

    /// What the administrator should do. No paths.
    #[must_use]
    pub const fn advice(&self) -> &'static str {
        match self {
            Self::Directory(_) => {
                "Check the state directory and its parents (owner SYSTEM or Administrators, \
                 no links), then run again."
            }
            Self::BadPath(_) => "Fix the state_dir setting in the config file, then run again.",
            Self::RollbackFailed(_) => {
                "A restore record may be in a sibling quarantine directory. See the \
                 RollbackFailed recovery steps in the documentation before running again."
            }
            Self::CarryFailed(_) => {
                "The restore record could not be moved into the fresh state directory. \
                 Check the state directory and run again."
            }
            Self::RecordDropped => {
                "A previous restore record could not be trusted. Restore w32time by hand \
                 first, then run install again, or remove the quarantine directory and the \
                 state directory after checking them."
            }
        }
    }
}

/// Maps a platform refusal to its class. The enum is non-exhaustive: any
/// variant added later lands in the safe `Directory` class.
#[cfg(windows)]
#[must_use]
pub fn classify_acl_error(e: &ntpc_platform::AclError) -> SecureRefusal {
    use ntpc_platform::AclError as A;
    let text = e.to_string();
    match e {
        A::BadPath | A::TrailingDotOrSpace | A::ReservedName | A::NotFixedDrive => {
            SecureRefusal::BadPath(text)
        }
        A::RollbackFailed { .. } => SecureRefusal::RollbackFailed(text),
        A::RestoreCarryFailed { .. } => SecureRefusal::CarryFailed(text),
        // PathChanged, Link, ParentLink, NotADirectory, UntrustedOwner,
        // UntrustedParent, UnexpectedChild, DaclNotApplied, Os, and any
        // variant added later: the directory is refused.
        _ => SecureRefusal::Directory(text),
    }
}

/// How to put `w32time` back by hand. Guesses no start type: the right one
/// is whatever it was before install, which only the record knew.
pub const MANUAL_RESTORE: &str = "To put w32time back by hand: open Services (services.msc), \
     open Windows Time, set the startup type it had before this tool was installed, and start \
     it if it was running before.";

/// Where the restore record lives.
pub trait RecordStore {
    /// Secures the state directory before the record is read or written.
    /// A dropped record is a refusal.
    ///
    /// # Errors
    /// [`SecureRefusal`] by class.
    fn secure(&mut self) -> Result<(), SecureRefusal>;
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
    install_after_checks(*opts, d)
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
    } else if !opts.silent && host.is_interactive() {
        host.say(warning);
        if host.ask_yes_no("Take over from w32time on this machine?") {
            None
        } else {
            host.say("Install cancelled. Nothing changed.");
            Some(exit::DECLINED)
        }
    } else {
        host.say(&format!(
            "{warning} No question can be asked here (silent, or stdin or stderr is not a \
             console). Install stops. Nothing changed. To install anyway pass \
             --confirm-domain-joined to the exe, or -ConfirmDomainJoined to the install script."
        ));
        Some(exit::DOMAIN_JOINED)
    }
}

/// Install steps 4 to 7, after the checks that change nothing.
fn install_after_checks(opts: InstallOptions, d: &mut Deps<'_>) -> u8 {
    if let Err(e) = d.store.secure() {
        d.host.say(&format!(
            "Install refused: {e}. {} w32time was not changed.",
            e.advice()
        ));
        return e.install_code();
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
        Err(e @ LoadError::NotTrusted(_)) => {
            d.host.say(&format!(
                "{e}. Nothing changed. {MANUAL_RESTORE} Then delete the record file."
            ));
            return exit::RECORD_NOT_TRUSTED;
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
    } else if let Some(code) = disabled_original_rule(opts, d) {
        return code;
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
            report_failed_takeover(&e, existing.is_none(), d);
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

/// R84: no record and `w32time` already disabled. Refuse unless the flag
/// says the disabled state really is the original. A query error is left to
/// the takeover, which reports it.
fn disabled_original_rule(opts: InstallOptions, d: &mut Deps<'_>) -> Option<u8> {
    let Ok(now) = d.scm.query(W32TIME) else {
        return None;
    };
    if now.start != StartType::Disabled {
        return None;
    }
    if opts.accept_disabled_original {
        d.host.say(
            "w32time is already disabled and there is no restore record. Recording disabled \
             as the original: --accept-disabled-original was given.",
        );
        return None;
    }
    d.host.say(
        "w32time is already disabled and there is no restore record. An earlier record may \
         have been lost, and recording disabled now would make uninstall leave w32time \
         disabled. w32time was not changed. Set its start type by hand and run install again, \
         or pass --accept-disabled-original if disabled really is the original.",
    );
    Some(exit::DISABLED_ORIGINAL)
}

/// M8: a takeover that failed before any change removes the record this
/// run wrote, so it cannot later win over an administrator's change. A
/// pre-existing record is never removed here.
fn report_failed_takeover(e: &TakeoverError, record_is_new: bool, d: &mut Deps<'_>) {
    if !e.changed_nothing() {
        d.host.say(
            "w32time may have been changed. The restore record is kept. Run uninstall to put \
             w32time back.",
        );
        return;
    }
    if !record_is_new {
        d.host
            .say("Nothing on w32time changed. The earlier restore record is kept.");
        return;
    }
    match d.store.remove() {
        Ok(()) => d
            .host
            .say("Nothing on w32time changed. The new restore record was removed."),
        Err(re) => d.host.say(&format!(
            "Nothing on w32time changed. The new restore record could not be removed ({re})."
        )),
    }
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

    match d.store.secure() {
        Ok(()) => restore_from_record(d, &mut codes),
        Err(e) => {
            d.host.say(&format!(
                "{e}. The restore record cannot be trusted. w32time is left as it is. {} {MANUAL_RESTORE}",
                e.advice()
            ));
            codes.push(exit::RECORD_NOT_TRUSTED);
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
        exit::RECORD_NOT_TRUSTED,
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

/// Uninstall step: read the record from the secured directory and restore
/// `w32time` from it. Pushes failure codes.
fn restore_from_record(d: &mut Deps<'_>, codes: &mut Vec<u8>) {
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
        Err(e @ LoadError::NotTrusted(_)) => {
            d.host.say(&format!(
                "{e}. w32time is left as it is. {MANUAL_RESTORE} Then delete the record file."
            ));
            codes.push(exit::RECORD_NOT_TRUSTED);
        }
        Err(e) => {
            d.host.say(&format!("{e}. w32time is left as it is."));
            codes.push(exit::RESTORE);
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

/// The line `--help` prints. It does not list `install` or `uninstall` yet:
/// the release gate must stay red until Task 14 makes them real (R85).
pub const HELP: &str = "usage: ntptimeclient-winrs (pre-alpha: no subcommands are available yet)";

/// Dispatches the command line. `config` gives the state directory
/// (`Config.state_dir`, R86). No arguments keeps the pre-alpha stub
/// (exit 0). `--help` prints [`HELP`] (exit 0). An unknown subcommand or
/// argument prints one usage line to `err` and exits [`exit::USAGE`] (M6).
pub fn dispatch(args: &[String], config: &Config, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match args.first().map(String::as_str) {
        None => {
            let _ = writeln!(
                out,
                "{} (pre-alpha, no service logic yet)",
                crate::CRATE_NAME
            );
            exit::OK
        }
        Some("--help" | "-h") if args.len() == 1 => {
            let _ = writeln!(out, "{HELP}");
            exit::OK
        }
        Some("install") => run_install(&args[1..], config),
        Some("uninstall") => run_uninstall(&args[1..], config),
        Some(_) => {
            let _ = writeln!(err, "unknown subcommand or argument. Run with --help.");
            exit::USAGE
        }
    }
}

/// `install` from the command line. Returns an [`exit`] code.
#[must_use]
pub fn run_install(args: &[String], config: &Config) -> u8 {
    let opts = match parse_install_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return exit::USAGE;
        }
    };
    run_install_real(opts, &config.state_dir)
}

/// `uninstall` from the command line. Returns an [`exit`] code.
#[must_use]
pub fn run_uninstall(args: &[String], config: &Config) -> u8 {
    if let Err(e) = parse_uninstall_args(args) {
        eprintln!("{e}");
        return exit::USAGE;
    }
    run_uninstall_real(&config.state_dir)
}

#[cfg(windows)]
fn run_install_real(opts: InstallOptions, state_dir: &Path) -> u8 {
    install(
        &opts,
        &mut Deps {
            host: &mut ConsoleHost::new(),
            store: &mut FileRecordStore::new(state_dir),
            scm: &mut ntpc_platform::ScmControl,
            reg: &mut PendingRegistration,
        },
    )
}

#[cfg(windows)]
fn run_uninstall_real(state_dir: &Path) -> u8 {
    uninstall(&mut Deps {
        host: &mut ConsoleHost::new(),
        store: &mut FileRecordStore::new(state_dir),
        scm: &mut ntpc_platform::ScmControl,
        reg: &mut PendingRegistration,
    })
}

#[cfg(not(windows))]
fn run_install_real(_opts: InstallOptions, _state_dir: &Path) -> u8 {
    eprintln!("install runs on Windows only");
    exit::USAGE
}

#[cfg(not(windows))]
fn run_uninstall_real(_state_dir: &Path) -> u8 {
    eprintln!("uninstall runs on Windows only");
    exit::USAGE
}

#[cfg(test)]
mod tests;
