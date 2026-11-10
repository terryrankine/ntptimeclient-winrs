//! The command line: parsing, the config file, `status`, `run` and
//! `service`. `install` and `uninstall` live in `cli`.
//!
//! Config file location (decided in Task 14c-B): `config.toml` in the
//! folder of the running exe. Why there:
//! - The exe folder must already be administrators-only (install refuses
//!   otherwise, exit 20, and the Task 15 wrapper checks it too). A config
//!   file there adds no new place to protect.
//! - The state directory cannot hold it: it is the secured directory and
//!   any unknown child is refused (`KNOWN_CHILDREN` has no config file).
//! - A separate folder under `ProgramData` would be a new trust root: any
//!   user can create folders in `ProgramData`, so a user could plant a
//!   config before the admin creates it.
//!
//! `install`, `uninstall` and `service` always use that file, so the
//! service and the installer agree on the state directory. `run` and
//! `status` accept `--config <path>` for development. A missing file means
//! the defaults. The file is read through `safe_open` (no link following,
//! a link is refused) and capped at 64 KiB by `Config::load`.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::{Config, ConfigError};
use crate::status::{StatusError, format_status, read_status};

/// The config file name, next to the exe.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Exit codes of the commands outside `install` and `uninstall`. They
/// follow on from `cli::exit` (0 to 21) and stay below the Task 15
/// wrapper's 40 to 47.
pub mod exit {
    /// `status`: there is no `status.json` (the service has not run, or the
    /// state directory is elsewhere).
    pub const STATUS_MISSING: u8 = 22;
    /// `status`: `status.json` is there but is not valid, too large, or
    /// could not be read.
    pub const STATUS_INVALID: u8 = 23;
    /// `status`: access denied. The state directory is readable by SYSTEM
    /// and Administrators only, so `status` needs an elevated prompt.
    pub const STATUS_DENIED: u8 = 24;
    /// The config file could not be read or breaks a rule.
    pub const CONFIG: u8 = 25;
    /// `service` was run by hand, not by the service control manager.
    pub const NOT_SCM: u8 = 26;
    /// `run` or `service`: the Windows host adapters are not built into
    /// this exe.
    pub const HOST_NOT_BUILT: u8 = 27;
    /// `run`: the host ended with an error.
    pub const RUN_FAILED: u8 = 28;
    /// `service`: the dispatcher failed for another reason.
    pub const SERVICE_FAILED: u8 = 29;
    /// `run`: our service is running (or its state cannot be read). Two
    /// instances must never adjust one clock.
    pub const RUN_CONFLICT: u8 = 30;

    /// Every code here, for tests.
    pub const ALL: [u8; 9] = [
        STATUS_MISSING,
        STATUS_INVALID,
        STATUS_DENIED,
        CONFIG,
        NOT_SCM,
        HOST_NOT_BUILT,
        RUN_FAILED,
        SERVICE_FAILED,
        RUN_CONFLICT,
    ];
}

/// `--help` text. It lists every subcommand by name: the Task 15 release
/// workflow refuses an exe whose help lacks `install` and `uninstall`.
pub const HELP: &str = "\
usage: ntptimeclient-winrs <command> [options]

commands:
  install     register and start the service, stop and disable w32time (elevated)
  uninstall   stop and remove the service, put w32time back (elevated)
  status      print the last status the service wrote (elevated)
  run         run in this console until Ctrl+C (development)
  service     the entry point the service control manager uses

options:
  --config <path>   config file for run and status
                    (default: config.toml next to the exe)
  -h, --help        print this text

install options:   --silent --confirm-domain-joined --accept-disabled-original
uninstall options: --silent

Exit codes are listed in docs/architecture.md.";

/// One parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `--help` or `-h`.
    Help,
    /// `install` with its own arguments.
    Install(Vec<String>),
    /// `uninstall` with its own arguments.
    Uninstall(Vec<String>),
    /// `status`.
    Status {
        /// `--config`, if given.
        config: Option<PathBuf>,
    },
    /// `run`.
    Run {
        /// `--config`, if given.
        config: Option<PathBuf>,
    },
    /// `service`.
    Service,
}

/// The usage line for errors.
pub const USAGE: &str = "usage: ntptimeclient-winrs <install|uninstall|status|run|service> \
     [options]. Run with --help for details.";

/// Parses the arguments after the exe name.
///
/// # Errors
/// One line saying what is wrong, ending with the usage line.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some(first) = args.first() else {
        return Err(format!("no command given. {USAGE}"));
    };
    let rest = &args[1..];
    match first.as_str() {
        "-h" | "--help" if rest.is_empty() => Ok(Command::Help),
        "install" => Ok(Command::Install(rest.to_vec())),
        "uninstall" => Ok(Command::Uninstall(rest.to_vec())),
        "status" => Ok(Command::Status {
            config: parse_config_only(rest)?,
        }),
        "run" => Ok(Command::Run {
            config: parse_config_only(rest)?,
        }),
        "service" if rest.is_empty() => Ok(Command::Service),
        _ => Err(format!("unknown command or argument. {USAGE}")),
    }
}

fn parse_config_only(rest: &[String]) -> Result<Option<PathBuf>, String> {
    match rest {
        [] => Ok(None),
        [flag, path] if flag == "--config" && !path.is_empty() && !path.starts_with("--") => {
            Ok(Some(PathBuf::from(path)))
        }
        _ => Err(format!("unknown argument. {USAGE}")),
    }
}

/// The default config path: [`CONFIG_FILE_NAME`] in `exe_dir`.
#[must_use]
pub fn default_config_path(exe_dir: &Path) -> PathBuf {
    exe_dir.join(CONFIG_FILE_NAME)
}

/// A config error as text without any path, for the Event Log and for
/// messages that may be copied into a ticket.
#[must_use]
pub fn config_error_text(e: &ConfigError) -> String {
    match e {
        ConfigError::Read { kind, .. } => format!("cannot read the config file: {kind}"),
        ConfigError::NotUtf8 { .. } => "the config file is not valid UTF-8".to_owned(),
        other => other.to_string(),
    }
}

/// Loads the config at `path`. A missing file gives the defaults. Any
/// other problem is an error: a config that exists but cannot be read must
/// not silently become the defaults.
///
/// # Errors
/// The path-free text of the problem.
pub fn load_config(path: &Path) -> Result<Config, String> {
    match Config::load(path) {
        Ok(c) => Ok(c),
        Err(ConfigError::Read {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => Ok(Config::default()),
        Err(e) => Err(config_error_text(&e)),
    }
}

/// `status`: reads `status.json` in the state directory of `cfg` and prints
/// the summary. Returns the exit code.
pub fn status_command(cfg: &Config, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let path = cfg.state_dir.join(crate::status::FILE_NAME);
    report_status(read_status(&path), out, err)
}

/// Prints a read result and gives the exit code.
pub fn report_status(
    read: Result<crate::status::StatusReport, StatusError>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    match read {
        Ok(r) => {
            let _ = write!(out, "{}", format_status(&r));
            crate::cli::exit::OK
        }
        Err(StatusError::Io(std::io::ErrorKind::NotFound)) => {
            let _ = writeln!(
                err,
                "No status file. The service has not written one yet, or the config names \
                 another state directory."
            );
            exit::STATUS_MISSING
        }
        Err(StatusError::Io(std::io::ErrorKind::PermissionDenied)) => {
            let _ = writeln!(
                err,
                "Access denied. The state directory is readable by SYSTEM and Administrators \
                 only. Run status from an elevated prompt."
            );
            exit::STATUS_DENIED
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "The status file cannot be used: {e}. It may be damaged or written by \
                 another version. The service rewrites it every 30 s."
            );
            exit::STATUS_INVALID
        }
    }
}

/// The whole command line: parse, then run. Returns the exit code.
/// No arguments, an unknown command or a bad argument print one usage line
/// on `err` and exit [`cli::exit::USAGE`](crate::cli::exit::USAGE).
pub fn main_entry(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let cmd = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return crate::cli::exit::USAGE;
        }
    };
    execute(cmd, out, err)
}

#[cfg(windows)]
fn execute(cmd: Command, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    real::execute(cmd, out, err)
}

#[cfg(not(windows))]
fn execute(cmd: Command, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if cmd == Command::Help {
        let _ = writeln!(out, "{HELP}");
        return crate::cli::exit::OK;
    }
    let _ = writeln!(err, "this command runs on Windows only");
    crate::cli::exit::USAGE
}

#[cfg(windows)]
mod real;

#[cfg(test)]
mod tests;
