//! Start-up steps and log texts, kept apart from the loop.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};

use ntpc_core::Ppm;

use super::{AdapterKey, DhcpSource, DriftFile, Inner, JoinClass, Msg, SecureOutcome};
use crate::config::Config;
use crate::logging::{Level, Logger};
use crate::resolver::ResolveNote;

/// Name of the DHCP reader thread.
const DHCP_THREAD: &str = "ntpc-dhcp";

/// The start lines: version, join state, active config and its warnings.
pub(super) fn log_start(cfg: &Config, join: &dyn super::JoinStateProvider, logger: &dyn Logger) {
    logger.log(
        Level::Info,
        "start",
        &format!("ntptimeclient-winrs {} starting", env!("CARGO_PKG_VERSION")),
    );
    let join_text = match join.join_state() {
        JoinClass::Workgroup => "workgroup",
        JoinClass::Domain => "domain joined",
        JoinClass::Unknown => "unknown",
    };
    logger.log(
        Level::Info,
        "join_state",
        &format!("join state: {join_text}"),
    );
    logger.log(Level::Info, "config", &config_line(cfg));
    for w in cfg.warnings() {
        logger.log(
            Level::Warn,
            "config_warning",
            &format!("config warning: {w}"),
        );
    }
}

/// Secures the state directory and logs the outcome. True if persistence
/// is on.
pub(super) fn secure_state_dir(state_dir: &dyn super::StateDir, logger: &dyn Logger) -> bool {
    match state_dir.secure() {
        SecureOutcome::Ok => {
            logger.log(Level::Info, "state_dir", "state directory secured");
            true
        }
        SecureOutcome::RestoreDropped => {
            logger.log(
                Level::Warn,
                "state_dir",
                "state directory secured. The w32time restore record was not trusted and \
                 was dropped, so uninstall cannot restore the original w32time state",
            );
            true
        }
        SecureOutcome::Refused { reason } => {
            logger.log(
                Level::Error,
                "state_dir",
                &format!(
                    "state directory could not be secured ({reason}). Persistence is off: \
                     no drift or status file. Timekeeping goes on"
                ),
            );
            false
        }
    }
}

/// Loads the saved drift and logs the note.
pub(super) fn load_drift(drift: &dyn DriftFile, logger: &dyn Logger) -> Option<Ppm> {
    match drift.load_checked() {
        Ok(p) => {
            logger.log(
                Level::Info,
                "drift_load",
                &format!("loaded drift {:+.3} ppm", p.value()),
            );
            Some(p)
        }
        Err(note) => {
            let level = if note == crate::drift_store::LoadNote::Missing {
                Level::Info
            } else {
                Level::Warn
            };
            logger.log(level, "drift_load", &format!("no saved drift: {note}"));
            None
        }
    }
}

pub(super) fn start_dhcp_reader(
    source: Arc<dyn DhcpSource>,
    tx: Sender<Msg>,
    logger: &dyn Logger,
) -> Option<Sender<BTreeSet<AdapterKey>>> {
    let (req_tx, req_rx) = mpsc::channel::<BTreeSet<AdapterKey>>();
    let spawned = std::thread::Builder::new()
        .name(DHCP_THREAD.to_owned())
        .spawn(move || {
            // Ends when the loop drops its sender, or when the loop is gone.
            while let Ok(skip) = req_rx.recv() {
                let result = source.read(&skip);
                if tx.send(Msg(Inner::Dhcp(result))).is_err() {
                    break;
                }
            }
        });
    match spawned {
        Ok(_) => Some(req_tx),
        Err(e) => {
            logger.log(
                Level::Error,
                "dhcp",
                &format!("could not start the DHCP reader thread: {e}. DHCP is off"),
            );
            None
        }
    }
}

/// The active config, keys and values. The state directory is named only
/// as default or custom, so no path reaches the log.
pub(super) fn config_line(cfg: &Config) -> String {
    let default_dir = Config::default().state_dir;
    format!(
        "config: servers [{}], dhcp {}, pool {}, step_threshold_ms {}, panic_threshold_s {}, \
         allow_panic_step {}, min_poll_s {}, max_poll_s {}, state_dir {}",
        cfg.servers.join(", "),
        if cfg.dhcp { "on" } else { "off" },
        cfg.pool,
        cfg.step_threshold_ms,
        cfg.panic_threshold_s,
        cfg.allow_panic_step,
        cfg.min_poll_s,
        cfg.max_poll_s,
        if cfg.state_dir == default_dir {
            "default"
        } else {
            "custom"
        }
    )
}

pub(super) fn resolve_note(n: &ResolveNote) -> (Level, String) {
    match n {
        ResolveNote::LookupFailed { name, kind, code } => (
            Level::Warn,
            match code {
                Some(c) => format!("lookup of {name} failed: {kind} (OS error {c})"),
                None => format!("lookup of {name} failed: {kind}"),
            },
        ),
        ResolveNote::KeptPrevious { name } => (
            Level::Info,
            format!("keeping the previous addresses of {name}"),
        ),
        ResolveNote::NoUsableAddresses { name } => {
            (Level::Warn, format!("{name} gave no usable address"))
        }
        ResolveNote::NameCapped { name, dropped } => (
            Level::Info,
            format!("{name}: {dropped} addresses over the per-name cap were dropped"),
        ),
        ResolveNote::TierCapped { tier, dropped } => (
            Level::Info,
            format!(
                "{} tier: {dropped} addresses over the per-tier cap were dropped",
                crate::logging::tier_label(Some(*tier))
            ),
        ),
        ResolveNote::PreviousExpired { name } => (
            Level::Warn,
            format!("the cached addresses of {name} expired after 24 h of failed lookups"),
        ),
        ResolveNote::IdsExhausted => (
            Level::Error,
            "source ids ran out. Some addresses were skipped".to_owned(),
        ),
    }
}
