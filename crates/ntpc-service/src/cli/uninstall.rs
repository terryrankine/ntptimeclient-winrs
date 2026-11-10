//! The `uninstall` steps.
//!
//! Order (R94): stop our service, put `w32time` back, then remove our
//! registration. When `w32time` was not put back (the restore failed, or no
//! usable record exists while `w32time` is disabled) the registration is
//! kept: the machine keeps our time sync instead of having none.
//!
//! The record is read only from a directory `secure_state_dir` verified,
//! and only after the file passed the provenance checks (R86). A missing
//! state directory is not created: it means there is no record.

use ntpc_platform::w32time::{StartType, W32TIME, restore};

use super::{
    Deps, DirState, LoadError, MANUAL_RESTORE, OwnService, SecureRefusal, exit, require_elevated,
};

/// Runs the uninstall steps. Returns an [`exit`] code. The code is the most
/// important failure: `w32time` problems first.
pub fn uninstall(d: &mut Deps<'_>) -> u8 {
    if let Some(code) = require_elevated(d.host, "Uninstall") {
        return code;
    }
    if let Err(e) = d.reg.check_ours() {
        d.host
            .say(&format!("Uninstall refused, nothing changed: {e}."));
        return exit::FOREIGN_SERVICE;
    }
    let mut codes = Vec::new();
    let mut stopped_ours = false;

    match d.reg.stop_service() {
        Ok(OwnService::Present) => {
            stopped_ours = true;
            d.host.say("Service stopped.");
        }
        Ok(OwnService::Absent) => d.host.say("Service is not installed. Continuing."),
        Ok(OwnService::WasStopped) => d.host.say("Service is installed and was not running."),
        Err(e) => {
            // Keep going. With w32time back, a still running service sees it
            // in its 30 s check and stops adjusting the clock.
            d.host.say(&format!("Stopping the service failed: {e}."));
            codes.push(exit::UNREGISTER);
        }
    }

    restore_step(d, &mut codes);

    let w32time_not_back =
        codes.contains(&exit::RESTORE) || codes.contains(&exit::NO_RECORD_DISABLED);
    if w32time_not_back {
        d.host.say(
            "w32time was not put back, so the service registration is kept. Put w32time back \
             by hand, then run uninstall again.",
        );
        if stopped_ours {
            restart_ours(d);
        }
    } else {
        match d.reg.unregister() {
            Ok(OwnService::Present | OwnService::WasStopped) => {
                d.host.say("Service registration removed.");
            }
            Ok(OwnService::Absent) => {}
            Err(e) => {
                d.host
                    .say(&format!("Removing the service registration failed: {e}."));
                codes.push(exit::UNREGISTER);
            }
        }
    }

    [
        exit::RESTORE,
        exit::NO_RECORD_DISABLED,
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

/// R94 concern: our service was stopped at the start and `w32time` is not
/// back, so without this the machine has no time service until the next
/// boot. Only a service this run stopped is started again.
fn restart_ours(d: &mut Deps<'_>) {
    match d.reg.start_service() {
        Ok(()) => d.host.say(
            "Our service was started again, so this machine keeps time sync until w32time is \
             put back.",
        ),
        Err(e) => d.host.say(&format!(
            "Our service could not be started again: {e}. This machine has no time sync until \
             it is started. Start it by hand with: sc.exe start {}",
            crate::registration::SERVICE_NAME
        )),
    }
}

/// What uninstall says for a refusal while securing. Its own words, not
/// install's: nothing is installed again here (N3).
fn uninstall_advice(e: &SecureRefusal) -> &'static str {
    match e {
        SecureRefusal::RecordDropped => {
            "It may be in a sibling directory whose name is the state directory name with \
             .old- and a hex suffix."
        }
        SecureRefusal::RollbackFailed(_) => {
            "A restore record may be in a sibling quarantine directory. See the RollbackFailed \
             recovery steps in the documentation."
        }
        SecureRefusal::Directory(_) => {
            "The state directory could not be checked, so its restore record cannot be trusted."
        }
        SecureRefusal::BadPath(_) => "The state_dir setting in the config file is not acceptable.",
        SecureRefusal::CarryFailed(_) => {
            "The restore record could not be moved into a fresh state directory."
        }
    }
}

/// Finds the record and restores `w32time` from it. Pushes failure codes.
fn restore_step(d: &mut Deps<'_>, codes: &mut Vec<u8>) {
    match d.store.dir_state() {
        DirState::ParentMissing => {
            d.host.say(
                "State directory unavailable: its parent folder does not exist. So there is no \
                 restore record.",
            );
            return flag_if_disabled(d, codes, false);
        }
        DirState::Missing => {
            d.host
                .say("There is no state directory, so there is no restore record.");
            return flag_if_disabled(d, codes, false);
        }
        DirState::Present => {}
    }
    if let Err(e) = d.store.secure() {
        d.host.say(&format!(
            "{e}. {} w32time is left as it is. {MANUAL_RESTORE}",
            uninstall_advice(&e)
        ));
        codes.push(exit::RECORD_NOT_TRUSTED);
        return flag_if_disabled(d, codes, true);
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
                    d.host.say(
                        "w32time was running but its original start type is disabled. Left \
                         stopped.",
                    );
                }
                if let Err(e) = d.store.remove() {
                    d.host
                        .say(&format!("The restore record could not be removed ({e})."));
                    codes.push(exit::STATE_DIR);
                }
            }
            Err(e) => {
                d.host.say(&format!(
                    "Restoring w32time failed: {e}. The restore record is kept. Run uninstall \
                     again."
                ));
                codes.push(exit::RESTORE);
            }
        },
        Ok(None) => {
            d.host
                .say("Found no restore record. w32time is left as it is.");
            flag_if_disabled(d, codes, false);
        }
        Err(LoadError::Invalid(e)) => {
            d.host.say(&format!(
                "The w32time restore record is not valid ({e}). w32time is left as it is. \
                 {MANUAL_RESTORE} Then delete the record file."
            ));
            codes.push(exit::RECORD_INVALID);
            flag_if_disabled(d, codes, true);
        }
        Err(e @ LoadError::NotTrusted(_)) => {
            d.host.say(&format!(
                "{e}. w32time is left as it is. {MANUAL_RESTORE} Then delete the record file."
            ));
            codes.push(exit::RECORD_NOT_TRUSTED);
            flag_if_disabled(d, codes, true);
        }
        Err(e) => {
            d.host.say(&format!("{e}. w32time is left as it is."));
            codes.push(exit::RESTORE);
        }
    }
}

/// R92: no usable record. A disabled `w32time` must not end in a silent 0.
/// `hint_shown`: the manual restore hint was already printed, so it is not
/// repeated (N3).
fn flag_if_disabled(d: &mut Deps<'_>, codes: &mut Vec<u8>, hint_shown: bool) {
    let hint = if hint_shown { "" } else { MANUAL_RESTORE };
    match d.scm.query(W32TIME) {
        Ok(s) if s.start == StartType::Disabled => {
            let line =
                format!("w32time is still disabled and no usable restore record was found. {hint}");
            d.host.say(line.trim_end());
            codes.push(exit::NO_RECORD_DISABLED);
        }
        Ok(_) => {}
        Err(e) => {
            let line = format!("Cannot read the w32time state ({e}). Check it by hand. {hint}");
            d.host.say(line.trim_end());
        }
    }
}
