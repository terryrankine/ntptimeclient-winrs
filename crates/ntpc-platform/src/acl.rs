//! Secures the state directory before the drift store touches it.
//!
//! This is the main control against a hijacked state directory. The drift
//! store in `ntpc-service` assumes it ran. The load-side opens of
//! `drift.txt` and the config live in that crate's `safe_open` module.
//!
//! Rules, from the Task 10 review:
//! - No link or junction at the directory or at any parent.
//! - An existing directory must be owned by SYSTEM or Administrators. The
//!   owner can always rewrite the DACL, so a foreign-owned directory is
//!   refused, never re-ACLed. There is no remove-and-recreate path.
//! - The DACL is protected (nothing inherited from the parent) and grants
//!   SYSTEM and Administrators full control, inherited by files and
//!   folders. Users get nothing: the directory holds only the drift value.
//! - A wrong DACL under a right owner is replaced and read back.
//! - Any failure is an error. The host then runs without a saved drift.
//!
//! Error text names no path, per the engine host contract.

use std::io;
use std::os::windows::io::OwnedHandle;
use std::path::{Component, Path, PathBuf, Prefix};

use thiserror::Error;

use crate::win32::{self, Principal, Security};

/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTR_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const ATTR_REPARSE_POINT: u32 = 0x400;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x80;
/// `READ_CONTROL`, `WRITE_DAC` and `WRITE_OWNER`.
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
/// `FILE_ALL_ACCESS`, what SDDL `FA` stands for.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, and nothing else: no
/// inherit-only and no inherited bit.
const OI_CI: u8 = 0x03;
/// `ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`, `ERROR_ACCESS_DENIED`,
/// `ERROR_ALREADY_EXISTS` and `ERROR_INVALID_OWNER`.
const FILE_NOT_FOUND: i32 = 2;
const PATH_NOT_FOUND: i32 = 3;
const ACCESS_DENIED: i32 = 5;
const ALREADY_EXISTS: i32 = 183;
const INVALID_OWNER: i32 = 1307;

/// Why the state directory could not be secured.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AclError {
    /// Only absolute local drive paths with plain components are accepted.
    #[error("state directory path must be an absolute local drive path")]
    BadPath,
    /// The directory itself is a symlink or junction.
    #[error("state directory is a link or junction")]
    Link,
    /// A parent of the directory is a symlink or junction.
    #[error("a parent of the state directory is a link or junction")]
    ParentLink,
    /// Something other than a directory sits at the path or a parent.
    #[error("state directory or a parent is not a directory")]
    NotADirectory,
    /// The owner is not SYSTEM or Administrators.
    #[error("state directory owner is not SYSTEM or Administrators")]
    UntrustedOwner,
    /// The DACL read back after writing it is still not the secure one.
    #[error("state directory access list is still wrong after setting it")]
    DaclNotApplied,
    /// An OS call failed. `detail` is the OS message, which holds no path.
    #[error("state directory {op} failed: {detail}")]
    Os {
        /// What was being done.
        op: &'static str,
        /// The OS error text.
        detail: String,
    },
}

fn os(op: &'static str, e: &io::Error) -> AclError {
    AclError::Os {
        op,
        detail: e.to_string(),
    }
}

/// Makes `path` a secure state directory, creating it if needed.
///
/// Call it before the first load or save, every start, including when the
/// directory already exists. Only the last component is created. Its parent
/// must exist.
///
/// A directory this call creates and then cannot secure is removed again,
/// best effort. It is empty and ours, and a half-secured directory must not
/// be left behind.
///
/// # Errors
/// [`AclError`] says which check failed.
pub fn secure_state_dir(path: &Path) -> Result<(), AclError> {
    let ancestors = ancestors(path)?;
    for a in &ancestors {
        check_ancestor(a)?;
    }
    let (handle, created) = open_or_create(path)?;
    let result = secure_open_dir(&handle, created);
    drop(handle);
    if result.is_err() && created {
        let _ = std::fs::remove_dir(path);
    }
    result
}

/// The drive root and every directory between it and `path`, top down.
/// `path` itself is not included.
fn ancestors(path: &Path) -> Result<Vec<PathBuf>, AclError> {
    let mut comps = path.components();
    match comps.next() {
        Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
        _ => return Err(AclError::BadPath),
    }
    if comps.next() != Some(Component::RootDir) {
        return Err(AclError::BadPath);
    }
    let rest: Vec<Component<'_>> = comps.collect();
    if rest.is_empty() || !rest.iter().all(|c| matches!(c, Component::Normal(_))) {
        return Err(AclError::BadPath);
    }
    let mut out = Vec::with_capacity(rest.len());
    let mut current: PathBuf = path.components().take(2).collect();
    out.push(current.clone());
    for c in &rest[..rest.len() - 1] {
        current.push(c);
        out.push(current.clone());
    }
    Ok(out)
}

fn check_ancestor(path: &Path) -> Result<(), AclError> {
    let h =
        win32::open_no_follow(path, FILE_READ_ATTRIBUTES).map_err(|e| os("parent check", &e))?;
    let tag = win32::attribute_tag(&h).map_err(|e| os("parent check", &e))?;
    if tag.attributes & ATTR_REPARSE_POINT != 0 {
        return Err(AclError::ParentLink);
    }
    if tag.attributes & ATTR_DIRECTORY == 0 {
        return Err(AclError::NotADirectory);
    }
    Ok(())
}

/// Opens the directory with the rights needed to fix it, creating it first
/// if it is missing. Returns whether this call created it.
fn open_or_create(path: &Path) -> Result<(OwnedHandle, bool), AclError> {
    let rights = READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES;
    let mut created = false;
    match win32::open_no_follow(path, rights) {
        Ok(h) => return Ok((h, false)),
        Err(e) if matches!(e.raw_os_error(), Some(FILE_NOT_FOUND | PATH_NOT_FOUND)) => {
            // A new directory gets the token's default owner. If that is not
            // trusted the directory could never pass, and a user could not
            // even delete it again once it has the secure DACL. So refuse
            // before creating anything.
            let owner = win32::token_default_owner().map_err(|e| os("read token", &e))?;
            if !matches!(owner, Principal::System | Principal::Administrators) {
                return Err(AclError::UntrustedOwner);
            }
            match win32::create_secure_dir(path) {
                Ok(()) => created = true,
                // Someone made it in between. Treat it as pre-existing.
                Err(e) if e.raw_os_error() == Some(ALREADY_EXISTS) => {}
                Err(e) => return Err(os("create", &e)),
            }
        }
        Err(e) if e.raw_os_error() == Some(ACCESS_DENIED) => return Err(denied(path, &e)),
        Err(e) => return Err(os("open", &e)),
    }
    match win32::open_no_follow(path, rights) {
        Ok(h) => Ok((h, created)),
        Err(e) => {
            let err = if e.raw_os_error() == Some(ACCESS_DENIED) {
                denied(path, &e)
            } else {
                os("open", &e)
            };
            if created {
                let _ = std::fs::remove_dir(path);
            }
            Err(err)
        }
    }
}

/// The write-rights open was refused. Look again read-only, so the error
/// says why: a link or a foreign owner explains it better than "denied".
fn denied(path: &Path, e: &io::Error) -> AclError {
    let Ok(h) = win32::open_no_follow(path, READ_CONTROL | FILE_READ_ATTRIBUTES) else {
        return os("open", e);
    };
    if let Err(why) = check_handle(&h) {
        return why;
    }
    match win32::read_security(&h) {
        Ok(s) if !owner_trusted(&s) => AclError::UntrustedOwner,
        _ => os("open", e),
    }
}

/// Refuses a link or a non-directory behind an open handle.
fn check_handle(h: &OwnedHandle) -> Result<(), AclError> {
    let tag = win32::attribute_tag(h).map_err(|e| os("check", &e))?;
    if tag.attributes & ATTR_REPARSE_POINT != 0 {
        return Err(AclError::Link);
    }
    if tag.attributes & ATTR_DIRECTORY == 0 {
        return Err(AclError::NotADirectory);
    }
    Ok(())
}

/// Every check and write goes through the handle, so a swap of the path
/// after the open cannot redirect them.
fn secure_open_dir(h: &OwnedHandle, created: bool) -> Result<(), AclError> {
    check_handle(h)?;
    let sec = win32::read_security(h).map_err(|e| os("read security", &e))?;
    if !owner_trusted(&sec) {
        return Err(AclError::UntrustedOwner);
    }
    if created || !dacl_is_secure(&sec) {
        match win32::write_secure_dacl(h, true) {
            Ok(()) => {}
            // The token cannot assign Administrators as owner. Keep the
            // owner, which was checked above, and set only the DACL.
            Err(e) if e.raw_os_error() == Some(INVALID_OWNER) => {
                win32::write_secure_dacl(h, false).map_err(|e| os("set security", &e))?;
            }
            Err(e) => return Err(os("set security", &e)),
        }
        let after = win32::read_security(h).map_err(|e| os("read security", &e))?;
        if !owner_trusted(&after) {
            return Err(AclError::UntrustedOwner);
        }
        if !dacl_is_secure(&after) {
            return Err(AclError::DaclNotApplied);
        }
    }
    Ok(())
}

fn owner_trusted(sec: &Security) -> bool {
    matches!(
        sec.owner,
        Some(Principal::System | Principal::Administrators)
    )
}

/// True for exactly the DACL in [`win32::SECURE_DACL_SDDL`]: protected, two
/// allow ACEs, SYSTEM and Administrators, full control, object and
/// container inherit, nothing inherited from above.
fn dacl_is_secure(sec: &Security) -> bool {
    let Some(aces) = &sec.dacl else {
        return false;
    };
    let good = |p: Principal| {
        aces.iter().any(|a| {
            a.principal == p && a.ace_type == 0 && a.flags == OI_CI && a.mask == FILE_ALL_ACCESS
        })
    };
    sec.dacl_protected
        && aces.len() == 2
        && good(Principal::System)
        && good(Principal::Administrators)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32::AceInfo;
    use std::process::Command;

    fn ace(principal: Principal) -> AceInfo {
        AceInfo {
            ace_type: 0,
            flags: OI_CI,
            mask: FILE_ALL_ACCESS,
            principal,
        }
    }

    fn secure() -> Security {
        Security {
            owner: Some(Principal::Administrators),
            dacl_protected: true,
            dacl: Some(vec![ace(Principal::System), ace(Principal::Administrators)]),
        }
    }

    #[test]
    fn secure_dacl_is_accepted() {
        assert!(dacl_is_secure(&secure()));
    }

    #[test]
    fn unprotected_null_or_extra_dacls_are_rejected() {
        let mut s = secure();
        s.dacl_protected = false;
        assert!(!dacl_is_secure(&s));
        let mut s = secure();
        s.dacl = None;
        assert!(!dacl_is_secure(&s));
        let mut s = secure();
        s.dacl.as_mut().unwrap().push(ace(Principal::Other));
        assert!(!dacl_is_secure(&s));
        let mut s = secure();
        s.dacl.as_mut().unwrap()[0].principal = Principal::Other;
        assert!(!dacl_is_secure(&s));
    }

    #[test]
    fn weak_mask_type_or_flags_are_rejected() {
        let mut s = secure();
        s.dacl.as_mut().unwrap()[0].mask = 0x0012_0089;
        assert!(!dacl_is_secure(&s));
        let mut s = secure();
        s.dacl.as_mut().unwrap()[1].ace_type = 1;
        assert!(!dacl_is_secure(&s));
        let mut s = secure();
        // Inherited bit set: it came from the parent.
        s.dacl.as_mut().unwrap()[1].flags = OI_CI | 0x10;
        assert!(!dacl_is_secure(&s));
    }

    #[test]
    fn owner_must_be_system_or_administrators() {
        let mut s = secure();
        assert!(owner_trusted(&s));
        s.owner = Some(Principal::System);
        assert!(owner_trusted(&s));
        s.owner = Some(Principal::Other);
        assert!(!owner_trusted(&s));
        s.owner = None;
        assert!(!owner_trusted(&s));
    }

    #[test]
    fn bad_paths_are_refused() {
        for p in [
            r"relative\state",
            r"\no-drive\state",
            r"C:relative",
            r"C:\",
            // A `.` in the middle is dropped by `Path::components` itself,
            // so only `..` is a case here.
            r"C:\a\..\b",
            r"\\server\share\state",
            r"\\?\UNC\server\share\state",
        ] {
            assert_eq!(
                secure_state_dir(Path::new(p)),
                Err(AclError::BadPath),
                "{p}"
            );
        }
    }

    #[test]
    fn ancestors_run_from_the_root_down() {
        let a = ancestors(Path::new(r"C:\ProgramData\ntpc\state")).unwrap();
        let want: Vec<PathBuf> = [r"C:\", r"C:\ProgramData", r"C:\ProgramData\ntpc"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(a, want);
        let a = ancestors(Path::new(r"\\?\C:\x")).unwrap();
        assert_eq!(a, vec![PathBuf::from(r"\\?\C:\")]);
    }

    #[test]
    fn error_text_names_no_path() {
        let all = [
            AclError::BadPath,
            AclError::Link,
            AclError::ParentLink,
            AclError::NotADirectory,
            AclError::UntrustedOwner,
            AclError::DaclNotApplied,
            os("open", &io::Error::from_raw_os_error(5)),
        ];
        for e in all {
            let s = e.to_string();
            assert!(!s.contains('\\') && !s.contains('/'), "{s}");
        }
    }

    /// A fresh directory under the system temp dir. Every test works only
    /// inside it and removes it at the end.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir()
                .join(format!("ntpc-acl-{name}-{}-{nanos}", std::process::id()));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // remove_dir_all does not follow junctions or symlinks, so it
            // cannot reach outside the scratch directory. A failure is
            // printed and fails the next test run's leftover check, never
            // silently ignored: a locked directory must not stay behind.
            if let Err(e) = std::fs::remove_dir_all(&self.0) {
                eprintln!("LEFTOVER test directory {}: {e}", self.0.display());
            }
        }
    }

    /// Fails if an earlier run left a scratch directory behind.
    #[test]
    fn no_scratch_directory_left_from_earlier_runs() {
        let mine = format!("-{}-", std::process::id());
        let left: Vec<String> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("ntpc-acl-") && !n.contains(&mine))
            .collect();
        assert!(left.is_empty(), "leftover scratch directories: {left:?}");
    }

    fn elevated() -> bool {
        win32::token_is_elevated().unwrap()
    }

    fn junction(link: &Path, target: &Path) -> bool {
        Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[test]
    fn user_owned_existing_dir_is_refused() {
        if elevated() {
            eprintln!("skip: elevated, a new directory would be owned by Administrators");
            return;
        }
        let s = Scratch::new("owner");
        let dir = s.0.join("state");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(secure_state_dir(&dir), Err(AclError::UntrustedOwner));
        // Refused means untouched: we can still write in it.
        std::fs::write(dir.join("probe"), b"x").unwrap();
    }

    #[test]
    fn junction_at_the_path_is_refused() {
        let s = Scratch::new("junction");
        let target = s.0.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = s.0.join("state");
        if !junction(&link, &target) {
            eprintln!("skip: mklink /J failed");
            return;
        }
        assert_eq!(secure_state_dir(&link), Err(AclError::Link));
    }

    #[test]
    fn dir_under_a_junctioned_parent_is_refused() {
        let s = Scratch::new("parent");
        let real = s.0.join("real");
        std::fs::create_dir_all(real.join("state")).unwrap();
        let link = s.0.join("link");
        if !junction(&link, &real) {
            eprintln!("skip: mklink /J failed");
            return;
        }
        assert_eq!(
            secure_state_dir(&link.join("state")),
            Err(AclError::ParentLink)
        );
        // A missing child under the junction must not be created either.
        assert_eq!(
            secure_state_dir(&link.join("new")),
            Err(AclError::ParentLink)
        );
        assert!(!real.join("new").exists());
    }

    #[test]
    fn file_symlink_at_the_path_is_refused() {
        let s = Scratch::new("symlink");
        let target = s.0.join("target.txt");
        std::fs::write(&target, b"x").unwrap();
        let link = s.0.join("state");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!("skip: no right to create a symlink (needs developer mode or admin)");
            return;
        }
        assert_eq!(secure_state_dir(&link), Err(AclError::Link));
    }

    #[test]
    fn a_file_at_the_path_is_refused() {
        let s = Scratch::new("file");
        let file = s.0.join("state");
        std::fs::write(&file, b"x").unwrap();
        let r = secure_state_dir(&file);
        // Non-elevated, the user owns the file, so either check may fire
        // first. Both refuse.
        assert!(
            matches!(r, Err(AclError::NotADirectory | AclError::UntrustedOwner)),
            "{r:?}"
        );
    }

    #[test]
    fn missing_parent_is_an_error_and_creates_nothing() {
        let s = Scratch::new("noparent");
        let dir = s.0.join("missing").join("state");
        assert!(matches!(secure_state_dir(&dir), Err(AclError::Os { .. })));
        assert!(!s.0.join("missing").exists());
    }

    #[test]
    fn user_token_creates_nothing() {
        if !matches!(win32::token_default_owner().unwrap(), Principal::Other) {
            eprintln!("skip: the token's default owner is trusted");
            return;
        }
        let s = Scratch::new("create");
        let dir = s.0.join("state");
        assert_eq!(secure_state_dir(&dir), Err(AclError::UntrustedOwner));
        assert!(!dir.exists(), "directory created for an untrusted owner");
    }

    #[test]
    fn elevated_create_and_recheck_succeed() {
        if !elevated() {
            eprintln!("skip: not elevated, the DACL success path needs Administrators");
            return;
        }
        let s = Scratch::new("elevated");
        let dir = s.0.join("state");
        secure_state_dir(&dir).unwrap();
        // The second call takes the already-exists path.
        secure_state_dir(&dir).unwrap();
        let h = win32::open_no_follow(&dir, READ_CONTROL | FILE_READ_ATTRIBUTES).unwrap();
        let sec = win32::read_security(&h).unwrap();
        assert!(owner_trusted(&sec) && dacl_is_secure(&sec), "{sec:?}");
        // Cleanup: Administrators hold full control on the directory, so the
        // elevated test removes it through Scratch::drop.
    }
}
