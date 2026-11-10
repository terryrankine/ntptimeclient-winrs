//! Secures the state directory before the drift store touches it.
//!
//! This is the main control against a hijacked state directory. The drift
//! store in `ntpc-service` assumes it ran. The load-side opens of
//! `drift.txt` and the config live in that crate's `safe_open` module.
//!
//! Rules, from the Task 10 and Task 11 reviews:
//! - No link or junction at the directory or at any parent. Every reparse
//!   tag is refused, on purpose: no state directory needs one.
//! - Every parent below the drive root is owned by SYSTEM, Administrators
//!   or TrustedInstaller (R69). The owner of a parent can rename the state
//!   directory away and put a junction in its place. The drive root is
//!   exempt.
//! - An existing directory must be owned by SYSTEM or Administrators. The
//!   owner can always rewrite the DACL, so a foreign-owned directory is
//!   refused, never re-ACLed. There is no remove-and-recreate path.
//! - The DACL is protected (nothing inherited from the parent) and grants
//!   SYSTEM and Administrators full control, inherited by files and
//!   folders. Users get nothing: the directory holds only the drift value.
//! - An existing directory is never re-ACLed (R78). A handle opened before a
//!   DACL change keeps the rights it was granted, so a re-ACLed old object can
//!   still be written, even turned into a junction, through such a handle.
//!   If the DACL or a child is wrong, the known children are cleaned, the old
//!   directory is renamed to a quarantine sibling `<name>.old-<hex>`, and a
//!   fresh directory is created with the secure descriptor from birth. No
//!   foreign handle or child can predate a fresh object.
//! - Every start checks every child, also when the DACL is right: known
//!   names only, plain file, one link, owner SYSTEM or Administrators.
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
/// `FILE_LIST_DIRECTORY` and `DELETE`.
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const DELETE: u32 = 0x0001_0000;
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
    /// A path component ends in a dot or a space. Windows strips those, so
    /// the name checked would not be the name opened.
    #[error("state directory path has a component ending in a dot or space")]
    TrailingDotOrSpace,
    /// The drive is not a fixed local disk (`DRIVE_FIXED`).
    #[error("state directory must be on a fixed local drive")]
    NotFixedDrive,
    /// The path no longer names the directory that was secured.
    #[error("state directory changed while it was being secured")]
    PathChanged,
    /// A component is a DOS device name (CON, NUL, COM1 and so on) or holds
    /// a colon (named stream syntax).
    #[error("state directory path has a device name or a colon")]
    ReservedName,
    /// Securing a fresh directory failed after the old one was moved to
    /// quarantine, and moving it back failed too. Both errors are kept.
    #[error(
        "state directory replacement failed ({cause}), and restoring the old directory failed ({rollback})"
    )]
    RollbackFailed {
        /// Why the fresh directory could not be secured.
        cause: String,
        /// Why the old directory could not be moved back.
        rollback: String,
    },
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
    /// A parent below the drive root is not owned by SYSTEM,
    /// Administrators or `TrustedInstaller`.
    #[error("a parent of the state directory has an untrusted owner")]
    UntrustedParent,
    /// The directory holds something other than plain, single-link
    /// `drift.txt` and `drift.txt.tmp` files, so its DACL is not fixed.
    #[error("state directory holds an unexpected entry")]
    UnexpectedChild,
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
/// On Ok the path names a directory, not a link, owned by SYSTEM or
/// Administrators, with exactly the protected secure DACL, whose children are
/// only plain single-link `drift.txt` or `drift.txt.tmp` files owned by
/// SYSTEM or Administrators. A directory with a wrong DACL or a wrong-owned
/// known child is replaced by a fresh one (R78). The old one goes to a
/// quarantine sibling `<name>.old-<hex>`, which is deleted best effort and
/// may be left behind, empty or holding whatever an attacker put there
/// later. Nothing reads it.
///
/// A directory this call creates and then cannot secure is removed again,
/// best effort. It is empty and ours, and a half-secured directory must not
/// be left behind.
///
/// A `subst` drive is accepted as a fixed drive. Pointing one at a user
/// directory is an administrator misconfiguration (R79), like R74 below.
///
/// Parents are checked for links and for their owner, not for their DACL
/// (R74). A parent owned by SYSTEM, Administrators or `TrustedInstaller` whose
/// DACL still grants Users `FILE_DELETE_CHILD` would let them remove the
/// state directory. That is an administrator misconfiguration and out of
/// scope here.
///
/// # Errors
/// [`AclError`] says which check failed.
pub fn secure_state_dir(path: &Path) -> Result<(), AclError> {
    secure_state_dir_with(path, &OS_PROBE)
}

/// OS reads that tests replace, so the parent rules can be checked inside a
/// user-owned temp tree.
struct Probe {
    /// The owner of an open object.
    owner: fn(&OwnedHandle) -> io::Result<Option<Principal>>,
    /// `GetDriveTypeW` of a drive root.
    drive_type: fn(&Path) -> u32,
}

const OS_PROBE: Probe = Probe {
    owner: os_owner,
    drive_type: win32::drive_type,
};

fn os_owner(h: &OwnedHandle) -> io::Result<Option<Principal>> {
    win32::read_security(h).map(|s| s.owner)
}

/// `DRIVE_FIXED`.
const DRIVE_FIXED: u32 = 3;

fn drive_ok(drive_type: u32) -> Result<(), AclError> {
    if drive_type == DRIVE_FIXED {
        Ok(())
    } else {
        Err(AclError::NotFixedDrive)
    }
}

fn secure_state_dir_with(path: &Path, probe: &Probe) -> Result<(), AclError> {
    let ancestors = ancestors(path)?;
    drive_ok((probe.drive_type)(&drive_root(path)?))?;
    for (i, a) in ancestors.iter().enumerate() {
        // Index 0 is the drive root, which is exempt from the owner check.
        check_ancestor(a, i > 0, probe)?;
    }
    secure_final(path)
}

/// `X:\` for the drive of `path`, also for a `\\?\X:\` path, because
/// `GetDriveTypeW` wants the plain form.
fn drive_root(path: &Path) -> Result<PathBuf, AclError> {
    match path.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Ok(PathBuf::from(format!("{}:\\", char::from(letter))))
            }
            _ => Err(AclError::BadPath),
        },
        _ => Err(AclError::BadPath),
    }
}

/// Everything after the parent checks. Split out so tests inside a
/// user-owned temp tree can reach the later checks.
fn secure_final(path: &Path) -> Result<(), AclError> {
    let (handle, created) = open_or_create(path)?;
    let result = if created {
        secure_fresh(&handle, path)
    } else {
        secure_existing(&handle, path)
    };
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
    if rest.iter().any(|c| ends_in_dot_or_space(c.as_os_str())) {
        return Err(AclError::TrailingDotOrSpace);
    }
    let verbatim = matches!(
        path.components().next(),
        Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::VerbatimDisk(_))
    );
    if rest
        .iter()
        .any(|c| has_colon(c.as_os_str()) || (!verbatim && is_device_name(c.as_os_str())))
    {
        return Err(AclError::ReservedName);
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

/// Windows drops a trailing dot or space from a name, so `state.` opens
/// `state`. Refuse such names rather than reason about it.
fn ends_in_dot_or_space(name: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    matches!(
        name.encode_wide().last(),
        Some(u) if u == u16::from(b'.') || u == u16::from(b' ')
    )
}

/// A colon in a component is named stream syntax (`dir:stream`).
fn has_colon(name: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide().any(|u| u == u16::from(b':'))
}

/// DOS device names: CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9, with
/// or without an extension, any case. In a non-verbatim path Win32 maps
/// them to the device, not to a file.
fn is_device_name(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_uppercase();
    let stem = name.split('.').next().unwrap_or("").trim_end();
    match stem {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let b = stem.as_bytes();
            b.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && (b'1'..=b'9').contains(&b[3])
        }
    }
}

/// Checks one parent through a single no-follow handle: not a link, a
/// directory, and with `check_owner` a trusted owner. The owner is read
/// from the same handle, so no second path lookup can be raced.
fn check_ancestor(path: &Path, check_owner: bool, probe: &Probe) -> Result<(), AclError> {
    let h = win32::open_no_follow(path, FILE_READ_ATTRIBUTES | READ_CONTROL)
        .map_err(|e| os("parent check", &e))?;
    let tag = win32::attribute_tag(&h).map_err(|e| os("parent check", &e))?;
    if tag.attributes & ATTR_REPARSE_POINT != 0 {
        return Err(AclError::ParentLink);
    }
    if tag.attributes & ATTR_DIRECTORY == 0 {
        return Err(AclError::NotADirectory);
    }
    if check_owner {
        let owner = (probe.owner)(&h).map_err(|e| os("parent check", &e))?;
        if !parent_owner_trusted(owner) {
            return Err(AclError::UntrustedParent);
        }
    }
    Ok(())
}

fn parent_owner_trusted(owner: Option<Principal>) -> bool {
    matches!(
        owner,
        Some(Principal::System | Principal::Administrators | Principal::TrustedInstaller)
    )
}

/// Rights on the state directory handle. `DELETE` lets the quarantine
/// rename and the quarantine delete go through the checked handle.
const DIR_RIGHTS: u32 =
    READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | DELETE;

/// Refuses before creating when new objects would get an untrusted owner.
/// Such a directory could never pass, and a user could not even delete it
/// again once it has the secure DACL.
fn require_trusted_token_owner() -> Result<(), AclError> {
    let owner = win32::token_default_owner().map_err(|e| os("read token", &e))?;
    if matches!(owner, Principal::System | Principal::Administrators) {
        Ok(())
    } else {
        Err(AclError::UntrustedOwner)
    }
}

/// Opens the directory with the rights needed to secure it, creating it
/// first if it is missing. Returns whether this call created it.
fn open_or_create(path: &Path) -> Result<(OwnedHandle, bool), AclError> {
    let mut created = false;
    match win32::open_no_follow(path, DIR_RIGHTS) {
        Ok(h) => return Ok((h, false)),
        Err(e) if matches!(e.raw_os_error(), Some(FILE_NOT_FOUND | PATH_NOT_FOUND)) => {
            require_trusted_token_owner()?;
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
    match win32::open_no_follow(path, DIR_RIGHTS) {
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

/// The steps after a fresh create, behind a trait so a test can pin their
/// order: the checks must run after the DACL write and before Ok.
trait DirOps {
    fn write_dacl(&self, h: &OwnedHandle) -> Result<(), AclError>;
    fn read_security(&self, h: &OwnedHandle) -> Result<Security, AclError>;
    fn require_empty(&self, h: &OwnedHandle) -> Result<(), AclError>;
    fn same_object(&self, h: &OwnedHandle, path: &Path) -> Result<(), AclError>;
}

/// The real OS.
struct OsOps;

impl DirOps for OsOps {
    fn write_dacl(&self, h: &OwnedHandle) -> Result<(), AclError> {
        match win32::write_secure_dacl(h, true) {
            Ok(()) => Ok(()),
            // The token cannot assign Administrators as owner. Keep the
            // owner, which is checked after, and set only the DACL.
            Err(e) if e.raw_os_error() == Some(INVALID_OWNER) => {
                win32::write_secure_dacl(h, false).map_err(|e| os("set security", &e))
            }
            Err(e) => Err(os("set security", &e)),
        }
    }

    fn read_security(&self, h: &OwnedHandle) -> Result<Security, AclError> {
        win32::read_security(h).map_err(|e| os("read security", &e))
    }

    fn require_empty(&self, h: &OwnedHandle) -> Result<(), AclError> {
        require_empty(h)
    }

    fn same_object(&self, h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
        same_object(h, path)
    }
}

/// A directory this run created, born with the secure DACL. No foreign
/// handle or child can predate it.
fn secure_fresh(h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    check_handle(h)?;
    finish_fresh(&OsOps, h, path)
}

/// Sets the owner where the token can (the DACL is the one it was born
/// with), reads it back, then checks the directory is still empty and still
/// the object at `path`.
fn finish_fresh(ops: &impl DirOps, h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    ops.write_dacl(h)?;
    let after = ops.read_security(h)?;
    if !owner_trusted(&after) {
        return Err(AclError::UntrustedOwner);
    }
    if !dacl_is_secure(&after) {
        return Err(AclError::DaclNotApplied);
    }
    ops.require_empty(h)?;
    ops.same_object(h, path)
}

/// The fast path: the DACL and every child were right. Only the identity
/// is checked again.
fn finish_keep(ops: &impl DirOps, h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    ops.same_object(h, path)
}

/// A directory that was there before this run.
fn secure_existing(h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    check_handle(h)?;
    let sec = win32::read_security(h).map_err(|e| os("read security", &e))?;
    if !owner_trusted(&sec) {
        return Err(AclError::UntrustedOwner);
    }
    let children = inspect_children(h, path)?;
    match decide(dacl_is_secure(&sec), &children) {
        Decision::Keep => finish_keep(&OsOps, h, path),
        Decision::Refuse => Err(AclError::UnexpectedChild),
        Decision::Quarantine => quarantine_and_recreate(h, path),
    }
}

/// What a child is, as far as the rules care.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildKind {
    File,
    Directory,
    /// Any reparse point: symlink, junction or other tag.
    Link,
}

/// One observed child of the state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildObs {
    /// `drift.txt` or `drift.txt.tmp`.
    known: bool,
    kind: ChildKind,
    /// Hard link count. Zero when not read (unknown name or not a file).
    links: u32,
    /// Owned by SYSTEM or Administrators.
    owner_trusted: bool,
}

/// What to do with an existing, trusted-owned directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// DACL exact and every child right: use it as it is.
    Keep,
    /// Fixable: clean the known children, quarantine, start fresh (R78).
    Quarantine,
    /// Something the service never writes is there. Persistence off.
    Refuse,
}

/// The rule table. Unknown names, directories, links and extra hard links
/// refuse. A wrong DACL or a wrong-owned known file quarantines. Else keep.
fn decide(dacl_exact: bool, children: &[ChildObs]) -> Decision {
    let shape_ok = |c: &ChildObs| c.known && c.kind == ChildKind::File && c.links == 1;
    if !children.iter().all(shape_ok) {
        return Decision::Refuse;
    }
    if dacl_exact && children.iter().all(|c| c.owner_trusted) {
        Decision::Keep
    } else {
        Decision::Quarantine
    }
}

fn kind_of(attributes: u32) -> ChildKind {
    if attributes & ATTR_REPARSE_POINT != 0 {
        ChildKind::Link
    } else if attributes & ATTR_DIRECTORY != 0 {
        ChildKind::Directory
    } else {
        ChildKind::File
    }
}

/// Lists the children through `dir` and observes each. Unknown names and
/// non-files are not opened. A known file is opened by path without
/// following a reparse point, and its kind, link count and owner are read
/// from that handle.
fn inspect_children(dir: &OwnedHandle, path: &Path) -> Result<Vec<ChildObs>, AclError> {
    let entries = win32::list_dir(dir).map_err(|e| os("list", &e))?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in &entries {
        let known = KNOWN_CHILDREN.iter().any(|k| entry.name == *k);
        let listed = kind_of(entry.attributes);
        if !known || listed != ChildKind::File {
            out.push(ChildObs {
                known,
                kind: listed,
                links: 0,
                owner_trusted: false,
            });
            continue;
        }
        let child =
            win32::open_no_follow(&path.join(&entry.name), READ_CONTROL | FILE_READ_ATTRIBUTES)
                .map_err(|e| os("open child", &e))?;
        let info = win32::link_info(&child).map_err(|e| os("check child", &e))?;
        let sec = win32::read_security(&child).map_err(|e| os("check child", &e))?;
        out.push(ChildObs {
            known,
            kind: kind_of(info.attributes),
            links: info.links,
            owner_trusted: owner_trusted(&sec),
        });
    }
    Ok(out)
}

/// R78: clean the known children, move the old directory to a quarantine
/// sibling through its own handle, create a fresh secure directory, and
/// delete the quarantine best effort. If the fresh directory fails, move
/// the old one back and report both errors if that fails too.
fn quarantine_and_recreate(h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    clean_known_children(h, path)?;
    rename_to_quarantine(h, path)?;
    match create_fresh(path) {
        Ok(()) => {
            // Best effort, as R78 says: the old directory is empty unless
            // someone added to it through a held handle. Delete through the
            // handle, so no link is followed. A failure leaves an inert
            // quarantine directory that nothing reads.
            let _ = win32::delete_by_handle(h);
            Ok(())
        }
        Err(cause) => match win32::rename_by_handle(h, path) {
            Ok(()) => Err(cause),
            Err(e) => Err(AclError::RollbackFailed {
                cause: cause.to_string(),
                rollback: e.to_string(),
            }),
        },
    }
}

/// Renames the directory behind `h` to `<name>.old-<16 hex>` next to it.
/// The suffix comes from the standard library's per-process random hash
/// keys, so another user cannot predict it and pre-create the name. Three
/// tries on a name clash, then refuse.
fn rename_to_quarantine(h: &OwnedHandle, path: &Path) -> Result<PathBuf, AclError> {
    use std::hash::BuildHasher;
    /// `ERROR_FILE_EXISTS` and `ERROR_ALREADY_EXISTS`.
    const FILE_EXISTS: i32 = 80;
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(AclError::BadPath);
    };
    let keys = std::collections::hash_map::RandomState::new();
    let mut last = None;
    for attempt in 0u32..3 {
        let suffix = keys.hash_one((attempt, win32::unbiased_interrupt_time_precise()));
        let mut q = name.to_os_string();
        q.push(format!(".old-{suffix:016x}"));
        let target = parent.join(q);
        match win32::rename_by_handle(h, &target) {
            Ok(()) => return Ok(target),
            Err(e) if matches!(e.raw_os_error(), Some(FILE_EXISTS | ALREADY_EXISTS)) => {
                last = Some(e);
            }
            Err(e) => return Err(os("quarantine", &e)),
        }
    }
    let e = last.unwrap_or_else(|| io::Error::other("no quarantine name"));
    Err(os("quarantine", &e))
}

/// Creates a fresh directory at `path` with the secure descriptor and
/// secures it. Refuses if anything already took the name. Removes it again
/// if securing fails.
fn create_fresh(path: &Path) -> Result<(), AclError> {
    require_trusted_token_owner()?;
    win32::create_secure_dir(path).map_err(|e| os("create", &e))?;
    let result = win32::open_no_follow(path, DIR_RIGHTS)
        .map_err(|e| os("open", &e))
        .and_then(|h| secure_fresh(&h, path));
    if result.is_err() {
        let _ = std::fs::remove_dir(path);
    }
    result
}

/// Refuses unless the directory behind `dir` is empty.
fn require_empty(dir: &OwnedHandle) -> Result<(), AclError> {
    if win32::list_dir(dir).map_err(|e| os("list", &e))?.is_empty() {
        Ok(())
    } else {
        Err(AclError::UnexpectedChild)
    }
}

/// Refuses if `path` no longer names the object behind `h`, for example
/// after a rename swap while it was being secured, or if the path is a
/// reparse point now. Compares volume serial and file index.
fn same_object(h: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    let again = win32::open_no_follow(path, FILE_READ_ATTRIBUTES).map_err(|e| os("reopen", &e))?;
    let a = win32::link_info(h).map_err(|e| os("identify", &e))?;
    let b = win32::link_info(&again).map_err(|e| os("identify", &e))?;
    if b.attributes & ATTR_REPARSE_POINT != 0 {
        return Err(AclError::Link);
    }
    if a.same_file(&b) {
        Ok(())
    } else {
        Err(AclError::PathChanged)
    }
}

/// The only names the drift store writes.
const KNOWN_CHILDREN: [&str; 2] = ["drift.txt", "drift.txt.tmp"];

/// Deletes `drift.txt` and `drift.txt.tmp` from a directory before it goes
/// to quarantine.
///
/// - Any other entry, or a known name that is a directory, a link of any
///   kind or has more than one hard link: `UnexpectedChild`, nothing deleted.
/// - An OS error while listing, opening or checking: `Os`, nothing deleted.
/// - An OS error on the second delete after the first worked: `Os`, and the
///   first file is gone. That partial delete only removes our own drift
///   file, which the next save writes again.
///
/// The listing goes through `dir`. Each known child is opened by its path
/// without following a reparse point, checked on that handle and deleted
/// through the same handle. The directory owner and parents are trusted by
/// now, so nobody unprivileged can swap the path in between.
fn clean_known_children(dir: &OwnedHandle, path: &Path) -> Result<(), AclError> {
    let entries = win32::list_dir(dir).map_err(|e| os("list", &e))?;
    let mut doomed = Vec::with_capacity(entries.len());
    for entry in &entries {
        let known = KNOWN_CHILDREN.iter().any(|k| entry.name == *k);
        if !known || entry.attributes & (ATTR_DIRECTORY | ATTR_REPARSE_POINT) != 0 {
            return Err(AclError::UnexpectedChild);
        }
        let child = win32::open_no_follow(&path.join(&entry.name), DELETE | FILE_READ_ATTRIBUTES)
            .map_err(|e| os("open child", &e))?;
        let info = win32::link_info(&child).map_err(|e| os("check child", &e))?;
        if info.links != 1 || info.attributes & (ATTR_DIRECTORY | ATTR_REPARSE_POINT) != 0 {
            return Err(AclError::UnexpectedChild);
        }
        doomed.push(child);
    }
    for child in &doomed {
        win32::delete_by_handle(child).map_err(|e| os("delete child", &e))?;
    }
    // The files go when their handles close.
    drop(doomed);
    // Something created during the clean-up also refuses.
    if !win32::list_dir(dir).map_err(|e| os("list", &e))?.is_empty() {
        return Err(AclError::UnexpectedChild);
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
            AclError::UntrustedParent,
            AclError::UnexpectedChild,
            AclError::TrailingDotOrSpace,
            AclError::NotFixedDrive,
            AclError::PathChanged,
            AclError::ReservedName,
            AclError::RollbackFailed {
                cause: "a".into(),
                rollback: "b".into(),
            },
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

    #[test]
    fn sid_strings_map_to_principals() {
        use crate::win32::principal_from_sid_string as p;
        assert_eq!(p("S-1-5-18"), Principal::System);
        assert_eq!(p("S-1-5-32-544"), Principal::Administrators);
        assert_eq!(
            p("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
            Principal::TrustedInstaller
        );
        // Users, Authenticated Users, a user SID, a near miss.
        for other in [
            "S-1-5-32-545",
            "S-1-5-11",
            "S-1-5-21-1-2-3-1001",
            "S-1-5-18-1",
            "S-1-5-32-5440",
            "",
        ] {
            assert_eq!(p(other), Principal::Other, "{other}");
        }
    }

    #[test]
    fn parent_owners_allowed_are_system_admins_and_trusted_installer() {
        assert!(parent_owner_trusted(Some(Principal::System)));
        assert!(parent_owner_trusted(Some(Principal::Administrators)));
        assert!(parent_owner_trusted(Some(Principal::TrustedInstaller)));
        assert!(!parent_owner_trusted(Some(Principal::Other)));
        assert!(!parent_owner_trusted(None));
    }

    #[test]
    fn state_dir_owner_may_not_be_trusted_installer() {
        let mut s = secure();
        s.owner = Some(Principal::TrustedInstaller);
        assert!(!owner_trusted(&s));
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
    fn user_owned_parent_is_refused_and_nothing_is_created() {
        if elevated() {
            eprintln!("skip: elevated, the scratch parent is owned by Administrators");
            return;
        }
        let s = Scratch::new("parentowner");
        let dir = s.0.join("state");
        let r = secure_state_dir(&dir);
        assert_eq!(r, Err(AclError::UntrustedParent));
        assert!(!r.unwrap_err().to_string().contains("ntpc-acl"));
        assert!(!dir.exists());
    }

    #[test]
    fn trusted_system_folder_passes_the_parent_check() {
        // Read only: opens C:\Windows for attributes and owner. Its owner is
        // TrustedInstaller on a default install. Nothing is written.
        let windows = Path::new(r"C:\Windows");
        if !windows.is_dir() {
            eprintln!("skip: no C:\\Windows");
            return;
        }
        assert_eq!(check_ancestor(windows, true, &OS_PROBE), Ok(()));
        assert_eq!(check_ancestor(Path::new(r"C:\"), false, &OS_PROBE), Ok(()));
    }

    // The tests below run inside a user-owned scratch tree, which the parent
    // check refuses. So they call `secure_final`, the part after it.

    #[test]
    fn user_owned_existing_dir_is_refused() {
        if elevated() {
            eprintln!("skip: elevated, a new directory would be owned by Administrators");
            return;
        }
        let s = Scratch::new("owner");
        let dir = s.0.join("state");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(secure_final(&dir), Err(AclError::UntrustedOwner));
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
        assert_eq!(secure_final(&link), Err(AclError::Link));
    }

    #[test]
    fn junctioned_parent_is_refused() {
        let s = Scratch::new("parent");
        let real = s.0.join("real");
        std::fs::create_dir_all(real.join("state")).unwrap();
        let link = s.0.join("link");
        if !junction(&link, &real) {
            eprintln!("skip: mklink /J failed");
            return;
        }
        // The reparse check comes before the owner check.
        assert_eq!(
            check_ancestor(&link, true, &OS_PROBE),
            Err(AclError::ParentLink)
        );
        assert_eq!(
            check_ancestor(&link, false, &OS_PROBE),
            Err(AclError::ParentLink)
        );
        // End to end, with every parent owner reported as trusted, the
        // junction itself is what refuses.
        assert_eq!(
            secure_state_dir_with(&link.join("state"), &TRUSTED),
            Err(AclError::ParentLink)
        );
        assert_eq!(
            secure_state_dir_with(&link.join("new"), &TRUSTED),
            Err(AclError::ParentLink)
        );
        assert!(!real.join("new").exists());
    }

    #[test]
    fn real_call_under_a_junction_in_a_user_tree_refuses_and_creates_nothing() {
        // With the real owner probe the user-owned scratch parent refuses
        // first. This proves only that nothing is created through the link.
        let s = Scratch::new("parentreal");
        let real = s.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = s.0.join("link");
        if !junction(&link, &real) {
            eprintln!("skip: mklink /J failed");
            return;
        }
        assert!(secure_state_dir(&link.join("new")).is_err());
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
        assert_eq!(secure_final(&link), Err(AclError::Link));
    }

    #[test]
    fn a_file_at_the_path_is_refused() {
        let s = Scratch::new("file");
        let file = s.0.join("state");
        std::fs::write(&file, b"x").unwrap();
        let r = secure_final(&file);
        // Non-elevated, the user owns the file, so either check may fire
        // first. Both refuse.
        assert!(
            matches!(r, Err(AclError::NotADirectory | AclError::UntrustedOwner)),
            "{r:?}"
        );
    }

    #[test]
    fn missing_parent_fails_the_parent_check_and_creates_nothing() {
        let s = Scratch::new("noparent");
        let dir = s.0.join("missing").join("state");
        let r = secure_state_dir_with(&dir, &TRUSTED);
        assert!(
            matches!(
                r,
                Err(AclError::Os {
                    op: "parent check",
                    ..
                })
            ),
            "{r:?}"
        );
        assert!(!s.0.join("missing").exists());
    }

    #[test]
    fn missing_parent_through_secure_final_creates_nothing() {
        // `secure_final` alone, with the parent `missing` absent. Non-elevated
        // the token owner check refuses first. Elevated the create fails
        // because the parent is not there. Either way nothing is created.
        let s = Scratch::new("nodir");
        let dir = s.0.join("missing").join("state");
        assert!(secure_final(&dir).is_err());
        assert!(!s.0.join("missing").exists());
    }

    // The signature must match `Probe::owner`, so the `Result` stays.
    #[allow(clippy::unnecessary_wraps)]
    fn trusted_owner(_: &OwnedHandle) -> io::Result<Option<Principal>> {
        Ok(Some(Principal::System))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn untrusted_owner(_: &OwnedHandle) -> io::Result<Option<Principal>> {
        Ok(Some(Principal::Other))
    }

    fn fixed(_: &Path) -> u32 {
        DRIVE_FIXED
    }

    fn removable(_: &Path) -> u32 {
        2
    }

    /// Every parent reported as owned by SYSTEM, every drive as fixed.
    const TRUSTED: Probe = Probe {
        owner: trusted_owner,
        drive_type: fixed,
    };

    #[test]
    fn injected_owner_decides_the_parent_check() {
        let s = Scratch::new("inject");
        let untrusted = Probe {
            owner: untrusted_owner,
            drive_type: fixed,
        };
        assert_eq!(check_ancestor(&s.0, true, &TRUSTED), Ok(()));
        assert_eq!(
            check_ancestor(&s.0, true, &untrusted),
            Err(AclError::UntrustedParent)
        );
        // The root is exempt: no owner is read.
        assert_eq!(check_ancestor(&s.0, false, &untrusted), Ok(()));
    }

    #[test]
    fn only_fixed_drives_pass() {
        assert_eq!(drive_ok(DRIVE_FIXED), Ok(()));
        // Unknown, no root, removable, remote, CD-ROM, RAM disk.
        for t in [0, 1, 2, 4, 5, 6] {
            assert_eq!(drive_ok(t), Err(AclError::NotFixedDrive), "{t}");
        }
        let probe = Probe {
            owner: trusted_owner,
            drive_type: removable,
        };
        assert_eq!(
            secure_state_dir_with(Path::new(r"C:\ProgramData\ntpc"), &probe),
            Err(AclError::NotFixedDrive)
        );
    }

    /// The first drive letter from D to Z whose `GetDriveTypeW` is `want`.
    /// Read only.
    fn drive_of_type(want: u32) -> Option<PathBuf> {
        (b'D'..=b'Z')
            .map(|l| PathBuf::from(format!("{}:\\", char::from(l))))
            .find(|r| win32::drive_type(r) == want)
    }

    #[test]
    fn a_real_remote_drive_is_refused() {
        // DRIVE_REMOTE is 4. No file is opened there: the drive check comes
        // before any open.
        let Some(root) = drive_of_type(4) else {
            eprintln!("skip: no mapped network drive");
            return;
        };
        eprintln!("remote drive used: {}", root.display());
        assert_eq!(
            secure_state_dir(&root.join("ntpc-state")),
            Err(AclError::NotFixedDrive)
        );
    }

    #[test]
    fn an_unused_drive_letter_is_refused() {
        // DRIVE_NO_ROOT_DIR is 1: the letter is not in use.
        let Some(root) = drive_of_type(1) else {
            eprintln!("skip: every letter from D to Z is in use");
            return;
        };
        assert_eq!(
            secure_state_dir(&root.join("ntpc-state")),
            Err(AclError::NotFixedDrive)
        );
    }

    #[test]
    fn drive_root_handles_plain_and_verbatim_paths() {
        assert_eq!(
            drive_root(Path::new(r"C:\x\y")).unwrap(),
            PathBuf::from(r"C:\")
        );
        assert_eq!(
            drive_root(Path::new(r"\\?\D:\x")).unwrap(),
            PathBuf::from(r"D:\")
        );
        assert_eq!(drive_root(Path::new(r"x\y")), Err(AclError::BadPath));
    }

    #[test]
    fn components_ending_in_dot_or_space_are_refused() {
        for p in [
            r"C:\ProgramData\ntpc.",
            r"C:\ProgramData\ntpc ",
            r"C:\ProgramData.\ntpc",
            r"C:\Program Data \ntpc",
            r"C:\a\b...",
        ] {
            assert_eq!(
                ancestors(Path::new(p)),
                Err(AclError::TrailingDotOrSpace),
                "{p}"
            );
        }
        for p in [r"C:\Program Data\ntpc", r"C:\a.b\c", r"C:\.hidden\x"] {
            assert!(ancestors(Path::new(p)).is_ok(), "{p}");
        }
    }

    #[test]
    fn require_empty_helper_refuses_a_planted_file_and_deletes_nothing() {
        let s = Scratch::new("planted");
        let dir = state_dir(&s);
        let h = listing_handle(&dir);
        assert_eq!(require_empty(&h), Ok(()));
        std::fs::write(dir.join("drift.txt"), b"9.9").unwrap();
        assert_eq!(require_empty(&h), Err(AclError::UnexpectedChild));
        assert!(dir.join("drift.txt").exists(), "must not delete");
    }

    #[test]
    fn identity_check_spots_a_rename_swap() {
        let s = Scratch::new("swap");
        let dir = state_dir(&s);
        let h = listing_handle(&dir);
        assert_eq!(same_object(&h, &dir), Ok(()));
        std::fs::rename(&dir, s.0.join("moved")).unwrap();
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(same_object(&h, &dir), Err(AclError::PathChanged));
    }

    #[test]
    fn user_token_creates_nothing() {
        if !matches!(win32::token_default_owner().unwrap(), Principal::Other) {
            eprintln!("skip: the token's default owner is trusted");
            return;
        }
        let s = Scratch::new("create");
        let dir = s.0.join("state");
        assert_eq!(secure_final(&dir), Err(AclError::UntrustedOwner));
        assert!(!dir.exists(), "directory created for an untrusted owner");
    }

    // `clean_known_children` is tested directly on a user-owned scratch
    // directory. Through `secure_state_dir` a user-owned directory is refused
    // at the owner check first, so non-elevated runs cannot reach it there.

    fn listing_handle(dir: &Path) -> OwnedHandle {
        win32::open_no_follow(dir, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).unwrap()
    }

    fn state_dir(s: &Scratch) -> PathBuf {
        let dir = s.0.join("state");
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn clean_removes_known_single_link_files() {
        let s = Scratch::new("cleanok");
        let dir = state_dir(&s);
        std::fs::write(dir.join("drift.txt"), b"1.0").unwrap();
        std::fs::write(dir.join("drift.txt.tmp"), b"2.0").unwrap();
        let h = listing_handle(&dir);
        assert_eq!(clean_known_children(&h, &dir), Ok(()));
        assert!(!dir.join("drift.txt").exists());
        assert!(!dir.join("drift.txt.tmp").exists());
    }

    #[test]
    fn clean_of_an_empty_dir_is_fine() {
        let s = Scratch::new("cleanempty");
        let dir = state_dir(&s);
        let h = listing_handle(&dir);
        assert_eq!(clean_known_children(&h, &dir), Ok(()));
    }

    #[test]
    fn clean_refuses_a_hard_linked_drift_file_and_deletes_nothing() {
        let s = Scratch::new("cleanhard");
        let dir = state_dir(&s);
        let outside = s.0.join("victim.txt");
        std::fs::write(&outside, b"keep").unwrap();
        std::fs::hard_link(&outside, dir.join("drift.txt")).unwrap();
        std::fs::write(dir.join("drift.txt.tmp"), b"2.0").unwrap();
        let h = listing_handle(&dir);
        assert_eq!(
            clean_known_children(&h, &dir),
            Err(AclError::UnexpectedChild)
        );
        assert!(dir.join("drift.txt").exists());
        assert!(
            dir.join("drift.txt.tmp").exists(),
            "deleted before refusing"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    }

    #[test]
    fn clean_refuses_a_symlink_child() {
        let s = Scratch::new("cleansym");
        let dir = state_dir(&s);
        let target = s.0.join("target.txt");
        std::fs::write(&target, b"keep").unwrap();
        if std::os::windows::fs::symlink_file(&target, dir.join("drift.txt")).is_err() {
            eprintln!("skip: no right to create a symlink");
            return;
        }
        let h = listing_handle(&dir);
        assert_eq!(
            clean_known_children(&h, &dir),
            Err(AclError::UnexpectedChild)
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn clean_refuses_an_unknown_child() {
        let s = Scratch::new("cleanunknown");
        let dir = state_dir(&s);
        std::fs::write(dir.join("drift.txt"), b"1.0").unwrap();
        std::fs::write(dir.join("other.txt"), b"x").unwrap();
        let h = listing_handle(&dir);
        assert_eq!(
            clean_known_children(&h, &dir),
            Err(AclError::UnexpectedChild)
        );
        assert!(dir.join("drift.txt").exists(), "deleted before refusing");
    }

    #[test]
    fn clean_refuses_a_directory_named_drift_txt() {
        let s = Scratch::new("cleansubdir");
        let dir = state_dir(&s);
        std::fs::create_dir(dir.join("drift.txt")).unwrap();
        let h = listing_handle(&dir);
        assert_eq!(
            clean_known_children(&h, &dir),
            Err(AclError::UnexpectedChild)
        );
        assert!(dir.join("drift.txt").is_dir());
    }

    #[test]
    fn clean_refuses_a_junction_named_drift_txt() {
        let s = Scratch::new("cleanjunction");
        let dir = state_dir(&s);
        let target = s.0.join("target");
        std::fs::create_dir(&target).unwrap();
        if !junction(&dir.join("drift.txt"), &target) {
            eprintln!("skip: mklink /J failed");
            return;
        }
        let h = listing_handle(&dir);
        assert_eq!(
            clean_known_children(&h, &dir),
            Err(AclError::UnexpectedChild)
        );
    }

    #[test]
    fn elevated_create_and_recheck_succeed() {
        if !elevated() {
            eprintln!("skip: not elevated, the DACL success path needs Administrators");
            return;
        }
        // `secure_final`: the scratch parent's owner depends on the temp
        // dir, which is not under test here.
        let s = Scratch::new("elevated");
        let dir = s.0.join("state");
        secure_final(&dir).unwrap();
        // The second call takes the already-exists path.
        secure_final(&dir).unwrap();
        let h = win32::open_no_follow(&dir, READ_CONTROL | FILE_READ_ATTRIBUTES).unwrap();
        let sec = win32::read_security(&h).unwrap();
        assert!(owner_trusted(&sec) && dacl_is_secure(&sec), "{sec:?}");
        // Cleanup: Administrators hold full control on the directory, so the
        // elevated test removes it through Scratch::drop.
    }

    #[test]
    fn elevated_wrong_dacl_is_quarantined_and_replaced() {
        if !elevated() {
            eprintln!("skip: not elevated, a trusted owner needs Administrators");
            return;
        }
        // Elevated, the new directory is owned by Administrators and keeps
        // the inherited DACL from the scratch parent: a wrong DACL.
        let s = Scratch::new("elevatedfix");
        let dir = state_dir(&s);
        std::fs::write(dir.join("drift.txt"), b"1.0").unwrap();
        let before = win32::link_info(&listing_handle(&dir)).unwrap();
        secure_final(&dir).unwrap();
        let h = win32::open_no_follow(&dir, READ_CONTROL | FILE_READ_ATTRIBUTES).unwrap();
        let after = win32::link_info(&h).unwrap();
        assert!(!before.same_file(&after), "the old object was kept");
        assert!(dacl_is_secure(&win32::read_security(&h).unwrap()));
        assert!(!dir.join("drift.txt").exists());
        drop(h);
        // A known file written by an Administrators token is kept.
        std::fs::write(dir.join("drift.txt"), b"2.0").unwrap();
        let kept = win32::link_info(&listing_handle(&dir)).unwrap();
        secure_final(&dir).unwrap();
        let now = win32::link_info(&listing_handle(&dir)).unwrap();
        assert!(kept.same_file(&now), "fast path should keep the directory");
        assert!(dir.join("drift.txt").exists());
        // An unknown name refuses.
        std::fs::write(dir.join("other"), b"x").unwrap();
        assert_eq!(secure_final(&dir), Err(AclError::UnexpectedChild));
        // A user-owned known file cannot be planted from an elevated test
        // without changing an owner, so that row is covered by `decide`.
        eprintln!("quarantine leftovers: {:?}", quarantine_leftovers(&s.0));
    }

    fn quarantine_leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".old-"))
            .collect()
    }

    fn obs(known: bool, kind: ChildKind, links: u32, owner_trusted: bool) -> ChildObs {
        ChildObs {
            known,
            kind,
            links,
            owner_trusted,
        }
    }

    #[test]
    fn decision_table() {
        use ChildKind::{Directory, File, Link};
        let good = obs(true, File, 1, true);
        let user_owned = obs(true, File, 1, false);
        // (DACL exact, children, expected)
        let rows: Vec<(bool, Vec<ChildObs>, Decision)> = vec![
            (true, vec![], Decision::Keep),
            (true, vec![good], Decision::Keep),
            (true, vec![good, good], Decision::Keep),
            (false, vec![], Decision::Quarantine),
            (false, vec![good], Decision::Quarantine),
            (true, vec![user_owned], Decision::Quarantine),
            (false, vec![user_owned], Decision::Quarantine),
            (true, vec![good, user_owned], Decision::Quarantine),
            (true, vec![obs(false, File, 1, true)], Decision::Refuse),
            (false, vec![obs(false, File, 1, false)], Decision::Refuse),
            (true, vec![obs(true, Directory, 0, true)], Decision::Refuse),
            (true, vec![obs(true, Link, 0, true)], Decision::Refuse),
            (true, vec![obs(true, File, 2, true)], Decision::Refuse),
            (false, vec![obs(true, File, 2, false)], Decision::Refuse),
            (true, vec![obs(true, File, 0, true)], Decision::Refuse),
            (
                true,
                vec![good, obs(false, File, 1, true)],
                Decision::Refuse,
            ),
            (
                false,
                vec![user_owned, obs(true, Link, 0, false)],
                Decision::Refuse,
            ),
        ];
        for (dacl, children, want) in rows {
            assert_eq!(decide(dacl, &children), want, "{dacl} {children:?}");
        }
    }

    fn inspect(dir: &Path) -> Vec<ChildObs> {
        let h = win32::open_no_follow(dir, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).unwrap();
        inspect_children(&h, dir).unwrap()
    }

    #[test]
    fn validator_empty_dir_keeps() {
        let s = Scratch::new("valempty");
        let dir = state_dir(&s);
        assert_eq!(inspect(&dir), vec![]);
        assert_eq!(decide(true, &inspect(&dir)), Decision::Keep);
    }

    #[test]
    fn validator_user_owned_known_file_quarantines() {
        if elevated() {
            eprintln!("skip: elevated, the file would be owned by Administrators");
            return;
        }
        let s = Scratch::new("valuser");
        let dir = state_dir(&s);
        std::fs::write(dir.join("drift.txt"), b"1.0").unwrap();
        let c = inspect(&dir);
        assert_eq!(c, vec![obs(true, ChildKind::File, 1, false)]);
        assert_eq!(decide(true, &c), Decision::Quarantine);
    }

    #[test]
    fn validator_refuses_a_hard_link() {
        let s = Scratch::new("valhard");
        let dir = state_dir(&s);
        let outside = s.0.join("victim.txt");
        std::fs::write(&outside, b"keep").unwrap();
        std::fs::hard_link(&outside, dir.join("drift.txt")).unwrap();
        let c = inspect(&dir);
        assert_eq!(c[0].links, 2);
        assert_eq!(decide(true, &c), Decision::Refuse);
    }

    #[test]
    fn validator_refuses_a_symlink() {
        let s = Scratch::new("valsym");
        let dir = state_dir(&s);
        let target = s.0.join("target.txt");
        std::fs::write(&target, b"keep").unwrap();
        if std::os::windows::fs::symlink_file(&target, dir.join("drift.txt")).is_err() {
            eprintln!("skip: no right to create a symlink");
            return;
        }
        let c = inspect(&dir);
        assert_eq!(c[0].kind, ChildKind::Link);
        assert_eq!(decide(true, &c), Decision::Refuse);
    }

    #[test]
    fn validator_refuses_an_unknown_name() {
        let s = Scratch::new("valunknown");
        let dir = state_dir(&s);
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        let c = inspect(&dir);
        assert!(!c[0].known);
        assert_eq!(decide(true, &c), Decision::Refuse);
    }

    #[test]
    fn validator_refuses_a_subdirectory() {
        let s = Scratch::new("valsubdir");
        let dir = state_dir(&s);
        std::fs::create_dir(dir.join("drift.txt")).unwrap();
        let c = inspect(&dir);
        assert_eq!(c[0].kind, ChildKind::Directory);
        assert_eq!(decide(true, &c), Decision::Refuse);
    }

    /// Records the order of the steps and can fail one of them.
    struct FakeOps {
        log: std::cell::RefCell<Vec<&'static str>>,
        fail: Option<&'static str>,
    }

    impl FakeOps {
        fn new(fail: Option<&'static str>) -> Self {
            Self {
                log: std::cell::RefCell::new(Vec::new()),
                fail,
            }
        }

        fn step(&self, name: &'static str) -> Result<(), AclError> {
            self.log.borrow_mut().push(name);
            if self.fail == Some(name) {
                Err(AclError::UnexpectedChild)
            } else {
                Ok(())
            }
        }
    }

    impl DirOps for FakeOps {
        fn write_dacl(&self, _: &OwnedHandle) -> Result<(), AclError> {
            self.step("write_dacl")
        }

        fn read_security(&self, _: &OwnedHandle) -> Result<Security, AclError> {
            self.step("read_security").map(|()| secure())
        }

        fn require_empty(&self, _: &OwnedHandle) -> Result<(), AclError> {
            self.step("require_empty")
        }

        fn same_object(&self, _: &OwnedHandle, _: &Path) -> Result<(), AclError> {
            self.step("same_object")
        }
    }

    #[test]
    fn fresh_path_runs_every_check_after_the_dacl_write() {
        let s = Scratch::new("pinfresh");
        let h = listing_handle(&s.0);
        let ops = FakeOps::new(None);
        assert_eq!(finish_fresh(&ops, &h, &s.0), Ok(()));
        assert_eq!(
            *ops.log.borrow(),
            vec![
                "write_dacl",
                "read_security",
                "require_empty",
                "same_object"
            ]
        );
        for step in ["require_empty", "same_object"] {
            let ops = FakeOps::new(Some(step));
            assert_eq!(
                finish_fresh(&ops, &h, &s.0),
                Err(AclError::UnexpectedChild),
                "{step}"
            );
        }
    }

    #[test]
    fn keep_path_checks_the_identity() {
        let s = Scratch::new("pinkeep");
        let h = listing_handle(&s.0);
        let ops = FakeOps::new(None);
        assert_eq!(finish_keep(&ops, &h, &s.0), Ok(()));
        assert_eq!(*ops.log.borrow(), vec!["same_object"]);
        let ops = FakeOps::new(Some("same_object"));
        assert!(finish_keep(&ops, &h, &s.0).is_err());
    }

    fn rename_handle(dir: &Path) -> OwnedHandle {
        // The temp dir grants Modify, not WRITE_OWNER, so not DIR_RIGHTS.
        win32::open_no_follow(dir, DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES).unwrap()
    }

    #[test]
    fn quarantine_rename_and_rename_back() {
        let s = Scratch::new("qrename");
        let dir = state_dir(&s);
        let h = rename_handle(&dir);
        let q = rename_to_quarantine(&h, &dir).unwrap();
        let name = q.file_name().unwrap().to_string_lossy().into_owned();
        let hex = name.strip_prefix("state.old-").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!dir.exists() && q.is_dir());
        win32::rename_by_handle(&h, &dir).unwrap();
        assert!(dir.is_dir() && !q.exists());
    }

    #[test]
    fn failed_fresh_create_rolls_the_old_directory_back() {
        if !matches!(win32::token_default_owner().unwrap(), Principal::Other) {
            eprintln!("skip: the token's default owner is trusted, the fresh create would work");
            return;
        }
        // Non-elevated, `create_fresh` refuses (untrusted token owner) after
        // the rename. The old directory must come back under its own name.
        let s = Scratch::new("qrollback");
        let dir = state_dir(&s);
        std::fs::write(dir.join("drift.txt"), b"1.0").unwrap();
        let before = win32::link_info(&listing_handle(&dir)).unwrap();
        let h = rename_handle(&dir);
        assert_eq!(
            quarantine_and_recreate(&h, &dir),
            Err(AclError::UntrustedOwner)
        );
        drop(h);
        let back = win32::link_info(&listing_handle(&dir)).unwrap();
        assert!(before.same_file(&back), "old directory not restored");
        assert!(!dir.join("drift.txt").exists(), "known file cleaned first");
        assert_eq!(quarantine_leftovers(&s.0), Vec::<String>::new());
    }

    #[test]
    fn identity_check_refuses_a_junction_now_at_the_path() {
        let s = Scratch::new("swapjunction");
        let dir = state_dir(&s);
        let h = listing_handle(&dir);
        std::fs::rename(&dir, s.0.join("moved")).unwrap();
        if !junction(&dir, &s.0.join("moved")) {
            eprintln!("skip: mklink /J failed");
            return;
        }
        assert_eq!(same_object(&h, &dir), Err(AclError::Link));
    }

    #[test]
    fn device_names_and_colons_are_refused() {
        for p in [
            r"C:\ProgramData\CON",
            r"C:\ProgramData\nul.txt",
            r"C:\ProgramData\Aux\state",
            r"C:\ProgramData\com1",
            r"C:\ProgramData\LPT9.log",
            r"C:\ProgramData\prn .x",
            r"C:\ProgramData\ntpc:stream",
            r"C:\ProgramData\ntpc::$DATA",
            r"\\?\C:\ProgramData\ntpc:x",
        ] {
            assert_eq!(ancestors(Path::new(p)), Err(AclError::ReservedName), "{p}");
        }
        for p in [
            r"C:\ProgramData\console",
            r"C:\ProgramData\COM0",
            r"C:\ProgramData\COM10",
            r"C:\ProgramData\LPT",
            r"C:\ProgramData\nulled",
            // Verbatim paths do not map device names.
            r"\\?\C:\ProgramData\CON",
        ] {
            assert!(ancestors(Path::new(p)).is_ok(), "{p}");
        }
    }
}
