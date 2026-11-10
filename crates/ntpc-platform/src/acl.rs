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
//!   refused, never re-ACLed.
//! - The DACL is protected (nothing inherited from the parent) and grants
//!   SYSTEM and Administrators full control, inherited by files and
//!   folders. Users get nothing: the directory holds only service state
//!   (drift, the w32time restore record, status).
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
///
/// Non-exhaustive: callers need a wildcard arm, so new refusals do not break
/// them.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The restore record could not be written into the fresh directory, or
    /// it did not read back the same.
    #[error("restore record could not be carried into the fresh state directory: {detail}")]
    RestoreCarryFailed {
        /// What failed. OS text, no path.
        detail: String,
    },
    /// Securing a fresh directory failed after the old one was moved to
    /// quarantine, and moving it back failed too. Both errors are kept.
    #[error(
        "state directory replacement failed ({cause}), and moving the previous directory back failed ({rollback}). The previous directory was left under a sibling name ending in .old- and a hex suffix, and it may hold the restore record"
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
/// only plain single-link files from [`KNOWN_CHILDREN`] owned by SYSTEM or
/// Administrators. A directory with a wrong DACL or a wrong-owned known child
/// is replaced by a fresh one (R78). The old one goes to a quarantine sibling
/// `<name>.old-<hex>`, which is deleted best effort and may be left behind,
/// empty or holding whatever an attacker put there later. Nothing reads it.
///
/// On that replacement only `restore.json` is carried into the fresh
/// directory (R80), and only if the old file is a plain single-link file of
/// at most 4 KiB owned by SYSTEM or Administrators. The bytes read through
/// that checked handle are written with `create_new`, synced and read back.
/// A restore record that fails the checks is not carried and not deleted:
/// it stays in the quarantine, and the result says
/// [`RestoreRecord::Dropped`]. Its content is checked by its reader, not
/// here. Everything else is regenerated or relearnt.
///
/// A directory this call creates and then cannot secure is removed again,
/// best effort. It is empty and ours, and a half-secured directory must not
/// be left behind.
///
/// `RollbackFailed` recovery (R88): the window between the quarantine rename
/// and the fresh create can be raced. A local user who creates a directory
/// at the original name in that window makes both the create and the rename
/// back fail. That needs a weak pre-existing directory and a user racing the
/// window. The previous directory, possibly holding `restore.json`, is then
/// left as `<name>.old-<hex>`. To recover: delete the squatter directory,
/// rename `<name>.old-<hex>` back to `<name>`, and run again. The caller
/// must refuse on `RollbackFailed` (install with its own exit code). The
/// quarantine name is deliberately not in the error, so a script cannot be
/// tricked into acting on a path an attacker chose. Task 12 treats it as
/// "the record may be in quarantine".
///
/// The fast path trusts any directory whose DACL is exactly the secure one.
/// An administrator must never re-ACL the state directory in place: a handle
/// opened before such a change would keep its rights. Quarantine siblings
/// `*.old-*` that stay behind are not cleaned up by the service. Removing
/// them is an administrator step.
///
/// Deferred (m-5): a file created at `restore.json` between the inspection
/// and the read can turn `Absent` into `Dropped`. That fails safe (install
/// refuses), so it is left as it is.
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
pub fn secure_state_dir(path: &Path) -> Result<Secured, AclError> {
    secure_state_dir_with(path, &OS_PROBE)
}

/// What `secure_state_dir` did with the w32time restore record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "install must refuse on RestoreRecord::Dropped"]
pub struct Secured {
    /// The fate of `restore.json`.
    pub restore_record: RestoreRecord,
}

/// The w32time restore record (`restore.json`, Task 12) after securing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreRecord {
    /// It is in the secured directory: kept on the fast path, or carried
    /// into a fresh directory.
    Kept,
    /// It existed but failed the provenance checks (owner, links, kind or
    /// size), so it was not carried. It stays in the quarantine directory.
    /// Install must treat the record as lost.
    Dropped,
    /// There was none.
    Absent,
}

impl Secured {
    const ABSENT: Self = Self {
        restore_record: RestoreRecord::Absent,
    };
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

fn secure_state_dir_with(path: &Path, probe: &Probe) -> Result<Secured, AclError> {
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
fn secure_final(path: &Path) -> Result<Secured, AclError> {
    let (handle, created) = open_or_create(path)?;
    let result = if created {
        secure_fresh(&handle, path).map(|()| Secured::ABSENT)
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
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let mut chars = stem.chars();
            let head: String = chars.by_ref().take(3).collect();
            let digit = chars.next();
            (head == "COM" || head == "LPT")
                && chars.next().is_none()
                // Windows also maps the superscript digits one, two and three.
                && matches!(digit, Some('1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'))
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
fn secure_existing(h: &OwnedHandle, path: &Path) -> Result<Secured, AclError> {
    check_handle(h)?;
    let sec = win32::read_security(h).map_err(|e| os("read security", &e))?;
    if !owner_trusted(&sec) {
        return Err(AclError::UntrustedOwner);
    }
    let children = inspect_children(h, path)?;
    let restore_record = match decide(dacl_is_secure(&sec), &children) {
        Decision::Keep => {
            finish_keep(&OsOps, h, path)?;
            if children.iter().any(|c| c.restore) {
                RestoreRecord::Kept
            } else {
                RestoreRecord::Absent
            }
        }
        Decision::Refuse => return Err(AclError::UnexpectedChild),
        Decision::Quarantine => quarantine_and_recreate(h, path)?,
    };
    Ok(Secured { restore_record })
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
    /// A name from [`KNOWN_CHILDREN`].
    known: bool,
    /// The name is `restore.json`.
    restore: bool,
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
                restore: entry.name == RESTORE_NAME,
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
            restore: entry.name == RESTORE_NAME,
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
fn quarantine_and_recreate(h: &OwnedHandle, path: &Path) -> Result<RestoreRecord, AclError> {
    quarantine_with(&OsQuarantine, h, path)
}

/// The steps of the quarantine path that tests replace. The real versions
/// are in [`OsQuarantine`]. A test cannot create a protected directory
/// without elevation, so its `create_fresh` makes a plain directory instead.
/// Everything else (read, clean, the quarantine rename, the rename back, the
/// removal of the fresh directory by handle) stays real.
trait QuarantineOps {
    /// The restore record's owner is SYSTEM or Administrators.
    fn restore_owner_ok(&self, h: &OwnedHandle) -> Result<bool, AclError>;
    /// Creates and secures the fresh directory, returning its handle.
    fn create_fresh(&self, path: &Path) -> Result<OwnedHandle, AclError>;
    /// Writes `restore.json` into the fresh directory and verifies it.
    fn write_restore(&self, dir: &Path, bytes: &[u8]) -> Result<(), AclError>;
    /// Reads a written file back.
    fn read_back(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Moves the old directory back to its name.
    fn rename_back(&self, h: &OwnedHandle, path: &Path) -> io::Result<()>;
    /// Deletes the emptied quarantine, best effort.
    fn delete_quarantine(&self, h: &OwnedHandle);
}

struct OsQuarantine;

impl QuarantineOps for OsQuarantine {
    fn restore_owner_ok(&self, h: &OwnedHandle) -> Result<bool, AclError> {
        os_child_owner_trusted(h)
    }

    fn create_fresh(&self, path: &Path) -> Result<OwnedHandle, AclError> {
        create_fresh(path)
    }

    fn write_restore(&self, dir: &Path, bytes: &[u8]) -> Result<(), AclError> {
        write_restore(dir, bytes, &|p| self.read_back(p))
    }

    fn read_back(&self, path: &Path) -> io::Result<Vec<u8>> {
        os_read_back(path)
    }

    fn rename_back(&self, h: &OwnedHandle, path: &Path) -> io::Result<()> {
        win32::rename_by_handle(h, path)
    }

    fn delete_quarantine(&self, h: &OwnedHandle) {
        // Best effort, as R78 says. Delete through the handle, so no link is
        // followed. A failure leaves an inert quarantine directory that
        // nothing reads.
        let _ = win32::delete_by_handle(h);
    }
}

/// R78 and R80, in order:
/// 1. read the restore record through its checked handle;
/// 2. clean the other known files;
/// 3. rename the old directory to `<name>.old-<hex>` through its handle;
/// 4. create and secure the fresh directory;
/// 5. carry the restore record into it.
///
/// If 4 or 5 fails, the fresh directory (if made) is deleted through its
/// handle, and the old one is renamed back. If that fails too, the error is
/// `RollbackFailed` and nothing in the quarantine is touched. On success the
/// carried original is removed from the quarantine, and the quarantine is
/// deleted only when no record was dropped. A dropped record stays there.
fn quarantine_with(
    ops: &impl QuarantineOps,
    h: &OwnedHandle,
    path: &Path,
) -> Result<RestoreRecord, AclError> {
    let source = read_restore(path, &|c| ops.restore_owner_ok(c))?;
    clean_known_children(h, path)?;
    let quarantine = rename_to_quarantine(h, path)?;
    let result = ops.create_fresh(path).and_then(|fresh| {
        let carried = match &source {
            RestoreSource::Carry { bytes, .. } => {
                ops.write_restore(path, bytes).map(|()| RestoreRecord::Kept)
            }
            RestoreSource::Dropped => Ok(RestoreRecord::Dropped),
            RestoreSource::Absent => Ok(RestoreRecord::Absent),
        };
        if carried.is_err() {
            // `write_restore` removed its own file, so the fresh directory is
            // empty. Delete it through its handle. The name is freed when the
            // handle closes, just below, before the rename back.
            let _ = win32::delete_by_handle(&fresh);
        }
        drop(fresh);
        carried
    });
    match result {
        Ok(record) => {
            if let RestoreSource::Carry { id, .. } = &source {
                remove_carried_original(&quarantine, id);
            }
            if record != RestoreRecord::Dropped {
                ops.delete_quarantine(h);
            }
            Ok(record)
        }
        Err(cause) => match ops.rename_back(h, path) {
            Ok(()) => Err(cause),
            Err(e) => Err(AclError::RollbackFailed {
                cause: cause.to_string(),
                rollback: e.to_string(),
            }),
        },
    }
}

/// The largest restore record that is carried.
const RESTORE_MAX_BYTES: u64 = 4096;

/// `FILE_READ_DATA`.
const FILE_READ_DATA: u32 = 0x0001;

/// The old restore record, read before the quarantine rename.
#[derive(Debug)]
enum RestoreSource {
    /// None there.
    Absent,
    /// There, but it failed a provenance check. Left where it is.
    Dropped,
    /// There and trusted. The bytes read through the checked handle, and its
    /// identity so the original can be removed from the quarantine later.
    Carry { bytes: Vec<u8>, id: win32::LinkInfo },
}

fn os_child_owner_trusted(h: &OwnedHandle) -> Result<bool, AclError> {
    win32::read_security(h)
        .map(|s| owner_trusted(&s))
        .map_err(|e| os("check restore record", &e))
}

/// Opens `dir\restore.json` without following a reparse point and checks
/// its provenance on that handle: plain file, one link, at most
/// [`RESTORE_MAX_BYTES`], and `owner_ok`. Reads the bytes through the same
/// handle. Content is not checked here: that is the reader's job (Task 12).
fn read_restore(
    dir: &Path,
    owner_ok: &dyn Fn(&OwnedHandle) -> Result<bool, AclError>,
) -> Result<RestoreSource, AclError> {
    use std::io::Read;
    let h = match win32::open_no_follow(
        &dir.join(RESTORE_NAME),
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
    ) {
        Ok(h) => h,
        Err(e) if matches!(e.raw_os_error(), Some(FILE_NOT_FOUND | PATH_NOT_FOUND)) => {
            return Ok(RestoreSource::Absent);
        }
        Err(e) => return Err(os("open restore record", &e)),
    };
    let id = win32::link_info(&h).map_err(|e| os("check restore record", &e))?;
    if kind_of(id.attributes) != ChildKind::File
        || id.links != 1
        || id.size > RESTORE_MAX_BYTES
        || !owner_ok(&h)?
    {
        return Ok(RestoreSource::Dropped);
    }
    let mut bytes = Vec::new();
    std::fs::File::from(h)
        .take(RESTORE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| os("read restore record", &e))?;
    // The size can change between the check and the read.
    if bytes.len() as u64 > RESTORE_MAX_BYTES {
        return Ok(RestoreSource::Dropped);
    }
    Ok(RestoreSource::Carry { bytes, id })
}

/// Reads a file back without following a reparse point, at most one byte
/// more than [`RESTORE_MAX_BYTES`].
fn os_read_back(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let h = win32::open_no_follow(path, FILE_READ_DATA | FILE_READ_ATTRIBUTES)?;
    let mut bytes = Vec::new();
    std::fs::File::from(h)
        .take(RESTORE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Writes `bytes` as `dir\restore.json` with `create_new` and the same
/// no-follow flags as the drift store, syncs it, and checks `read_back`
/// returns the same bytes. Removes the file it created if anything fails.
fn write_restore(
    dir: &Path,
    bytes: &[u8],
    read_back: &dyn Fn(&Path) -> io::Result<Vec<u8>>,
) -> Result<(), AclError> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    /// `FILE_FLAG_OPEN_REPARSE_POINT` and `SECURITY_IDENTIFICATION`, as in
    /// the service's `safe_open`.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    let p = dir.join(RESTORE_NAME);
    let fail = |detail: String| AclError::RestoreCarryFailed { detail };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(&p)
        // Not created, so nothing of ours to remove.
        .map_err(|e| fail(e.to_string()))?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    let checked = written
        .and_then(|()| read_back(&p))
        .map_err(|e| e.to_string());
    match checked {
        Ok(back) if back == bytes => Ok(()),
        Ok(_) => {
            let _ = std::fs::remove_file(&p);
            Err(fail("read-back differs".into()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&p);
            Err(fail(e))
        }
    }
}

/// Deletes the carried original from the quarantine, best effort, only if
/// the name there still holds the very file that was read.
fn remove_carried_original(quarantine: &Path, id: &win32::LinkInfo) {
    let Ok(h) = win32::open_no_follow(
        &quarantine.join(RESTORE_NAME),
        DELETE | FILE_READ_ATTRIBUTES,
    ) else {
        return;
    };
    if win32::link_info(&h).is_ok_and(|now| now.same_file(id)) {
        let _ = win32::delete_by_handle(&h);
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

/// Creates a fresh directory at `path` with the secure descriptor, secures
/// it, and returns its handle. Refuses if anything already took the name
/// (error 183). If securing fails it is deleted through its handle. Only
/// when the open itself fails is it removed by path: it was created a moment
/// ago with the secure DACL, so nobody unprivileged can have replaced it.
fn create_fresh(path: &Path) -> Result<OwnedHandle, AclError> {
    require_trusted_token_owner()?;
    win32::create_secure_dir(path).map_err(|e| os("create", &e))?;
    let h = match win32::open_no_follow(path, DIR_RIGHTS) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_dir(path);
            return Err(os("open", &e));
        }
    };
    if let Err(e) = secure_fresh(&h, path) {
        let _ = win32::delete_by_handle(&h);
        return Err(e);
    }
    Ok(h)
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

/// Every name the service writes in the state directory, by owner:
/// - `drift.txt`, `drift.txt.tmp`: drift store (Task 10). Not carried on
///   quarantine. The drift is only a starting hint and is relearnt.
/// - `restore.json`, `restore.json.tmp`: w32time takeover record (Task 12).
///   Only `restore.json` is carried (R80). A `.tmp` is never carried.
/// - `status.json`, `status.json.tmp`: status output (later task). Not
///   carried. It is regenerated.
pub const KNOWN_CHILDREN: [&str; 6] = [
    "drift.txt",
    "drift.txt.tmp",
    "restore.json",
    "restore.json.tmp",
    "status.json",
    "status.json.tmp",
];

/// The one file carried into a fresh directory.
const RESTORE_NAME: &str = "restore.json";

/// Deletes the known files except `restore.json` from a directory before it
/// goes to quarantine. `restore.json` stays: its bytes were read already and
/// are carried, or it was dropped and stays in the quarantine.
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
        if entry.name == RESTORE_NAME {
            continue;
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
    // Something created during the clean-up also refuses. Only the restore
    // record may remain.
    if win32::list_dir(dir)
        .map_err(|e| os("list", &e))?
        .iter()
        .any(|e| e.name != RESTORE_NAME)
    {
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
            AclError::RestoreCarryFailed {
                detail: "read-back differs".into(),
            },
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
        assert_eq!(
            secure_final(&dir).unwrap().restore_record,
            RestoreRecord::Absent
        );
        // The second call takes the already-exists path.
        assert_eq!(
            secure_final(&dir).unwrap().restore_record,
            RestoreRecord::Absent
        );
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
        std::fs::write(dir.join("restore.json"), b"{\"r\":1}").unwrap();
        let before = win32::link_info(&listing_handle(&dir)).unwrap();
        assert_eq!(
            secure_final(&dir).unwrap().restore_record,
            RestoreRecord::Kept
        );
        assert_eq!(
            std::fs::read(dir.join("restore.json")).unwrap(),
            b"{\"r\":1}"
        );
        std::fs::remove_file(dir.join("restore.json")).unwrap();
        let h = win32::open_no_follow(&dir, READ_CONTROL | FILE_READ_ATTRIBUTES).unwrap();
        let after = win32::link_info(&h).unwrap();
        assert!(!before.same_file(&after), "the old object was kept");
        assert!(dacl_is_secure(&win32::read_security(&h).unwrap()));
        assert!(!dir.join("drift.txt").exists());
        drop(h);
        // A known file written by an Administrators token is kept.
        std::fs::write(dir.join("drift.txt"), b"2.0").unwrap();
        let kept = win32::link_info(&listing_handle(&dir)).unwrap();
        assert_eq!(
            secure_final(&dir).unwrap().restore_record,
            RestoreRecord::Absent
        );
        let now = win32::link_info(&listing_handle(&dir)).unwrap();
        assert!(kept.same_file(&now), "fast path should keep the directory");
        assert!(dir.join("drift.txt").exists());
        // An unknown name refuses.
        std::fs::write(dir.join("other"), b"x").unwrap();
        assert_eq!(secure_final(&dir), Err(AclError::UnexpectedChild));
        // A user-owned known file cannot be planted from an elevated test
        // without changing an owner, so that row is covered by `decide`.
        assert_eq!(quarantine_leftovers(&s.0), Vec::<String>::new());
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
            restore: false,
            kind,
            links,
            owner_trusted,
        }
    }

    fn restore_obs(kind: ChildKind, links: u32, owner_trusted: bool) -> ChildObs {
        ChildObs {
            restore: true,
            ..obs(true, kind, links, owner_trusted)
        }
    }

    #[test]
    fn decision_table_for_the_restore_record() {
        use ChildKind::{File, Link};
        let drift = obs(true, File, 1, true);
        let rows: Vec<(bool, Vec<ChildObs>, Decision)> = vec![
            // Trusted restore record: kept like any known file.
            (true, vec![restore_obs(File, 1, true)], Decision::Keep),
            (
                true,
                vec![drift, restore_obs(File, 1, true)],
                Decision::Keep,
            ),
            // User-owned: forces the quarantine path, where it is dropped.
            (
                true,
                vec![restore_obs(File, 1, false)],
                Decision::Quarantine,
            ),
            (
                false,
                vec![restore_obs(File, 1, false)],
                Decision::Quarantine,
            ),
            // Wrong DACL with a trusted record: quarantine, record carried.
            (
                false,
                vec![restore_obs(File, 1, true)],
                Decision::Quarantine,
            ),
            // Hard-linked or a link: refuse, as for every known name.
            (true, vec![restore_obs(File, 2, true)], Decision::Refuse),
            (true, vec![restore_obs(Link, 0, true)], Decision::Refuse),
            // Absent: only the other children count.
            (true, vec![drift], Decision::Keep),
        ];
        // Size is not an input here. A trusted record of any size in a
        // secure directory is kept: only trusted principals can write there,
        // and content checks belong to the reader. Size limits the carry
        // only (`read_restore_drops_an_oversized_record`).
        for (dacl, children, want) in rows {
            assert_eq!(decide(dacl, &children), want, "{dacl} {children:?}");
        }
    }

    // The signature must match the owner predicate, so the `Result` stays.
    #[allow(clippy::unnecessary_wraps)]
    fn yes(_: &OwnedHandle) -> Result<bool, AclError> {
        Ok(true)
    }

    // The signature must match the owner predicate, so the `Result` stays.
    #[allow(clippy::unnecessary_wraps)]
    fn no(_: &OwnedHandle) -> Result<bool, AclError> {
        Ok(false)
    }

    #[test]
    fn read_restore_absent() {
        let s = Scratch::new("rrabsent");
        let dir = state_dir(&s);
        assert!(matches!(
            read_restore(&dir, &yes).unwrap(),
            RestoreSource::Absent
        ));
    }

    #[test]
    fn read_restore_carries_a_trusted_record() {
        let s = Scratch::new("rrtrusted");
        let dir = state_dir(&s);
        std::fs::write(dir.join("restore.json"), b"{\"start\":\"auto\"}").unwrap();
        match read_restore(&dir, &yes).unwrap() {
            RestoreSource::Carry { bytes, id } => {
                assert_eq!(bytes, b"{\"start\":\"auto\"}");
                assert_eq!(id.links, 1);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn read_restore_drops_an_untrusted_record_and_leaves_it() {
        let s = Scratch::new("rruntrusted");
        let dir = state_dir(&s);
        std::fs::write(dir.join("restore.json"), b"x").unwrap();
        assert!(matches!(
            read_restore(&dir, &no).unwrap(),
            RestoreSource::Dropped
        ));
        assert!(dir.join("restore.json").exists());
        // With the real owner check a user-owned record drops too.
        if !elevated() {
            assert!(matches!(
                read_restore(&dir, &os_child_owner_trusted).unwrap(),
                RestoreSource::Dropped
            ));
        }
    }

    #[test]
    fn read_restore_drops_an_oversized_record() {
        let s = Scratch::new("rrbig");
        let dir = state_dir(&s);
        std::fs::write(dir.join("restore.json"), vec![b'a'; 4097]).unwrap();
        assert!(matches!(
            read_restore(&dir, &yes).unwrap(),
            RestoreSource::Dropped
        ));
        std::fs::write(dir.join("restore.json"), vec![b'a'; 4096]).unwrap();
        assert!(matches!(
            read_restore(&dir, &yes).unwrap(),
            RestoreSource::Carry { .. }
        ));
    }

    #[test]
    fn read_restore_drops_a_hard_linked_record() {
        let s = Scratch::new("rrhard");
        let dir = state_dir(&s);
        let outside = s.0.join("outside.json");
        std::fs::write(&outside, b"x").unwrap();
        std::fs::hard_link(&outside, dir.join("restore.json")).unwrap();
        assert!(matches!(
            read_restore(&dir, &yes).unwrap(),
            RestoreSource::Dropped
        ));
    }

    #[test]
    fn write_restore_writes_and_verifies() {
        let s = Scratch::new("wrok");
        let dir = state_dir(&s);
        write_restore(&dir, b"{}", &os_read_back).unwrap();
        assert_eq!(std::fs::read(dir.join("restore.json")).unwrap(), b"{}");
    }

    #[test]
    fn write_restore_read_back_failure_removes_the_file() {
        let s = Scratch::new("wrbad");
        let dir = state_dir(&s);
        let differs = |_: &Path| Ok(b"tampered".to_vec());
        assert!(matches!(
            write_restore(&dir, b"{}", &differs),
            Err(AclError::RestoreCarryFailed { .. })
        ));
        assert!(!dir.join("restore.json").exists());
        let fails = |_: &Path| -> io::Result<Vec<u8>> { Err(io::Error::from_raw_os_error(5)) };
        assert!(write_restore(&dir, b"{}", &fails).is_err());
        assert!(!dir.join("restore.json").exists());
    }

    #[test]
    fn write_restore_never_overwrites() {
        let s = Scratch::new("wrexists");
        let dir = state_dir(&s);
        std::fs::write(dir.join("restore.json"), b"old").unwrap();
        assert!(matches!(
            write_restore(&dir, b"new", &os_read_back),
            Err(AclError::RestoreCarryFailed { .. })
        ));
        assert_eq!(std::fs::read(dir.join("restore.json")).unwrap(), b"old");
    }

    #[test]
    fn clean_keeps_the_restore_record_and_removes_the_rest() {
        let s = Scratch::new("cleanrestore");
        let dir = state_dir(&s);
        for n in KNOWN_CHILDREN {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        let h = listing_handle(&dir);
        assert_eq!(clean_known_children(&h, &dir), Ok(()));
        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["restore.json".to_string()]);
    }

    #[test]
    fn all_six_known_names_are_recognised() {
        let s = Scratch::new("knownsix");
        let dir = state_dir(&s);
        for n in KNOWN_CHILDREN {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        let c = inspect(&dir);
        assert_eq!(c.len(), 6);
        assert!(c.iter().all(|o| o.known && o.kind == ChildKind::File));
        assert_eq!(c.iter().filter(|o| o.restore).count(), 1);
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
        std::fs::write(dir.join("restore.json"), b"{\"keep\":1}").unwrap();
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
        // The restore record is never deleted by the clean-up and comes back
        // with the old directory.
        assert_eq!(
            std::fs::read(dir.join("restore.json")).unwrap(),
            b"{\"keep\":1}"
        );
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
    fn console_and_superscript_device_names_are_refused() {
        for name in [
            "CONIN$",
            "conout$",
            "CONOUT$.txt",
            "COM\u{b9}",
            "com\u{b2}.log",
            "COM\u{b3}",
            "LPT\u{b9}",
            "lpt\u{b3} .x",
        ] {
            let p = PathBuf::from(r"C:\ProgramData").join(name);
            assert_eq!(ancestors(&p), Err(AclError::ReservedName), "{name}");
        }
        // Only superscript one to three are device digits.
        for name in ["COM\u{2074}", "LPT\u{b9}\u{b9}", "CONIN", "CONOUT$X"] {
            let p = PathBuf::from(r"C:\ProgramData").join(name);
            assert!(ancestors(&p).is_ok(), "{name}");
        }
    }

    #[test]
    fn identity_check_refuses_the_same_object_turned_into_a_junction() {
        // The I-2 case: a handle opened earlier sets a reparse point on the
        // very object that was secured. File ID unchanged, reparse bit set.
        let s = Scratch::new("selfjunction");
        let dir = state_dir(&s);
        let target = s.0.join("target");
        std::fs::create_dir(&target).unwrap();
        let h = win32::open_no_follow(&dir, FILE_WRITE_DATA | FILE_READ_ATTRIBUTES).unwrap();
        assert_eq!(same_object(&h, &dir), Ok(()));
        win32::set_junction(&h, &target).unwrap();
        assert_eq!(same_object(&h, &dir), Err(AclError::Link));
    }

    /// `FILE_WRITE_DATA`, for the junction test.
    const FILE_WRITE_DATA: u32 = 0x0002;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Create {
        /// A plain directory stands in for the protected one.
        Plain,
        /// The create fails, the name stays free.
        Fail,
        /// Someone squats the name in the window: a directory appears and
        /// the create fails with 183.
        Squat,
    }

    /// Stands in for the steps that need elevation. `create_fresh` replaces
    /// `CreateDirectoryW` with the secure descriptor plus the fresh checks
    /// by a plain `create_dir` and a handle. `write_restore` is the real
    /// function unless `write_fails`. `read_back` is the real one unless
    /// `read_back_differs`. The rename back and the quarantine delete are
    /// real, and `deleted` records whether the delete ran.
    struct FakeQ {
        owner_ok: bool,
        create: Create,
        write_fails: bool,
        read_back_differs: bool,
        deleted: std::cell::Cell<bool>,
    }

    impl FakeQ {
        fn new(create: Create) -> Self {
            Self {
                owner_ok: true,
                create,
                write_fails: false,
                read_back_differs: false,
                deleted: std::cell::Cell::new(false),
            }
        }
    }

    impl QuarantineOps for FakeQ {
        fn restore_owner_ok(&self, _: &OwnedHandle) -> Result<bool, AclError> {
            Ok(self.owner_ok)
        }

        fn create_fresh(&self, path: &Path) -> Result<OwnedHandle, AclError> {
            match self.create {
                Create::Plain => {
                    std::fs::create_dir(path).map_err(|e| os("create", &e))?;
                    win32::open_no_follow(path, DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)
                        .map_err(|e| os("open", &e))
                }
                Create::Fail => Err(os("create", &io::Error::from_raw_os_error(5))),
                Create::Squat => {
                    std::fs::create_dir(path).unwrap();
                    Err(os("create", &io::Error::from_raw_os_error(183)))
                }
            }
        }

        fn write_restore(&self, dir: &Path, bytes: &[u8]) -> Result<(), AclError> {
            if self.write_fails {
                return Err(AclError::RestoreCarryFailed {
                    detail: "injected write failure".into(),
                });
            }
            write_restore(dir, bytes, &|p| self.read_back(p))
        }

        fn read_back(&self, path: &Path) -> io::Result<Vec<u8>> {
            if self.read_back_differs {
                Ok(b"tampered".to_vec())
            } else {
                os_read_back(path)
            }
        }

        fn rename_back(&self, h: &OwnedHandle, path: &Path) -> io::Result<()> {
            win32::rename_by_handle(h, path)
        }

        fn delete_quarantine(&self, h: &OwnedHandle) {
            self.deleted.set(true);
            let _ = win32::delete_by_handle(h);
        }
    }

    const RECORD: &[u8] = b"{\"w32time\":\"auto\"}";

    /// A weak state directory with a drift file and, if asked, a restore
    /// record. Runs the quarantine path and returns the result, the old
    /// directory's identity and the quarantine names left in the scratch.
    fn run_quarantine(
        s: &Scratch,
        ops: &FakeQ,
        with_record: bool,
    ) -> (Result<RestoreRecord, AclError>, win32::LinkInfo, PathBuf) {
        let dir = state_dir(s);
        std::fs::write(dir.join("drift.txt"), b"1.0").unwrap();
        if with_record {
            std::fs::write(dir.join("restore.json"), RECORD).unwrap();
        }
        let h = rename_handle(&dir);
        let before = win32::link_info(&h).unwrap();
        let r = quarantine_with(ops, &h, &dir);
        drop(h);
        (r, before, dir)
    }

    /// The old directory is back under its name, cleaned of the drift file,
    /// with the restore record byte for byte, and no quarantine is left.
    fn assert_rolled_back(s: &Scratch, dir: &Path, before: &win32::LinkInfo) {
        let back = win32::link_info(&listing_handle(dir)).unwrap();
        assert!(before.same_file(&back), "old directory not renamed back");
        assert_eq!(std::fs::read(dir.join("restore.json")).unwrap(), RECORD);
        assert!(!dir.join("drift.txt").exists());
        assert_eq!(quarantine_leftovers(&s.0), Vec::<String>::new());
    }

    #[test]
    fn rollback_after_a_read_back_mismatch() {
        let s = Scratch::new("rbreadback");
        let ops = FakeQ {
            read_back_differs: true,
            ..FakeQ::new(Create::Plain)
        };
        let (r, before, dir) = run_quarantine(&s, &ops, true);
        assert!(
            matches!(r, Err(AclError::RestoreCarryFailed { .. })),
            "{r:?}"
        );
        assert_rolled_back(&s, &dir, &before);
        assert!(!ops.deleted.get());
    }

    #[test]
    fn rollback_after_a_write_failure() {
        let s = Scratch::new("rbwrite");
        let ops = FakeQ {
            write_fails: true,
            ..FakeQ::new(Create::Plain)
        };
        let (r, before, dir) = run_quarantine(&s, &ops, true);
        assert!(
            matches!(r, Err(AclError::RestoreCarryFailed { .. })),
            "{r:?}"
        );
        assert_rolled_back(&s, &dir, &before);
        assert!(!ops.deleted.get());
    }

    #[test]
    fn rollback_after_a_create_failure() {
        let s = Scratch::new("rbcreate");
        let ops = FakeQ::new(Create::Fail);
        let (r, before, dir) = run_quarantine(&s, &ops, true);
        assert!(matches!(r, Err(AclError::Os { op: "create", .. })), "{r:?}");
        assert_rolled_back(&s, &dir, &before);
        assert!(!ops.deleted.get());
    }

    #[test]
    fn squat_ends_in_rollback_failed_and_leaves_the_quarantine_untouched() {
        let s = Scratch::new("rbsquat");
        let ops = FakeQ::new(Create::Squat);
        let (r, before, dir) = run_quarantine(&s, &ops, true);
        let Err(AclError::RollbackFailed { cause, rollback }) = &r else {
            panic!("{r:?}");
        };
        // Both errors are kept: the squatted create (183) and the failed
        // rename back.
        assert!(cause.contains("183"), "{cause}");
        assert!(rollback.contains("os error"), "{rollback}");
        let text = r.clone().unwrap_err().to_string();
        assert!(text.contains(".old-") && !text.contains('\\'), "{text}");
        // The squatter holds the name. The old directory is in quarantine,
        // untouched, with the record byte for byte. No delete ran.
        assert!(!before.same_file(&win32::link_info(&listing_handle(&dir)).unwrap()));
        let left = quarantine_leftovers(&s.0);
        assert_eq!(left.len(), 1);
        let q = s.0.join(&left[0]);
        assert!(before.same_file(&win32::link_info(&listing_handle(&q)).unwrap()));
        assert_eq!(std::fs::read(q.join("restore.json")).unwrap(), RECORD);
        assert!(!ops.deleted.get(), "the quarantine delete must not run");
    }

    #[test]
    fn success_carries_the_record_and_deletes_the_quarantine() {
        let s = Scratch::new("okcarry");
        let ops = FakeQ::new(Create::Plain);
        let (r, before, dir) = run_quarantine(&s, &ops, true);
        assert_eq!(r, Ok(RestoreRecord::Kept));
        let now = win32::link_info(&listing_handle(&dir)).unwrap();
        assert!(
            !before.same_file(&now),
            "the fresh directory is a new object"
        );
        assert_eq!(std::fs::read(dir.join("restore.json")).unwrap(), RECORD);
        assert!(!dir.join("drift.txt").exists());
        assert!(ops.deleted.get());
        assert_eq!(quarantine_leftovers(&s.0), Vec::<String>::new());
    }

    #[test]
    fn success_without_a_record_deletes_the_quarantine() {
        let s = Scratch::new("okabsent");
        let ops = FakeQ::new(Create::Plain);
        let (r, _, dir) = run_quarantine(&s, &ops, false);
        assert_eq!(r, Ok(RestoreRecord::Absent));
        assert!(ops.deleted.get());
        assert!(!dir.join("restore.json").exists());
        assert_eq!(quarantine_leftovers(&s.0), Vec::<String>::new());
    }

    #[test]
    fn a_dropped_record_keeps_the_quarantine_and_its_record() {
        let s = Scratch::new("okdropped");
        let ops = FakeQ {
            owner_ok: false,
            ..FakeQ::new(Create::Plain)
        };
        let (r, _, dir) = run_quarantine(&s, &ops, true);
        assert_eq!(r, Ok(RestoreRecord::Dropped));
        assert!(!ops.deleted.get(), "the quarantine delete must not run");
        assert!(!dir.join("restore.json").exists(), "dropped, not carried");
        let left = quarantine_leftovers(&s.0);
        assert_eq!(left.len(), 1);
        assert_eq!(
            std::fs::read(s.0.join(&left[0]).join("restore.json")).unwrap(),
            RECORD
        );
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
