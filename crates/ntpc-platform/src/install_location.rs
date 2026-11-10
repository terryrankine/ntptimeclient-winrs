//! Is the installed exe somewhere only administrators can change?
//!
//! The service runs the exe as `LocalSystem` from where it is installed.
//! Anyone who can write the exe, its folder, or rename a parent folder can
//! make the next start run their code as `LocalSystem`. Install refuses
//! such a location. The Task 15 wrapper runs the same check
//! (`Test-LocationOrFail`). This is the Rust copy, for defence in depth and
//! for an install run without the wrapper.
//!
//! Rules (the same masks as `packaging/preview-common.ps1`):
//! - The exe and its folder: owner SYSTEM, Administrators or
//!   `TrustedInstaller`. No allow ACE for anyone else with a write, delete,
//!   permission or owner right ([`WRITE_MASK`]).
//! - Each parent folder up to the drive root: the same owner rule, and no
//!   allow ACE for anyone else with a right that renames or removes a child
//!   or changes permissions ([`ANCESTOR_MASK`]). A root that lets users
//!   create folders (`C:\`) is fine.
//! - Inherit-only ACEs do not apply to the object itself and are skipped.
//!   Deny ACEs are skipped (they only take rights away).
//! - A null DACL grants everyone everything: refused.
//! - An ACE type this code does not read (object or callback ACEs): refused
//!   unless inherit-only. Fail closed.
//! - No reparse point anywhere on the path, and the drive must be fixed.

#[cfg(windows)]
use std::path::Path;

/// Rights on the exe or its folder that let someone change what runs:
/// write data, append, write extended attributes, delete child, write
/// attributes, delete, write DAC, write owner, generic all, generic write.
pub const WRITE_MASK: u32 =
    0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

/// Rights on a parent folder that let someone rename or remove the child
/// or change permissions: delete child, delete, write DAC, write owner,
/// generic all, generic write.
pub const ANCESTOR_MASK: u32 = 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

/// The last reason of a refused location: what to do. Generic, no path.
pub const ADVICE: &str = "To fix it, extract the files from an elevated prompt into a new folder \
     under Program Files, or take ownership with takeown /a and reset the permissions with \
     icacls, then run again.";

/// Drops repeated reasons, keeps the order, and ends with [`ADVICE`].
#[must_use]
pub fn finish(reasons: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in reasons {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    if !out.is_empty() {
        out.push(ADVICE.to_owned());
    }
    out
}

/// The reasons for a file in the exe folder, with its bare name in place
/// of the role, so the admin knows which one. Never a path.
#[must_use]
pub fn name_folder_file(name: &str, reasons: Vec<String>) -> Vec<String> {
    let label = Role::FolderFile.label();
    reasons
        .into_iter()
        .map(|r| r.replacen(label, &format!("the file {name} in the exe folder"), 1))
        .collect()
}

/// `INHERIT_ONLY_ACE`.
const INHERIT_ONLY: u8 = 0x08;
/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE`.
const ALLOWED: u8 = 0;
const DENIED: u8 = 1;

/// Who an ACE or owner names, as far as this check cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    /// SYSTEM, Administrators or `TrustedInstaller`.
    Trusted,
    /// Anyone else, or a SID that could not be read.
    Other,
}

/// One ACE, reduced to what the judge needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ace {
    /// `ACE_HEADER.AceType`.
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags`.
    pub flags: u8,
    /// The access mask.
    pub mask: u32,
    /// Who it is for.
    pub who: Who,
}

/// Owner and DACL of one path on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The owner, `None` if there is none.
    pub owner: Option<Who>,
    /// The ACEs, `None` for a null DACL.
    pub dacl: Option<Vec<Ace>>,
    /// The object is a reparse point.
    pub reparse: bool,
    /// Hard links. A file with more than one can be changed through
    /// another name in a folder nobody checked (M9, R105).
    pub links: u32,
}

/// Which role the object plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The exe file.
    Exe,
    /// The folder that holds the exe.
    Folder,
    /// A parent folder above that.
    Ancestor,
    /// The config file (I1). Read as `LocalSystem` at every start, so it
    /// decides the time sources and `allow_panic_step`.
    Config,
    /// The folder of a config file named with `--config`.
    ConfigFolder,
    /// Any other file in the exe folder. A DLL there could be loaded by
    /// the exe, and the scripts there run elevated.
    FolderFile,
}

impl Role {
    const fn mask(self) -> u32 {
        match self {
            Role::Exe | Role::Folder | Role::Config | Role::ConfigFolder | Role::FolderFile => {
                WRITE_MASK
            }
            Role::Ancestor => ANCESTOR_MASK,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Role::Exe => "the exe",
            Role::Folder => "the exe folder",
            Role::Ancestor => "a parent folder",
            Role::Config => "the config file",
            Role::ConfigFolder => "the config folder",
            Role::FolderFile => "a file in the exe folder",
        }
    }

    const fn is_file(self) -> bool {
        matches!(self, Role::Exe | Role::Config | Role::FolderFile)
    }
}

/// The reasons one object fails. Empty means it passed. The text names the
/// role, never the path, so it can go to a log.
#[must_use]
pub fn judge(role: Role, f: &Facts) -> Vec<String> {
    let mut out = Vec::new();
    let what = role.label();
    if f.reparse {
        out.push(format!("{what} is a link or reparse point"));
    }
    if role.is_file() && f.links > 1 {
        out.push(format!("{what} has more than one hard link"));
    }
    if f.owner != Some(Who::Trusted) {
        out.push(format!(
            "{what} is not owned by SYSTEM, Administrators or TrustedInstaller"
        ));
    }
    let Some(dacl) = &f.dacl else {
        out.push(format!("{what} has no DACL, so everyone has full access"));
        return out;
    };
    for a in dacl {
        if a.flags & INHERIT_ONLY != 0 || a.ace_type == DENIED {
            continue;
        }
        if a.ace_type != ALLOWED {
            out.push(format!(
                "{what} has an access entry of type {} that this check cannot read",
                a.ace_type
            ));
            continue;
        }
        if a.who == Who::Other && a.mask & role.mask() != 0 {
            out.push(format!(
                "{what} lets an account other than SYSTEM or Administrators change it (rights {:#x})",
                a.mask & role.mask()
            ));
        }
    }
    out
}

/// Reads the facts of one path without following a link.
#[cfg(windows)]
fn read_facts(p: &Path) -> std::io::Result<Facts> {
    use crate::win32;
    /// `READ_CONTROL | FILE_READ_ATTRIBUTES`: owner, DACL, attributes and
    /// the link count.
    const ACCESS: u32 = 0x0002_0000 | 0x80;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const ATTR_REPARSE: u32 = 0x400;
    let h = win32::open_no_follow(p, ACCESS)?;
    let tag = win32::attribute_tag(&h)?;
    let link = win32::link_info(&h)?;
    let sec = win32::read_security(&h)?;
    let who = |pr: win32::Principal| match pr {
        win32::Principal::System
        | win32::Principal::Administrators
        | win32::Principal::TrustedInstaller => Who::Trusted,
        win32::Principal::Other => Who::Other,
    };
    Ok(Facts {
        owner: sec.owner.map(who),
        dacl: sec.dacl.map(|v| {
            v.into_iter()
                .map(|a| Ace {
                    ace_type: a.ace_type,
                    flags: a.flags,
                    mask: a.mask,
                    who: who(a.principal),
                })
                .collect()
        }),
        reparse: tag.attributes & ATTR_REPARSE != 0,
        links: link.links,
    })
}

#[cfg(windows)]
fn judge_path(role: Role, p: &Path, out: &mut Vec<String>) {
    match read_facts(p) {
        Ok(f) => out.extend(judge(role, &f)),
        Err(e) => out.push(format!(
            "cannot read the permissions of {}: OS error {}",
            role.label(),
            e.raw_os_error().unwrap_or(-1)
        )),
    }
}

/// The file, its folder and every parent up to the drive root.
#[cfg(windows)]
fn check_chain(file: &Path, file_role: Role, folder_role: Role) -> Vec<String> {
    /// `DRIVE_FIXED`.
    const DRIVE_FIXED: u32 = 3;
    let mut out = Vec::new();
    if !file.is_absolute() {
        out.push(format!("the path of {} is not absolute", file_role.label()));
        return out;
    }
    let mut steps: Vec<(Role, &Path)> = vec![(file_role, file)];
    let mut cur = file.parent();
    let mut role = folder_role;
    while let Some(p) = cur {
        steps.push((role, p));
        role = Role::Ancestor;
        cur = p.parent();
    }
    if let Some((_, root)) = steps.last()
        && crate::win32::drive_type(root) != DRIVE_FIXED
    {
        out.push(format!(
            "{} is not on a fixed local drive",
            file_role.label()
        ));
    }
    for (role, p) in steps {
        judge_path(role, p, &mut out);
    }
    out
}

/// Checks the exe at `exe` (an absolute, already resolved path), its folder,
/// every parent up to the drive root, and every other file directly in the
/// exe folder (the config file, DLLs, the scripts). Read only. Empty means
/// safe. A path that cannot be read counts as unsafe.
#[cfg(windows)]
#[must_use]
pub fn check_exe_location(exe: &Path) -> Vec<String> {
    let mut out = check_chain(exe, Role::Exe, Role::Folder);
    let Some(folder) = exe.parent() else {
        return out;
    };
    match std::fs::read_dir(folder) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    out.push("cannot list the exe folder".to_owned());
                    continue;
                };
                let path = entry.path();
                if path.file_name() == exe.file_name() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                // m1: no sub folder at all. The release zip has none, and a
                // folder named `<exe>.local` could redirect DLL loads.
                match entry.file_type() {
                    Ok(t) if t.is_dir() && !t.is_symlink() => out.push(format!(
                        "the exe folder holds a sub folder, {name}. Remove it: a folder there \
                         can change which DLLs load"
                    )),
                    _ => {
                        let mut one = Vec::new();
                        judge_path(Role::FolderFile, &path, &mut one);
                        out.extend(name_folder_file(&name, one));
                    }
                }
            }
        }
        Err(e) => out.push(format!(
            "cannot list the exe folder: OS error {}",
            e.raw_os_error().unwrap_or(-1)
        )),
    }
    finish(out)
}

/// Checks a config file, its folder and every parent (I1). A missing file
/// passes: it means the defaults. Read only.
#[cfg(windows)]
#[must_use]
pub fn check_config_location(config: &Path) -> Vec<String> {
    match std::fs::symlink_metadata(config) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        _ => finish(check_chain(config, Role::Config, Role::ConfigFolder)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(ace_type: u8, flags: u8, mask: u32, who: Who) -> Ace {
        Ace {
            ace_type,
            flags,
            mask,
            who,
        }
    }

    fn facts(aces: Vec<Ace>) -> Facts {
        Facts {
            owner: Some(Who::Trusted),
            dacl: Some(aces),
            reparse: false,
            links: 1,
        }
    }

    /// Roughly what `C:\Program Files` grants: full to the trusted ones,
    /// read and execute to Users, an inherit-only creator owner entry.
    fn program_files_like() -> Vec<Ace> {
        vec![
            ace(ALLOWED, 0, 0x1F_01FF, Who::Trusted),
            ace(ALLOWED, 0, 0x0012_00A9, Who::Other),
            ace(ALLOWED, INHERIT_ONLY | 0x3, 0x1000_0000, Who::Other),
        ]
    }

    #[test]
    fn admin_only_folder_passes_every_role() {
        for r in [Role::Exe, Role::Folder, Role::Ancestor] {
            assert!(judge(r, &facts(program_files_like())).is_empty(), "{r:?}");
        }
    }

    #[test]
    fn users_write_fails_the_exe_and_folder() {
        for bit in [
            0x2,
            0x4,
            0x10,
            0x40,
            0x100,
            0x1_0000,
            0x4_0000,
            0x8_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            let f = facts(vec![ace(ALLOWED, 0, bit, Who::Other)]);
            assert_eq!(judge(Role::Exe, &f).len(), 1, "{bit:#x}");
            assert_eq!(judge(Role::Folder, &f).len(), 1, "{bit:#x}");
        }
    }

    #[test]
    fn root_that_lets_users_add_folders_is_fine_as_a_parent() {
        // C:\ grants Authenticated Users "append data" (create folders).
        let f = facts(vec![ace(ALLOWED, 0, 0x4, Who::Other)]);
        assert_eq!(judge(Role::Ancestor, &f), Vec::<String>::new());
        // But not as the exe's own folder.
        assert_eq!(judge(Role::Folder, &f).len(), 1);
    }

    #[test]
    fn parent_delete_child_or_permission_rights_fail() {
        for bit in [0x40, 0x1_0000, 0x4_0000, 0x8_0000, 0x1000_0000, 0x4000_0000] {
            let f = facts(vec![ace(ALLOWED, 0, bit, Who::Other)]);
            assert_eq!(judge(Role::Ancestor, &f).len(), 1, "{bit:#x}");
        }
    }

    #[test]
    fn untrusted_or_missing_owner_fails() {
        let mut f = facts(vec![]);
        f.owner = Some(Who::Other);
        assert_eq!(judge(Role::Folder, &f).len(), 1);
        f.owner = None;
        assert_eq!(judge(Role::Folder, &f).len(), 1);
    }

    #[test]
    fn null_dacl_fails() {
        let f = Facts {
            owner: Some(Who::Trusted),
            dacl: None,
            reparse: false,
            links: 1,
        };
        assert_eq!(judge(Role::Exe, &f).len(), 1);
    }

    #[test]
    fn deny_and_inherit_only_entries_are_skipped() {
        let f = facts(vec![
            ace(DENIED, 0, 0xFFFF_FFFF, Who::Other),
            ace(ALLOWED, INHERIT_ONLY, 0x4000_0000, Who::Other),
        ]);
        assert_eq!(judge(Role::Exe, &f), Vec::<String>::new());
    }

    #[test]
    fn unknown_ace_types_fail_closed() {
        // 9 is ACCESS_ALLOWED_CALLBACK_ACE_TYPE: not read, so refused.
        let f = facts(vec![ace(9, 0, 0, Who::Other)]);
        assert_eq!(judge(Role::Exe, &f).len(), 1);
        // Inherit-only, it does not apply here.
        let f = facts(vec![ace(9, INHERIT_ONLY, 0, Who::Other)]);
        assert_eq!(judge(Role::Exe, &f), Vec::<String>::new());
    }

    #[test]
    fn reparse_point_fails() {
        let mut f = facts(vec![]);
        f.reparse = true;
        assert_eq!(judge(Role::Ancestor, &f).len(), 1);
    }

    #[test]
    fn reasons_name_no_path() {
        let f = Facts {
            owner: Some(Who::Other),
            dacl: Some(vec![
                ace(ALLOWED, 0, 0x2, Who::Other),
                ace(9, 0, 0, Who::Other),
            ]),
            reparse: true,
            links: 3,
        };
        for r in judge(Role::Folder, &f) {
            assert!(!r.contains('\\') && !r.contains(':'), "{r}");
        }
    }

    #[test]
    fn a_hard_linked_file_fails_but_a_folder_count_is_ignored() {
        let mut f = facts(vec![]);
        f.links = 2;
        for r in [Role::Exe, Role::Config, Role::FolderFile] {
            assert_eq!(judge(r, &f).len(), 1, "{r:?}");
        }
        assert_eq!(judge(Role::Folder, &f), Vec::<String>::new());
    }

    #[test]
    fn a_config_owned_by_a_user_or_writable_by_users_fails() {
        let mut f = facts(program_files_like());
        f.owner = Some(Who::Other);
        assert_eq!(judge(Role::Config, &f).len(), 1);
        // Users with Modify, as a loose ACL on a copied file has.
        let f = facts(vec![
            ace(ALLOWED, 0, 0x001F_01FF, Who::Trusted),
            ace(ALLOWED, 0, 0x0013_01BF, Who::Other),
        ]);
        assert_eq!(judge(Role::Config, &f).len(), 1);
        assert_eq!(judge(Role::FolderFile, &f).len(), 1);
    }

    #[test]
    fn a_user_owned_folder_file_with_a_trusted_acl_fails() {
        // b2: the owner can change the ACL whatever it says now.
        let mut f = facts(vec![ace(ALLOWED, 0, 0x001F_01FF, Who::Trusted)]);
        f.owner = Some(Who::Other);
        let r = name_folder_file("helper.dll", judge(Role::FolderFile, &f));
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0].starts_with("the file helper.dll in the exe folder"),
            "{r:?}"
        );
    }

    #[test]
    fn reasons_are_deduplicated_and_end_with_the_advice() {
        let r = finish(vec!["a".to_owned(), "b".to_owned(), "a".to_owned()]);
        assert_eq!(r, vec!["a".to_owned(), "b".to_owned(), ADVICE.to_owned()]);
        assert_eq!(finish(Vec::new()), Vec::<String>::new());
        assert!(ADVICE.contains("takeown /a") && ADVICE.contains("icacls"));
        assert!(!ADVICE.contains(':'), "no path in the advice");
    }

    #[test]
    fn an_admin_only_config_passes() {
        assert_eq!(
            judge(Role::Config, &facts(program_files_like())),
            Vec::<String>::new()
        );
    }

    // Read-only checks on the real file system.

    #[cfg(windows)]
    #[test]
    fn a_system_exe_location_passes() {
        let root = std::env::var_os("SystemRoot").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        // Measured: System32 files are hard links into WinSxS, so the link
        // rule refuses them. That is right for an install folder. Here only
        // the owner and ACL rules are checked on a real admin-only chain.
        let exe = root.join("System32").join("cmd.exe");
        let reasons: Vec<String> = check_chain(&exe, Role::Exe, Role::Folder)
            .into_iter()
            .filter(|r| !r.contains("hard link"))
            .collect();
        assert_eq!(reasons, Vec::<String>::new());
    }

    #[cfg(windows)]
    #[test]
    fn a_user_temp_location_fails() {
        // The test process owns its temp folder, so its owner is not trusted.
        let dir = std::env::temp_dir().join(format!("ntpc-loc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("fake.exe");
        std::fs::write(&exe, b"x").unwrap();
        let reasons = check_exe_location(&exe);
        let _ = std::fs::remove_file(&exe);
        let _ = std::fs::remove_dir(&dir);
        assert_ne!(reasons, Vec::<String>::new());
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_config_passes_and_a_system_file_passes() {
        let root = std::env::var_os("SystemRoot").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        assert_eq!(
            check_config_location(&root.join("System32").join("ntpc-no-such-config.toml")),
            Vec::<String>::new()
        );
        let reasons: Vec<String> = check_config_location(&root.join("System32").join("cmd.exe"))
            .into_iter()
            .filter(|r| !r.contains("hard link") && r != ADVICE)
            .collect();
        assert_eq!(reasons, Vec::<String>::new());
    }

    #[cfg(windows)]
    #[test]
    fn a_user_owned_or_hard_linked_config_fails() {
        let dir = std::env::temp_dir().join(format!("ntpc-cfgloc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, b"dhcp = true").unwrap();
        let owned = check_config_location(&cfg);
        assert!(
            owned
                .iter()
                .any(|r| r.contains("the config file is not owned")),
            "{owned:?}"
        );
        let link = dir.join("second-name.toml");
        std::fs::hard_link(&cfg, &link).unwrap();
        let linked = check_config_location(&cfg);
        assert!(
            linked.iter().any(|r| r.contains("more than one hard link")),
            "{linked:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn a_loose_file_next_to_the_exe_fails_the_exe_check() {
        let dir = std::env::temp_dir().join(format!("ntpc-folderfiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("ntptimeclient-winrs.exe");
        std::fs::write(&exe, b"x").unwrap();
        std::fs::write(dir.join("helper.dll"), b"x").unwrap();
        // a1: a user-owned config.toml is named by its bare file name.
        std::fs::write(dir.join("config.toml"), b"dhcp = true").unwrap();
        std::fs::create_dir_all(dir.join("ntptimeclient-winrs.exe.local")).unwrap();
        let reasons = check_exe_location(&exe);
        assert!(
            reasons
                .iter()
                .any(|r| r.starts_with("the file helper.dll in the exe folder")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.starts_with("the file config.toml in the exe folder")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("sub folder, ntptimeclient-winrs.exe.local")),
            "{reasons:?}"
        );
        assert_eq!(reasons.last().map(String::as_str), Some(ADVICE));
        let dir_text = dir.to_string_lossy().into_owned();
        assert!(
            reasons.iter().all(|r| !r.contains(&dir_text)),
            "{reasons:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn a_relative_path_fails() {
        assert_ne!(
            check_exe_location(Path::new("ntptimeclient-winrs.exe")),
            Vec::<String>::new()
        );
    }
}
