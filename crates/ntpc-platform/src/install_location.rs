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
}

impl Role {
    const fn mask(self) -> u32 {
        match self {
            Role::Exe | Role::Folder => WRITE_MASK,
            Role::Ancestor => ANCESTOR_MASK,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Role::Exe => "the exe",
            Role::Folder => "the exe folder",
            Role::Ancestor => "a parent folder",
        }
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

/// Checks the exe at `exe` (an absolute, already resolved path), its folder
/// and every parent up to the drive root. Read only. Empty means safe.
///
/// # Errors
/// None. A path that cannot be read is a reason, not an error: unreadable
/// counts as unsafe.
#[cfg(windows)]
#[must_use]
pub fn check_exe_location(exe: &Path) -> Vec<String> {
    use crate::win32;

    /// `READ_CONTROL`, enough for owner and DACL.
    const READ_CONTROL: u32 = 0x0002_0000;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const ATTR_REPARSE: u32 = 0x400;
    /// `DRIVE_FIXED`.
    const DRIVE_FIXED: u32 = 3;

    let read = |p: &Path| -> std::io::Result<Facts> {
        let h = win32::open_no_follow(p, READ_CONTROL)?;
        let tag = win32::attribute_tag(&h)?;
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
        })
    };

    let mut out = Vec::new();
    if !exe.is_absolute() {
        out.push("the exe path is not absolute".to_owned());
        return out;
    }
    let mut steps: Vec<(Role, &Path)> = vec![(Role::Exe, exe)];
    let mut cur = exe.parent();
    let mut role = Role::Folder;
    while let Some(p) = cur {
        steps.push((role, p));
        role = Role::Ancestor;
        cur = p.parent();
    }
    if let Some((_, root)) = steps.last()
        && win32::drive_type(root) != DRIVE_FIXED
    {
        out.push("the exe is not on a fixed local drive".to_owned());
    }
    for (role, p) in steps {
        match read(p) {
            Ok(f) => out.extend(judge(role, &f)),
            Err(e) => out.push(format!(
                "cannot read the permissions of {}: OS error {}",
                role.label(),
                e.raw_os_error().unwrap_or(-1)
            )),
        }
    }
    out
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
        };
        for r in judge(Role::Folder, &f) {
            assert!(!r.contains('\\') && !r.contains(':'), "{r}");
        }
    }

    // Read-only checks on the real file system.

    #[cfg(windows)]
    #[test]
    fn a_system_exe_location_passes() {
        let root = std::env::var_os("SystemRoot").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        let exe = root.join("System32").join("cmd.exe");
        let reasons = check_exe_location(&exe);
        assert!(reasons.is_empty(), "{reasons:?}");
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
    fn a_relative_path_fails() {
        assert_ne!(
            check_exe_location(Path::new("ntptimeclient-winrs.exe")),
            Vec::<String>::new()
        );
    }
}
