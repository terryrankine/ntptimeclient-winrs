//! Thin safe wrappers over the Win32 calls the adapters need.
//!
//! This is the only module with `unsafe`. Each wrapper owns its buffers and
//! handles, checks the return value and gives back plain Rust types. Facts
//! and sources for every call: `docs/architecture.md`, "Platform".
//!
//! Nothing here decides policy. `clock` and `acl` do that.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_NOT_ALL_ASSIGNED, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree,
    SYSTEMTIME,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, IsWellKnownSid, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_SYSTEMTIME_NAME, SECURITY_ATTRIBUTES,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
    TokenPrivileges, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemTimeAdjustment, GetSystemTimeAdjustmentPrecise, GetSystemTimePreciseAsFileTime,
    SetSystemTime, SetSystemTimeAdjustmentPrecise,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::Time::FileTimeToSystemTime;
use windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise;

/// The rate state the OS reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawAdjustment {
    /// Counts added per update period.
    pub adjustment: u64,
    /// Counts per update period at the nominal rate.
    pub increment: u64,
    /// The OS keeps time itself and ignores `adjustment`.
    pub disabled: bool,
}

/// Reads `GetSystemTimeAdjustmentPrecise`. Read only.
///
/// # Errors
/// The OS error if the call fails.
pub fn time_adjustment_precise() -> io::Result<RawAdjustment> {
    let mut adjustment = 0u64;
    let mut increment = 0u64;
    let mut disabled = 0;
    // SAFETY: the three out pointers point at live locals of the documented
    // types (u64, u64, BOOL). The call writes nothing else.
    let ok = unsafe {
        GetSystemTimeAdjustmentPrecise(&raw mut adjustment, &raw mut increment, &raw mut disabled)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(RawAdjustment {
        adjustment,
        increment,
        disabled: disabled != 0,
    })
}

/// Reads the legacy `GetSystemTimeAdjustment`. Read only. Used to compare.
///
/// # Errors
/// The OS error if the call fails.
pub fn time_adjustment_legacy() -> io::Result<RawAdjustment> {
    let mut adjustment = 0u32;
    let mut increment = 0u32;
    let mut disabled = 0;
    // SAFETY: as above, with the documented u32, u32, BOOL out types.
    let ok = unsafe {
        GetSystemTimeAdjustment(&raw mut adjustment, &raw mut increment, &raw mut disabled)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(RawAdjustment {
        adjustment: u64::from(adjustment),
        increment: u64::from(increment),
        disabled: disabled != 0,
    })
}

/// Calls `SetSystemTimeAdjustmentPrecise`. This changes the system clock
/// rate. Only the clock adapter and the ignored admin tests call it.
///
/// # Errors
/// The OS error if the call fails, for example without the privilege.
pub fn set_time_adjustment_precise(adjustment: u64, disabled: bool) -> io::Result<()> {
    // SAFETY: plain value arguments, no pointers.
    let ok = unsafe { SetSystemTimeAdjustmentPrecise(adjustment, i32::from(disabled)) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wall time as a `FILETIME` value: 100 ns units since 1601-01-01 UTC.
#[must_use]
pub fn system_time_precise() -> u64 {
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: `ft` is a live FILETIME. The call has no failure mode.
    unsafe { GetSystemTimePreciseAsFileTime(&raw mut ft) };
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// Unbiased interrupt time in 100 ns units. It excludes sleep.
#[must_use]
pub fn unbiased_interrupt_time_precise() -> u64 {
    let mut t = 0u64;
    // SAFETY: `t` is a live u64. The call has no failure mode.
    unsafe { QueryUnbiasedInterruptTimePrecise(&raw mut t) };
    t
}

/// Sets the system clock to a `FILETIME` value. Milliseconds only: the
/// sub-millisecond part is dropped by `FileTimeToSystemTime`. This changes
/// the system clock. Only the clock adapter and the ignored admin tests call
/// it.
///
/// # Errors
/// The OS error if the conversion or the set fails.
pub fn set_system_time(filetime: u64) -> io::Result<()> {
    // The masks keep each half inside 32 bits, so the casts lose nothing.
    #[allow(clippy::cast_possible_truncation)]
    let ft = FILETIME {
        dwLowDateTime: (filetime & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (filetime >> 32) as u32,
    };
    let mut st = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    // SAFETY: both pointers point at live locals of the documented types.
    let ok = unsafe { FileTimeToSystemTime(&raw const ft, &raw mut st) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `st` is a filled SYSTEMTIME that lives across the call.
    let ok = unsafe { SetSystemTime(&raw const st) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens the current process token with `access`.
fn process_token(access: u32) -> io::Result<OwnedHandle> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no close.
    // `token` is a live out slot. On success it holds a handle we own.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `token` is a valid handle owned by us
    // and closed exactly once by OwnedHandle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// The LUID of `SeSystemtimePrivilege` on this machine.
fn systemtime_luid() -> io::Result<LUID> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: a null system name means the local system. The name is a
    // static NUL-terminated wide string. `luid` is a live out slot.
    let ok = unsafe { LookupPrivilegeValueW(ptr::null(), SE_SYSTEMTIME_NAME, &raw mut luid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(luid)
}

/// Whether the process token holds `SeSystemtimePrivilege` at all, enabled
/// or not. Read only.
///
/// # Errors
/// The OS error if the token cannot be read.
pub fn token_has_systemtime_privilege() -> io::Result<bool> {
    let luid = systemtime_luid()?;
    let token = process_token(TOKEN_QUERY)?;
    let mut needed = 0u32;
    // SAFETY: a null buffer of length 0 asks only for the size. It fails
    // with ERROR_INSUFFICIENT_BUFFER and sets `needed`.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &raw mut needed,
        );
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 elements give the 4-byte alignment TOKEN_PRIVILEGES needs.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `needed` bytes, writable and aligned.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let base = buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: the OS filled `buf` with a TOKEN_PRIVILEGES. Reading the count
    // stays inside the buffer, which holds at least the header.
    let count = unsafe { (*base).PrivilegeCount } as usize;
    let header = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let fits = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|n| n.checked_add(header))
        .is_some_and(|n| n <= needed as usize);
    if !fits {
        return Err(io::Error::other("token privilege list is truncated"));
    }
    // SAFETY: the check above proves `count` entries lie inside `buf`. The
    // array starts at the `Privileges` field and the buffer outlives the
    // slice.
    let entries = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*base).Privileges).cast::<LUID_AND_ATTRIBUTES>(),
            count,
        )
    };
    Ok(entries
        .iter()
        .any(|e| e.Luid.LowPart == luid.LowPart && e.Luid.HighPart == luid.HighPart))
}

/// Whether the process token is elevated. Read only.
///
/// # Errors
/// The OS error if the token cannot be read.
pub fn token_is_elevated() -> io::Result<bool> {
    let token = process_token(TOKEN_QUERY)?;
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // The struct is 4 bytes, so the size fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let size = size_of::<TOKEN_ELEVATION>() as u32;
    // SAFETY: `elevation` is a live TOKEN_ELEVATION of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            ptr::from_mut(&mut elevation).cast::<c_void>(),
            size,
            &raw mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// Enables `SeSystemtimePrivilege` on the process token.
///
/// # Errors
/// `ERROR_NOT_ALL_ASSIGNED` (1300) when the token lacks the privilege.
/// The docs say the call can return success in that case, so the last error
/// is checked too. Any other OS error as it comes.
pub fn enable_systemtime_privilege() -> io::Result<()> {
    let luid = systemtime_luid()?;
    let token = process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    let state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: `state` is a live TOKEN_PRIVILEGES with one entry. No previous
    // state is asked for, so the null out pointers and zero length match.
    let ok = unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &raw const state,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // SAFETY: GetLastError only reads the thread's last error value.
    let last = unsafe { GetLastError() };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if last == ERROR_NOT_ALL_ASSIGNED {
        return Err(error_from_code(last));
    }
    Ok(())
}

/// A `WIN32_ERROR` as an `io::Error`.
fn error_from_code(code: u32) -> io::Error {
    // Win32 error codes are below 0x8000_0000, so the cast keeps the value.
    #[allow(clippy::cast_possible_wrap)]
    io::Error::from_raw_os_error(code as i32)
}

/// `path` as a NUL-terminated wide string. Refuses an inner NUL.
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path holds a NUL",
        ));
    }
    w.push(0);
    Ok(w)
}

/// Opens `path` without following a reparse point at its last component.
/// Works for files and directories.
///
/// # Errors
/// The OS error if the open fails.
pub fn open_no_follow(path: &Path, access: u32) -> io::Result<OwnedHandle> {
    let name = wide(path)?;
    // SAFETY: `name` is NUL-terminated and outlives the call. No security
    // attributes and no template are passed, which the API allows.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `h` is a valid handle we now own.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

/// File attributes and reparse tag of an open handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeTag {
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// The reparse tag. Meaningful only with the reparse attribute.
    pub reparse_tag: u32,
}

/// Reads `FileAttributeTagInfo` for `handle`.
///
/// # Errors
/// The OS error if the query fails.
pub fn attribute_tag(handle: &OwnedHandle) -> io::Result<AttributeTag> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // The struct is 8 bytes, so the size fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let size = size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32;
    // SAFETY: `info` is a live struct of the class and size passed. The
    // handle is open for the duration of the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileAttributeTagInfo,
            ptr::from_mut(&mut info).cast::<c_void>(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(AttributeTag {
        attributes: info.FileAttributes,
        reparse_tag: info.ReparseTag,
    })
}

/// A SID sorted into the cases the state directory cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// `NT AUTHORITY\SYSTEM`.
    System,
    /// `BUILTIN\Administrators`.
    Administrators,
    /// Anyone else.
    Other,
}

/// One ACE of a DACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AceInfo {
    /// `ACE_HEADER.AceType`. 0 is access allowed, 1 is access denied.
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags`.
    pub flags: u8,
    /// Access mask. Zero for ACE types without a plain mask and SID.
    pub mask: u32,
    /// Who the ACE is for. `Other` for ACE types without a plain SID.
    pub principal: Principal,
}

/// Owner and DACL of an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// The owner, or `None` if the descriptor has none.
    pub owner: Option<Principal>,
    /// The DACL is protected from inheritance.
    pub dacl_protected: bool,
    /// The ACEs, or `None` for a null DACL (which grants everyone all).
    pub dacl: Option<Vec<AceInfo>>,
}

/// `ACCESS_ALLOWED_ACE_TYPE`. Written out to avoid one more feature.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `ACCESS_DENIED_ACE_TYPE`. Same layout as the allowed ACE.
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// Frees a `LocalAlloc` buffer from the OS on drop.
struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an OS call documented to return
            // LocalAlloc memory, and it is freed once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn classify(sid: PSID) -> Principal {
    if sid.is_null() {
        return Principal::Other;
    }
    // SAFETY: `sid` points at a valid SID inside a live security descriptor.
    if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
        return Principal::System;
    }
    // SAFETY: as above.
    if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0 {
        return Principal::Administrators;
    }
    Principal::Other
}

/// Reads owner and DACL through an open handle.
///
/// # Errors
/// The OS error if the read fails.
pub fn read_security(handle: &OwnedHandle) -> io::Result<Security> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: every out pointer is a live local. The group and SACL slots
    // are null because they are not asked for.
    let rc = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut sd,
        )
    };
    if rc != 0 {
        return Err(error_from_code(rc));
    }
    // `owner` and `dacl` point into `sd`, which lives until this guard drops
    // at the end of the function.
    let _guard = LocalMem(sd);
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd` is the live descriptor from the call above.
    if unsafe { GetSecurityDescriptorControl(sd, &raw mut control, &raw mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = if owner.is_null() {
        None
    } else {
        Some(classify(owner))
    };
    let aces = if dacl.is_null() {
        None
    } else {
        // SAFETY: `dacl` points at a valid ACL inside `sd`.
        let count = unsafe { (*dacl).AceCount };
        let mut out = Vec::with_capacity(usize::from(count));
        for i in 0..u32::from(count) {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `i` is below the ACL's own count. `ace` is an out slot.
            if unsafe { GetAce(dacl, i, &raw mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: GetAce returned a pointer to an ACE inside `sd`. Every
            // ACE starts with an ACE_HEADER.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            let (mask, principal) = if header.AceType == ACCESS_ALLOWED_ACE_TYPE
                || header.AceType == ACCESS_DENIED_ACE_TYPE
            {
                let a = ace.cast::<ACCESS_ALLOWED_ACE>();
                // SAFETY: allowed and denied ACEs share the
                // ACCESS_ALLOWED_ACE layout. The SID starts at
                // `SidStart` and lies inside the ACE.
                unsafe {
                    (
                        (*a).Mask,
                        classify(ptr::addr_of!((*a).SidStart).cast_mut().cast()),
                    )
                }
            } else {
                (0, Principal::Other)
            };
            out.push(AceInfo {
                ace_type: header.AceType,
                flags: header.AceFlags,
                mask,
                principal,
            });
        }
        Some(out)
    };
    Ok(Security {
        owner,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        dacl: aces,
    })
}

/// SDDL of the state directory DACL: protected, SYSTEM and Administrators
/// full control, inherited by files and folders.
pub const SECURE_DACL_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The same with the owner set to Administrators.
const SECURE_OWNER_DACL_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// A self-relative security descriptor built from SDDL.
fn descriptor(sddl: &str) -> io::Result<LocalMem> {
    let s: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `s` is NUL-terminated and outlives the call. `sd` is an out
    // slot. The size out pointer may be null.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            s.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalMem(sd))
}

/// Writes the state directory DACL through `handle`, protected so nothing
/// is inherited from the parent. With `set_owner` it also makes
/// Administrators the owner.
///
/// # Errors
/// The OS error code. `ERROR_INVALID_OWNER` (1307) means the token cannot
/// assign that owner.
pub fn write_secure_dacl(handle: &OwnedHandle, set_owner: bool) -> io::Result<()> {
    let sd = descriptor(SECURE_OWNER_DACL_SDDL)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `sd.0` is a live descriptor. The out slots are live locals.
    if unsafe {
        GetSecurityDescriptorDacl(sd.0, &raw mut present, &raw mut dacl, &raw mut defaulted)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        // A null DACL would grant everyone everything. Never pass one on.
        return Err(io::Error::other("built descriptor has no DACL"));
    }
    let mut owner: PSID = ptr::null_mut();
    // SAFETY: as above.
    if unsafe { GetSecurityDescriptorOwner(sd.0, &raw mut owner, &raw mut defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let owner = if set_owner {
        info |= OWNER_SECURITY_INFORMATION;
        owner
    } else {
        ptr::null_mut()
    };
    // SAFETY: `owner` and `dacl` point into `sd`, which outlives the call.
    // The handle is open for the call.
    let rc = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            info,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if rc != 0 {
        return Err(error_from_code(rc));
    }
    Ok(())
}

/// Creates one directory with the state directory DACL already applied, so
/// it is never open to others in between. Parents are not created.
///
/// # Errors
/// The OS error if the create fails, `ERROR_ALREADY_EXISTS` included.
pub fn create_secure_dir(path: &Path) -> io::Result<()> {
    let name = wide(path)?;
    let sd = descriptor(SECURE_DACL_SDDL)?;
    // The struct is 24 bytes, so the size fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `name` is NUL-terminated. `attrs` and the descriptor it points
    // at outlive the call.
    let ok = unsafe { CreateDirectoryW(name.as_ptr(), &raw const attrs) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
