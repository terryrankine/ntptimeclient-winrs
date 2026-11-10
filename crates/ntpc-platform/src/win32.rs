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

use windows_sys::core::PWSTR;

use windows_sys::Win32::Foundation::{
    ERROR_NOT_ALL_ASSIGNED, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree,
    SYSTEMTIME,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SE_PRIVILEGE_ENABLED, SE_SYSTEMTIME_NAME, SECURITY_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_OWNER, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenOwner,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FULL_DIR_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo,
    FileDispositionInfo, FileFullDirectoryInfo, FileFullDirectoryRestartInfo, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemTimeAdjustmentPrecise, GetSystemTimePreciseAsFileTime, SetSystemTime,
    SetSystemTimeAdjustmentPrecise,
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

#[cfg(test)]
/// Reads the legacy `GetSystemTimeAdjustment`. Read only. Used to compare.
///
/// # Errors
/// The OS error if the call fails.
pub fn time_adjustment_legacy() -> io::Result<RawAdjustment> {
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAdjustment;
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

/// Reads one variable-size token information class. Returns the buffer and
/// the number of bytes the OS wrote. The u64 elements give the alignment
/// every token structure needs.
fn token_info(token: &OwnedHandle, class: i32) -> io::Result<(Vec<u64>, usize)> {
    let mut needed = 0u32;
    // SAFETY: a null buffer of length 0 asks only for the size. The call
    // fails with ERROR_INSUFFICIENT_BUFFER and sets `needed`.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::null_mut(),
            0,
            &raw mut needed,
        );
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let mut written = 0u32;
    // SAFETY: `buf` holds at least `needed` writable, aligned bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &raw mut written,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((buf, (written as usize).min(needed as usize)))
}

/// The default owner the process token gives to new objects. Read only.
///
/// # Errors
/// The OS error if the token cannot be read.
pub fn token_default_owner() -> io::Result<Principal> {
    let token = process_token(TOKEN_QUERY)?;
    let (buf, len) = token_info(&token, TokenOwner)?;
    if len < size_of::<TOKEN_OWNER>() {
        return Err(io::Error::other("token owner is truncated"));
    }
    // SAFETY: the OS filled `buf` with a TOKEN_OWNER, checked to fit.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_OWNER>()).Owner };
    // SAFETY: GetTokenInformation stores the owner SID inside `buf` itself,
    // right after the TOKEN_OWNER header, and `buf` lives across the call.
    Ok(unsafe { classify(sid) })
}

#[cfg(test)]
/// Whether the process token holds `SeSystemtimePrivilege` at all, enabled
/// or not. Read only.
///
/// # Errors
/// The OS error if the token cannot be read.
pub fn token_has_systemtime_privilege() -> io::Result<bool> {
    use windows_sys::Win32::Security::TokenPrivileges;
    let luid = systemtime_luid()?;
    let token = process_token(TOKEN_QUERY)?;
    let (buf, len) = token_info(&token, TokenPrivileges)?;
    let header = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    if len < header {
        return Err(io::Error::other("token privilege list is truncated"));
    }
    let base = buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: the OS filled `buf` with a TOKEN_PRIVILEGES and the check
    // above proves the count field lies inside it.
    let count = unsafe { (*base).PrivilegeCount } as usize;
    let fits = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|n| n.checked_add(header))
        .is_some_and(|n| n <= len);
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

#[cfg(test)]
/// Whether the process token is elevated. Read only.
///
/// # Errors
/// The OS error if the token cannot be read.
pub fn token_is_elevated() -> io::Result<bool> {
    use windows_sys::Win32::Security::{TOKEN_ELEVATION, TokenElevation};
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
    /// `NT SERVICE\TrustedInstaller`. Owns many system folders.
    TrustedInstaller,
    /// Anyone else.
    Other,
}

/// SYSTEM, `S-1-5-18`.
const SID_SYSTEM: &str = "S-1-5-18";
/// Administrators, `S-1-5-32-544`.
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// `TrustedInstaller`, the service SID of `NT SERVICE\TrustedInstaller`.
const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Sorts a SID in string form. Pure, so the mapping is unit tested.
#[must_use]
pub fn principal_from_sid_string(sid: &str) -> Principal {
    match sid {
        SID_SYSTEM => Principal::System,
        SID_ADMINISTRATORS => Principal::Administrators,
        SID_TRUSTED_INSTALLER => Principal::TrustedInstaller,
        _ => Principal::Other,
    }
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

impl LocalMem {
    /// Takes ownership of `ptr`.
    ///
    /// # Safety
    /// `ptr` is null or came from an OS call documented to return memory
    /// that the caller frees with `LocalFree`. Nothing else frees it.
    unsafe fn new(ptr: *mut c_void) -> Self {
        Self(ptr)
    }
}

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `new`'s contract says the pointer is LocalAlloc memory
            // owned by this value alone, and it is freed once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Sorts a SID.
///
/// # Safety
/// `sid` is null or points at a valid SID that stays alive for the call.
unsafe fn classify(sid: PSID) -> Principal {
    if sid.is_null() {
        return Principal::Other;
    }
    let mut text: PWSTR = ptr::null_mut();
    // SAFETY: the caller guarantees `sid` is a valid live SID. `text` is an
    // out slot that receives LocalAlloc memory on success.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        // An unreadable SID is never trusted.
        return Principal::Other;
    }
    // SAFETY: on success `text` is LocalAlloc memory we must free.
    let _guard = unsafe { LocalMem::new(text.cast()) };
    let mut len = 0usize;
    // SAFETY: the OS returns a NUL-terminated wide string. The scan stops at
    // the NUL, which lies inside the allocation.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` wide chars from `text` are initialised and inside the
    // allocation, which `_guard` keeps alive until the end of the function.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    principal_from_sid_string(&String::from_utf16_lossy(units))
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
    // SAFETY: GetSecurityInfo documents `sd` as LocalFree memory.
    let _guard = unsafe { LocalMem::new(sd) };
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd` is the live descriptor from the call above.
    if unsafe { GetSecurityDescriptorControl(sd, &raw mut control, &raw mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = if owner.is_null() {
        None
    } else {
        // SAFETY: `owner` points at the owner SID inside `sd`, alive here.
        Some(unsafe { classify(owner) })
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
    // SAFETY: the call documents `sd` as LocalFree memory.
    Ok(unsafe { LocalMem::new(sd) })
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

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's own name, no path.
    pub name: std::ffi::OsString,
    /// `FILE_ATTRIBUTE_*` bits as the listing reports them.
    pub attributes: u32,
}

/// Byte offsets inside one `FILE_FULL_DIR_INFO` record. Checked against
/// the real struct at compile time below.
const REC_NEXT: usize = 0;
const REC_ATTRIBUTES: usize = 56;
const REC_NAME_LENGTH: usize = 60;
const REC_NAME: usize = 68;

const _: () = {
    assert!(std::mem::offset_of!(FILE_FULL_DIR_INFO, NextEntryOffset) == REC_NEXT);
    assert!(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileAttributes) == REC_ATTRIBUTES);
    assert!(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileNameLength) == REC_NAME_LENGTH);
    assert!(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName) == REC_NAME);
};

fn read_u32(buf: &[u8], at: usize) -> io::Result<u32> {
    at.checked_add(4)
        .and_then(|end| buf.get(at..end))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| io::Error::other("directory listing record out of bounds"))
}

/// Walks the `FILE_FULL_DIR_INFO` records in `buf`. Safe code only: every
/// field is read through a bounds-checked slice, so a bad record gives an
/// error, never a read outside `buf`. `.` and `..` are left out.
///
/// # Errors
/// A record header or name that does not fit in `buf`, or a next offset
/// that leaves `buf`.
pub fn parse_dir_records(buf: &[u8], out: &mut Vec<DirEntry>) -> io::Result<()> {
    use std::os::windows::ffi::OsStringExt;
    let mut offset = 0usize;
    loop {
        // The fixed header must fit before any field is read.
        if offset
            .checked_add(REC_NAME)
            .is_none_or(|end| end > buf.len())
        {
            return Err(io::Error::other("directory listing record out of bounds"));
        }
        let next = read_u32(buf, offset + REC_NEXT)? as usize;
        let attributes = read_u32(buf, offset + REC_ATTRIBUTES)?;
        let name_len = read_u32(buf, offset + REC_NAME_LENGTH)? as usize;
        let name_start = offset + REC_NAME;
        let name = name_start
            .checked_add(name_len)
            .and_then(|end| buf.get(name_start..end))
            .ok_or_else(|| io::Error::other("directory listing name out of bounds"))?;
        let units: Vec<u16> = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let name = std::ffi::OsString::from_wide(&units);
        if name != "." && name != ".." {
            out.push(DirEntry { name, attributes });
        }
        if next == 0 {
            return Ok(());
        }
        offset = offset
            .checked_add(next)
            .filter(|o| *o < buf.len())
            .ok_or_else(|| io::Error::other("directory listing next record out of bounds"))?;
    }
}

/// Lists a directory through its open handle. The handle needs
/// `FILE_LIST_DIRECTORY`. Nothing is opened by path and no link is followed.
/// `.` and `..` are left out.
///
/// # Errors
/// The OS error if the listing fails, or a malformed record.
pub fn list_dir(handle: &OwnedHandle) -> io::Result<Vec<DirEntry>> {
    // u64 elements give the 8-byte alignment the OS wants for the buffer.
    let mut buf = vec![0u64; 8192];
    let bytes = buf.len() * 8;
    // 64 KiB fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let size = bytes as u32;
    let mut out = Vec::new();
    let mut class = FileFullDirectoryRestartInfo;
    loop {
        // SAFETY: `buf` is `size` writable, aligned bytes. The handle is open.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle(),
                class,
                buf.as_mut_ptr().cast::<c_void>(),
                size,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(18) {
                // ERROR_NO_MORE_FILES: the listing is complete.
                return Ok(out);
            }
            return Err(e);
        }
        class = FileFullDirectoryInfo;
        // SAFETY: `buf` owns `bytes` initialised bytes (it started zeroed and
        // u64 has no invalid bit patterns). The byte view lives only for the
        // parse call, while `buf` is not touched otherwise.
        let view = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
        parse_dir_records(view, &mut out)?;
    }
}

/// Attributes, hard link count and identity of an open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkInfo {
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// Number of hard links to the file.
    pub links: u32,
    /// Serial number of the volume that holds the file.
    pub volume_serial: u32,
    /// File index, unique on its volume while the file is open.
    pub file_index: u64,
}

impl LinkInfo {
    /// True when both describe the same file on the same volume.
    #[must_use]
    pub fn same_file(&self, other: &Self) -> bool {
        self.volume_serial == other.volume_serial && self.file_index == other.file_index
    }
}

/// Reads `GetFileInformationByHandle` for `handle`.
///
/// # Errors
/// The OS error if the query fails.
pub fn link_info(handle: &OwnedHandle) -> io::Result<LinkInfo> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain data. All zero is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a live struct of the documented type.
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LinkInfo {
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

/// `GetDriveTypeW` for a drive root such as `C:\`. Read only.
#[must_use]
pub fn drive_type(root: &Path) -> u32 {
    let Ok(name) = wide(root) else {
        // DRIVE_NO_ROOT_DIR: never accepted.
        return 1;
    };
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { GetDriveTypeW(name.as_ptr()) }
}

/// Marks the file behind `handle` for deletion. It goes when the last
/// handle closes. The handle needs `DELETE`. Deleting through the checked
/// handle means the file checked is the file deleted.
///
/// # Errors
/// The OS error if the call fails.
pub fn delete_by_handle(handle: &OwnedHandle) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // The struct is 1 byte, so the size fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let size = size_of::<FILE_DISPOSITION_INFO>() as u32;
    // SAFETY: `info` is a live struct of the class and size passed.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle(),
            FileDispositionInfo,
            (&raw const info).cast::<c_void>(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One record: next offset, attributes, name. Padded to 8 bytes like
    /// the OS does when `pad` is set.
    fn record(next: u32, attributes: u32, name: &str, pad: bool) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut r = vec![0u8; REC_NAME];
        r[REC_NEXT..REC_NEXT + 4].copy_from_slice(&next.to_le_bytes());
        r[REC_ATTRIBUTES..REC_ATTRIBUTES + 4].copy_from_slice(&attributes.to_le_bytes());
        let len = u32::try_from(units.len() * 2).unwrap();
        r[REC_NAME_LENGTH..REC_NAME_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        for u in units {
            r.extend_from_slice(&u.to_le_bytes());
        }
        if pad {
            while !r.len().is_multiple_of(8) {
                r.push(0);
            }
        }
        r
    }

    fn parse(buf: &[u8]) -> io::Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        parse_dir_records(buf, &mut out).map(|()| out)
    }

    #[test]
    fn walker_reads_chained_records_and_skips_dots() {
        let a = record(0, 0x10, ".", true);
        let mut buf = a.clone();
        buf[REC_NEXT..REC_NEXT + 4].copy_from_slice(&u32::try_from(a.len()).unwrap().to_le_bytes());
        let b = record(0, 0x20, "drift.txt", true);
        buf.extend_from_slice(&b);
        let out = parse(&buf).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "drift.txt");
        assert_eq!(out[0].attributes, 0x20);
    }

    #[test]
    fn walker_stops_at_a_zero_next_offset() {
        let mut buf = record(0, 0x20, "drift.txt", true);
        // Garbage after the last record is never read.
        buf.extend_from_slice(&[0xFF; 100]);
        assert_eq!(parse(&buf).unwrap().len(), 1);
    }

    #[test]
    fn walker_refuses_a_truncated_header() {
        let buf = record(0, 0x20, "x", false);
        assert!(parse(&buf[..REC_NAME - 1]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn walker_refuses_a_name_longer_than_the_buffer() {
        let mut buf = record(0, 0x20, "drift.txt", false);
        buf.truncate(buf.len() - 2);
        assert!(parse(&buf).is_err());
        let mut huge = record(0, 0x20, "x", false);
        huge[REC_NAME_LENGTH..REC_NAME_LENGTH + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&huge).is_err());
    }

    #[test]
    fn walker_refuses_a_next_offset_past_the_end() {
        let mut buf = record(0, 0x20, "drift.txt", true);
        let len = u32::try_from(buf.len()).unwrap();
        buf[REC_NEXT..REC_NEXT + 4].copy_from_slice(&len.to_le_bytes());
        assert!(parse(&buf).is_err());
        buf[REC_NEXT..REC_NEXT + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&buf).is_err());
    }
}
