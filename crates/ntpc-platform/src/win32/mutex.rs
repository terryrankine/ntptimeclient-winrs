//! A named mutex that marks "an instance is adjusting the clock" (R111).
//!
//! Facts (Learn, `CreateMutexW`): if the named mutex "existed before this
//! function call, the return value is a handle to the existing object, and
//! the `GetLastError` function returns `ERROR_ALREADY_EXISTS`". "The mutex
//! object is destroyed when its last handle has been closed", and the
//! system closes handles "automatically when the process terminates".
//! Learn warns that "a malicious user can create this mutex before you do
//! and prevent your application from starting". Mutexes need no privilege
//! to be created in the global namespace (Learn, Kernel object namespaces:
//! only file mappings and symbolic links do). So the owner of an existing
//! mutex is checked: only one owned by SYSTEM or Administrators counts as
//! another instance. Policy for a squatted name is in `instance.rs`.

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::Threading::CreateMutexW;

use super::{LocalMem, Principal, classify, descriptor, error_from_code};

/// A fresh mutex grants only SYSTEM and Administrators any access.
const MUTEX_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// An open named mutex. Closed once on drop.
#[derive(Debug)]
pub struct NamedMutex(HANDLE);

// SAFETY: a kernel handle is not tied to a thread. The handle is only
// closed, once, in drop.
unsafe impl Send for NamedMutex {}
// SAFETY: no method reads or writes through the handle.
unsafe impl Sync for NamedMutex {}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful CreateMutexW and is
        // closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// What opening the name found.
#[derive(Debug)]
pub enum Opened {
    /// This call created it. Hold the handle for the life of the instance.
    Created(NamedMutex),
    /// It existed. The owner of the existing object.
    Existed(NamedMutex, Principal),
}

fn owner_of(h: HANDLE) -> Principal {
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `h` is a live mutex handle with MUTEX_ALL_ACCESS (Learn),
    // which includes READ_CONTROL. The out slots are live locals. Only the
    // owner is asked for.
    let rc = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut sd,
        )
    };
    if rc != 0 {
        // Unreadable counts as not trusted.
        return Principal::Other;
    }
    // SAFETY: on success `sd` is LocalAlloc memory owned by us.
    let _guard = unsafe { LocalMem::new(sd) };
    // SAFETY: `owner` points into `sd`, alive until `_guard` drops.
    unsafe { classify(owner) }
}

/// Creates or opens the named mutex `name` without taking ownership.
///
/// # Errors
/// The OS error, for example access denied when an existing object's DACL
/// refuses us.
pub fn open(name: &str) -> io::Result<Opened> {
    open_with(name, MUTEX_SDDL)
}

fn open_with(name: &str, sddl: &str) -> io::Result<Opened> {
    if name.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"));
    }
    let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let sd = descriptor(sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        #[allow(clippy::cast_possible_truncation)]
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `sa`, its descriptor and `w` are live for the call. No
    // initial ownership: the handle's existence is the signal.
    let h = unsafe { CreateMutexW(&raw const sa, 0, w.as_ptr()) };
    // SAFETY: read straight after the call.
    let last = unsafe { GetLastError() };
    if h.is_null() {
        return Err(error_from_code(last));
    }
    let m = NamedMutex(h);
    if last == ERROR_ALREADY_EXISTS {
        let owner = owner_of(h);
        return Ok(Opened::Existed(m, owner));
    }
    Ok(Opened::Created(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(tag: &str) -> String {
        // Local, not Global, so a test never meets a real instance.
        format!("Local\\ntpc-test-mutex-{tag}-{}", std::process::id())
    }

    #[test]
    fn second_open_in_one_process_sees_the_first() {
        let n = name("two");
        // Everyone may open the test object, so the test also passes
        // without elevation.
        let first = open_with(&n, "D:P(A;;GA;;;WD)").unwrap();
        assert!(matches!(first, Opened::Created(_)));
        let second = open_with(&n, "D:P(A;;GA;;;WD)").unwrap();
        // This process's token gives the owner. A test runs as an ordinary
        // or elevated user, so only the variant is checked here.
        assert!(matches!(second, Opened::Existed(_, _)));
        drop(second);
        drop(first);
        // All handles closed: the object is gone, so a new open creates it.
        assert!(matches!(
            open_with(&n, "D:P(A;;GA;;;WD)").unwrap(),
            Opened::Created(_)
        ));
    }

    #[test]
    fn the_real_descriptor_admits_only_system_and_administrators() {
        let n = name("acl");
        let first = open(&n).unwrap();
        assert!(matches!(first, Opened::Created(_)));
        // Elevated: the second open sees it. Not elevated: the DACL refuses
        // this token, which is the point of the descriptor.
        match open(&n) {
            Ok(Opened::Existed(_, _)) => {}
            Err(e) => assert_eq!(e.raw_os_error(), Some(5)),
            Ok(Opened::Created(_)) => panic!("the first handle is still open"),
        }
    }

    #[test]
    fn a_nul_in_the_name_is_refused() {
        assert!(open("Local\\a\0b").is_err());
    }
}
