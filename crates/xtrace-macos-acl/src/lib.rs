//! Exact empty-ACL evidence from the macOS SDK, never an admission verdict by itself.
//!
//! Callers bracket this query with their existing descriptor/path state checks. In particular,
//! the named-file variant must not open another descriptor: closing it can drop SQLite locks.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

// sys/acl.h: acl_t is `struct _acl *`, and acl_type_t is an enum with nonnegative
// values (the Darwin C ABI uses unsigned int). The pointee is deliberately opaque.
#[repr(C)]
struct Acl {
    _private: [u8; 0],
}

#[repr(u32)]
enum AclType {
    Extended = 0x0000_0100,
}

// <pwd.h>, <grp.h>: uid_t/gid_t are u32 and __darwin_time_t is long on macOS.
#[repr(C)]
struct Passwd {
    pw_name: *mut c_char,
    pw_passwd: *mut c_char,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: std::ffi::c_long,
    pw_class: *mut c_char,
    pw_gecos: *mut c_char,
    pw_dir: *mut c_char,
    pw_shell: *mut c_char,
    pw_expire: std::ffi::c_long,
}

#[repr(C)]
struct Group {
    gr_name: *mut c_char,
    gr_passwd: *mut c_char,
    gr_gid: u32,
    gr_mem: *mut *mut c_char,
}

// SAFETY: signatures match <sys/acl.h>, <pwd.h> and <grp.h>. ssize_t is isize
// on both supported macOS architectures; all pointers remain SDK-owned or borrowed.
unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: AclType) -> *mut Acl;
    fn acl_get_link_np(path_p: *const c_char, acl_type: AclType) -> *mut Acl;
    fn acl_init(count: c_int) -> *mut Acl;
    fn acl_size(acl: *mut Acl) -> isize;
    fn acl_free(obj_p: *mut c_void) -> c_int;
    fn getpwuid_r(
        uid: u32,
        pwd: *mut Passwd,
        buffer: *mut c_char,
        size: usize,
        result: *mut *mut Passwd,
    ) -> c_int;
    fn getgrgid_r(
        gid: u32,
        group: *mut Group,
        buffer: *mut c_char,
        size: usize,
        result: *mut *mut Group,
    ) -> c_int;
}

/// `ls` prints account names when available, numeric IDs otherwise. Keep its parser's name
/// restrictions; an unusual directory-service name must not become admissible via the fast
/// path. Use reentrant lookups and bounded storage; any lookup error falls back to `ls`.
pub fn listing_names_compatible(
    metadata: &std::fs::Metadata,
    valid_name: impl Fn(&str) -> bool,
) -> bool {
    let mut buffer = [0_u8; 16 * 1024];
    let mut user = std::mem::MaybeUninit::<Passwd>::uninit();
    let mut group = std::mem::MaybeUninit::<Group>::uninit();
    let mut user_result = std::ptr::null_mut();
    let mut group_result = std::ptr::null_mut();
    // SAFETY: the SDK writes into correctly aligned structs and the live, writable buffer.
    // On successful non-null results its name pointers are terminated strings in that buffer.
    // Each name is consumed before the buffer is reused; no directory-service data escapes.
    unsafe {
        if getpwuid_r(
            metadata.uid(),
            user.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut user_result,
        ) != 0
        {
            return false;
        }
        if !user_result.is_null() {
            let name = (*user_result).pw_name;
            if name.is_null() || !CStr::from_ptr(name).to_str().is_ok_and(&valid_name) {
                return false;
            }
        }
        if getgrgid_r(
            metadata.gid(),
            group.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut group_result,
        ) != 0
        {
            return false;
        }
        group_result.is_null()
            || (!(*group_result).gr_name.is_null()
                && CStr::from_ptr((*group_result).gr_name).to_str().is_ok_and(&valid_name))
    }
}

/// Returns true only for a proven empty extended ACL; false means nonempty or unknown.
/// This is evidence only: callers must bracket it with identity, state and deadline checks.
/// A supplied file is queried by held descriptor; otherwise the final name is not followed.
///
/// Only a successful query returning an empty ACL can bypass `ls`. No errno, including
/// ENOENT, EINVAL or ENOTSUP, proves absence. `acl_init(3)` documents a zero-entry ACL;
/// `acl_size(3)` gives its external representation size. The extended format has a fixed
/// header plus one fixed-size record per entry, so equal successful sizes prove zero entries
/// without inspecting an opaque handle or mistaking Darwin's end-of-iteration EINVAL for
/// absence. Even failure to free a handle forces fallback.
pub fn no_extended_acl(path: &Path, descriptor: Option<&File>) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: the CString remains live and terminated, and any supplied descriptor is borrowed
    // for the whole call. All non-null handles come from the SDK, are used only with SDK ACL
    // functions, and are freed exactly once on every branch. No pointee is read by Rust.
    unsafe {
        let acl = match descriptor {
            Some(file) => acl_get_fd_np(file.as_raw_fd(), AclType::Extended),
            None => acl_get_link_np(path.as_ptr(), AclType::Extended),
        };
        if acl.is_null() {
            return false;
        }
        let empty = acl_init(0);
        if empty.is_null() {
            acl_free(acl.cast());
            return false;
        }
        let size = acl_size(acl);
        let empty_size = acl_size(empty);
        let freed_empty = acl_free(empty.cast()) == 0;
        let freed_acl = acl_free(acl.cast()) == 0;
        size > 0 && size == empty_size && freed_empty && freed_acl
    }
}
