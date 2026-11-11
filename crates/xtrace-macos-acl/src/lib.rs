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

// <sys/acl.h>: acl_t is `struct _acl *`. The pointee is deliberately opaque.
#[repr(C)]
struct Acl {
    _private: [u8; 0],
}

#[cfg(test)]
#[repr(u32)]
enum AclType {
    Extended = 0x0000_0100,
}

// <sys/_types/_filesec_t.h> and <sys/fcntl.h>: opaque SDK-owned security state.
#[repr(C)]
struct Filesec {
    _private: [u8; 0],
}

#[repr(u32)]
enum FilesecProperty {
    Acl = 5,
}

// <sys/stat.h>, __DARWIN_STRUCT_STAT64, on arm64 and x86_64. Only output storage;
// Rust never reads it. In particular, do not use the legacy 32-bit-inode layout.
#[repr(C)]
struct Stat {
    dev: i32,
    mode: u16,
    nlink: u16,
    ino: u64,
    uid: u32,
    gid: u32,
    rdev: i32,
    times: [[i64; 2]; 4],
    size: i64,
    blocks: i64,
    blksize: i32,
    flags: u32,
    generation: u32,
    spare: i32,
    qspare: [i64; 2],
}

const _: () = {
    assert!(std::mem::size_of::<Stat>() == 144);
    assert!(std::mem::align_of::<Stat>() == 8);
};

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

// SAFETY: signatures match <sys/acl.h>, <sys/fcntl.h>, <sys/stat.h>, <pwd.h>
// and <grp.h>. ssize_t is isize on both supported macOS architectures. Intel's
// inode64 symbols match the Stat layout; arm64 uses that layout without a suffix.
unsafe extern "C" {
    fn filesec_init() -> *mut Filesec;
    fn filesec_free(filesec: *mut Filesec);
    fn filesec_query_property(
        filesec: *mut Filesec,
        property: FilesecProperty,
        present: *mut c_int,
    ) -> c_int;
    fn filesec_get_property(
        filesec: *mut Filesec,
        property: FilesecProperty,
        value: *mut c_void,
    ) -> c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: c_int, stat: *mut Stat, filesec: *mut Filesec) -> c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "lstatx_np$INODE64")]
    fn lstatx_np(path: *const c_char, stat: *mut Stat, filesec: *mut Filesec) -> c_int;
    #[cfg(test)]
    fn acl_set_fd_np(fd: c_int, acl: *mut Acl, acl_type: AclType) -> c_int;
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

/// Returns true only for a proven absent or empty extended ACL; false means nonempty or unknown.
/// This is evidence only: callers must bracket it with identity, state and deadline checks.
/// A supplied file is queried by held descriptor; otherwise the final name is not followed.
///
/// A successful extended stat followed by a successful property query proves absence when
/// FILESEC_ACL is unset: Darwin Libc's statx1 clears it for KAUTH_FILESEC_NOACL. Bare
/// NULL/ENOENT from acl_get_fd_np or acl_get_link_np is not used as evidence; errors from
/// stat or either property operation always force fallback. `acl_init(3)` documents a
/// zero-entry ACL;
/// `acl_size(3)` gives its external representation size. The extended format has a fixed
/// header plus one fixed-size record per entry, so equal successful sizes prove zero entries
/// without inspecting an opaque handle or mistaking Darwin's end-of-iteration EINVAL for
/// absence. Even failure to free a handle forces fallback.
pub fn no_extended_acl(path: &Path, descriptor: Option<&File>) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: the CString remains live and terminated, and any supplied descriptor is borrowed
    // for the whole call. Stat is correctly aligned SDK output storage. Each filesec is fresh,
    // populated only by a successful bound/unfollowed query, and freed on every branch. The
    // property getter allocates an independent acl_t, freed even if a later operation fails.
    unsafe {
        let filesec = filesec_init();
        if filesec.is_null() {
            return false;
        }
        let mut stat = std::mem::MaybeUninit::<Stat>::uninit();
        let queried = match descriptor {
            Some(file) => fstatx_np(file.as_raw_fd(), stat.as_mut_ptr(), filesec),
            None => lstatx_np(path.as_ptr(), stat.as_mut_ptr(), filesec),
        };
        let mut present = -1;
        if queried != 0 || filesec_query_property(filesec, FilesecProperty::Acl, &mut present) != 0
        {
            filesec_free(filesec);
            return false;
        }
        if present == 0 {
            filesec_free(filesec);
            return true;
        }
        // Libc returns the property's validity bitmask, not a normalized boolean.
        let mut acl: *mut Acl = std::ptr::null_mut();
        let got_acl = filesec_get_property(filesec, FilesecProperty::Acl, (&raw mut acl).cast());
        filesec_free(filesec);
        if got_acl != 0 || acl.is_null() {
            if !acl.is_null() {
                acl_free(acl.cast());
            }
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

#[cfg(test)]
mod tests;
