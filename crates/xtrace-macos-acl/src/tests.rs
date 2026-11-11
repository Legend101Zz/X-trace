use super::*;
use std::io;
use std::os::unix::fs::{DirBuilderExt as _, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .ok_or_else(|| io::Error::other("source tools/dev/env.sh for private scratch"))?;
        let path = PathBuf::from(root).join(format!(
            "macos-acl-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let fixture = Self(path);
        // Clear inheritance on the parent before creating the ordinary no-ACL children.
        chmod(&fixture.0, &["-N"])?;
        Ok(fixture)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        assert!(removed.is_ok(), "remove ACL fixture: {removed:?}");
    }
}

fn chmod(path: &Path, args: &[&str]) -> io::Result<()> {
    let status = Command::new("/bin/chmod").args(args).arg(path).status()?;
    assert!(status.success(), "fixture chmod must succeed");
    Ok(())
}

fn assert_both(path: &Path, file: &File, empty: bool) {
    // These call the FFI bridge directly. It has no subprocess implementation; chmod is
    // used only to arrange the fixture, never to obtain a verdict.
    assert_eq!(no_extended_acl(path, Some(file)), empty, "held descriptor");
    assert_eq!(no_extended_acl(path, None), empty, "unfollowed name");
}

fn assert_acl_property(path: &Path, file: &File, expected: bool) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: each query gets a fresh SDK handle and aligned output storage. The borrowed
    // file and CString stay live; filesec is freed before any assertion can unwind.
    unsafe {
        for by_name in [false, true] {
            let filesec = filesec_init();
            assert!(!filesec.is_null(), "filesec allocation");
            let mut stat = std::mem::MaybeUninit::<Stat>::uninit();
            let status = if by_name {
                lstatx_np(path.as_ptr(), stat.as_mut_ptr(), filesec)
            } else {
                fstatx_np(file.as_raw_fd(), stat.as_mut_ptr(), filesec)
            };
            let mut present = -1;
            let property = filesec_query_property(filesec, FilesecProperty::Acl, &mut present);
            filesec_free(filesec);
            assert_eq!(status, 0, "extended stat");
            assert_eq!(property, 0, "ACL property query");
            assert_eq!(present, c_int::from(expected), "ACL property presence");
        }
    }
    Ok(())
}

#[test]
fn fresh_files_and_directories_without_acls_are_empty_natively() -> io::Result<()> {
    let root = Fixture::new()?;
    let path = root.0.join("file");
    let file = File::create(&path)?;
    let directory_path = root.0.join("directory");
    std::fs::create_dir(&directory_path)?;
    let directory = File::open(&directory_path)?;
    for (path, file) in [(&path, &file), (&directory_path, &directory)] {
        assert_acl_property(path, file, false)?;
        assert_both(path, file, true);
    }
    Ok(())
}

#[test]
fn grants_are_not_empty_and_chmod_n_restores_native_absence() -> io::Result<()> {
    let root = Fixture::new()?;
    let path = root.0.join("file");
    let file = File::create(&path)?;
    let directory = File::open(&root.0)?;
    for (path, file) in [(&path, &file), (&root.0, &directory)] {
        assert_both(path, file, true);
        chmod(path, &["+a", "group:everyone allow read"])?;
        assert_acl_property(path, file, true)?;
        assert_both(path, file, false);
        chmod(path, &["-N"])?;
        assert_acl_property(path, file, false)?;
        assert_both(path, file, true);
    }
    Ok(())
}

#[test]
fn explicitly_set_zero_entry_acls_are_empty_natively() -> io::Result<()> {
    let root = Fixture::new()?;
    let path = root.0.join("file");
    let file = File::create(&path)?;
    let directory = File::open(&root.0)?;
    for (path, file) in [(&path, &file), (&root.0, &directory)] {
        // SAFETY: acl_init returns an SDK handle; the borrowed descriptor stays live.
        // The handle is freed before assertions, including when the setter fails.
        let (set, freed) = unsafe {
            let acl = acl_init(0);
            assert!(!acl.is_null(), "empty ACL allocation");
            let set = acl_set_fd_np(file.as_raw_fd(), acl, AclType::Extended);
            (set, acl_free(acl.cast()))
        };
        assert_eq!(set, 0, "set explicit zero-entry ACL");
        assert_eq!(freed, 0, "free explicit zero-entry ACL");
        assert_acl_property(path, file, true)?;
        assert_both(path, file, true);
    }
    Ok(())
}

#[test]
fn removed_names_are_unknown_but_held_descriptors_remain_bound() -> io::Result<()> {
    let root = Fixture::new()?;
    let path = root.0.join("file");
    let held = File::create(&path)?;
    std::fs::remove_file(&path)?;
    assert!(!no_extended_acl(&path, None), "ENOENT from stat is unknown");
    assert!(no_extended_acl(&path, Some(&held)), "held file still has no ACL");

    let replacement = File::create(&path)?;
    chmod(&path, &["+a", "group:everyone allow read"])?;
    assert_both(&path, &replacement, false);
    assert!(no_extended_acl(&path, Some(&held)), "query must stay on held inode");
    assert!(!no_extended_acl(&root.0.join("missing/child"), None));
    assert!(!no_extended_acl(Path::new(""), None));
    assert!(!no_extended_acl(Path::new("invalid\0name"), None));
    Ok(())
}

#[test]
fn named_queries_do_not_follow_the_final_symlink() -> io::Result<()> {
    let root = Fixture::new()?;
    let target = root.0.join("target");
    let file = File::create(&target)?;
    chmod(&target, &["+a", "group:everyone allow read"])?;
    let link = root.0.join("link");
    symlink(&target, &link)?;
    assert_both(&target, &file, false);
    assert!(no_extended_acl(&link, None), "symlink's own ACL is absent");
    std::fs::remove_file(&target)?;
    assert!(no_extended_acl(&link, None), "dangling link still exists");
    Ok(())
}
