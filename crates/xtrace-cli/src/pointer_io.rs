//! Bounded descriptor-relative I/O for public repository locator files.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};

use crate::error::CliError;

pub(crate) const POINTER_MAX_BYTES: usize = 8192;
pub(crate) const PENDING_MAX_BYTES: usize = 8192;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
const BUDGET: Duration = Duration::from_secs(5);

pub(crate) struct RepositoryInitLock {
    _file: File,
    root: File,
    pub(crate) directory: File,
    started: Instant,
}

impl RepositoryInitLock {
    pub(crate) fn acquire(repo: &Path) -> Result<Self, CliError> {
        let started = Instant::now();
        let repo_file = open_directory(repo)?;
        let directory = open_or_create_directory(&repo_file, ".xtrace")?;
        let (file, created) = match fs::openat(
            &directory,
            "init.lock",
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(fd) => (File::from(fd), true),
            Err(error) if error == rustix::io::Errno::EXIST => (
                open_at(
                    &directory,
                    "init.lock",
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?,
                false,
            ),
            Err(_) => return Err(io_error("open repository init lock")),
        };
        if created {
            fs::fchmod(&file, Mode::from_bits_truncate(0o600))
                .map_err(|_| io_error("secure new repository init lock"))?;
        }
        validate_file(&file, &directory, "init.lock")?;
        loop {
            check_budget(started)?;
            match fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    validate_directory_name(&repo_file, ".xtrace", &directory)?;
                    return Ok(Self { _file: file, root: repo_file, directory, started });
                }
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(io_error("acquire repository init lock")),
            }
        }
    }

    pub(crate) fn read(&self, name: &str, cap: usize) -> Result<Option<Vec<u8>>, CliError> {
        validate_directory_name(&self.root, ".xtrace", &self.directory)?;
        let result = read_at(&self.directory, name, cap, self.started)?;
        validate_directory_name(&self.root, ".xtrace", &self.directory)?;
        Ok(result)
    }

    pub(crate) fn revalidate(&self) -> Result<(), CliError> {
        validate_directory_name(&self.root, ".xtrace", &self.directory)?;
        check_budget(self.started)
    }

    pub(crate) fn publish(&self, name: &str, bytes: &[u8], cap: usize) -> Result<(), CliError> {
        if bytes.len() > cap {
            return Err(CliError::StoreCorrupted(
                "repository metadata exceeds its size limit".into(),
            ));
        }
        validate_directory_name(&self.root, ".xtrace", &self.directory)?;
        let random = uuid::Uuid::now_v7().simple().to_string();
        let temporary_name = format!(".xtrace-{random}.tmp");
        let file = open_at(
            &self.directory,
            &temporary_name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?;
        let initial = validate_file(&file, &self.directory, &temporary_name)?;
        if fs::fchmod(&file, Mode::from_bits_truncate(0o600)).is_err() {
            if self.remove_owned(&temporary_name, &file).is_err() {
                return Err(CliError::StoreUnavailable(
                    "repository metadata cleanup is uncertain".into(),
                ));
            }
            return Err(io_error("secure new repository metadata"));
        }
        let result = (|| {
            (&file).write_all(bytes).map_err(|_| io_error("write repository metadata"))?;
            check_budget(self.started)?;
            file.sync_all().map_err(|_| io_error("sync repository metadata"))?;
            let current = file.metadata().map_err(|_| io_error("inspect repository metadata"))?;
            validate_metadata(&current)?;
            ensure_same(&initial, &current)?;
            ensure_name_matches(&self.directory, &temporary_name, &current)?;
            fs::renameat_with(
                &self.directory,
                &temporary_name,
                &self.directory,
                name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| {
                CliError::StoreUnavailable(
                    "repository metadata already exists or could not be published".into(),
                )
            })?;
            self.directory
                .sync_all()
                .map_err(|_| io_error("sync repository metadata directory"))?;
            validate_directory_name(&self.root, ".xtrace", &self.directory)?;
            check_budget(self.started)
        })();
        if result.is_err() {
            match open_at(
                &self.directory,
                &temporary_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(named) => match named.metadata() {
                    Ok(metadata) if same_identity(&initial, &metadata) => {
                        if fs::unlinkat(&self.directory, &temporary_name, AtFlags::empty()).is_err()
                        {
                            return Err(CliError::StoreUnavailable(
                                "repository metadata cleanup is uncertain".into(),
                            ));
                        }
                    }
                    Ok(_) => {
                        return Err(CliError::StoreUnavailable(
                            "repository metadata ownership changed during cleanup".into(),
                        ));
                    }
                    Err(_) => {
                        return Err(CliError::StoreUnavailable(
                            "repository metadata cleanup is uncertain".into(),
                        ));
                    }
                },
                Err(CliError::ProjectDirectoryMissing(_)) => {}
                Err(_) => {
                    return Err(CliError::StoreUnavailable(
                        "repository metadata cleanup is uncertain".into(),
                    ));
                }
            }
        }
        result
    }

    pub(crate) fn remove_owned(&self, name: &str, expected: &File) -> Result<(), CliError> {
        validate_directory_name(&self.root, ".xtrace", &self.directory)?;
        let metadata =
            expected.metadata().map_err(|_| io_error("inspect owned repository metadata"))?;
        validate_metadata(&metadata)?;
        ensure_name_matches(&self.directory, name, &metadata)?;
        fs::unlinkat(&self.directory, name, AtFlags::empty())
            .map_err(|_| io_error("remove owned repository metadata"))?;
        self.directory.sync_all().map_err(|_| io_error("sync repository metadata directory"))?;
        validate_directory_name(&self.root, ".xtrace", &self.directory)
    }

    pub(crate) fn open_owned(&self, name: &str) -> Result<File, CliError> {
        let file = open_at(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        validate_file(&file, &self.directory, name)?;
        Ok(file)
    }
}

pub(crate) fn read_unlocked(
    repo: &Path,
    name: &str,
    cap: usize,
) -> Result<Option<Vec<u8>>, CliError> {
    let started = Instant::now();
    let repo_file = open_directory(repo)?;
    let directory = open_existing_directory(&repo_file, ".xtrace")?;
    let result = read_at(&directory, name, cap, started)?;
    validate_directory_name(&repo_file, ".xtrace", &directory)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn repo() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).expect("repo");
        (temp, repo)
    }

    #[test]
    fn pointer_read_refuses_symlink_and_hardlink_targets() {
        let (_temp, repo) = repo();
        let lock = RepositoryInitLock::acquire(&repo).expect("lock");
        let outside = repo.join("outside");
        std::fs::write(&outside, b"secret").expect("outside file");
        symlink(&outside, repo.join(".xtrace/config.toml")).expect("symlink");
        assert!(read_unlocked(&repo, "config.toml", POINTER_MAX_BYTES).is_err());
        std::fs::remove_file(repo.join(".xtrace/config.toml")).expect("remove symlink");
        std::fs::hard_link(&outside, repo.join(".xtrace/config.toml")).expect("hardlink");
        assert!(lock.read("config.toml", POINTER_MAX_BYTES).is_err());
    }

    #[test]
    fn pointer_read_refuses_fifo_without_waiting_for_a_writer() {
        let (_temp, repo) = repo();
        let lock = RepositoryInitLock::acquire(&repo).expect("lock");
        fs::mkfifoat(&lock.directory, "config.toml", Mode::from_bits_truncate(0o600))
            .expect("fifo");
        assert!(lock.read("config.toml", POINTER_MAX_BYTES).is_err());
    }

    #[test]
    fn pointer_read_refuses_a_symlinked_metadata_directory() {
        let (_temp, repo) = repo();
        let outside = repo.join("outside");
        std::fs::create_dir(&outside).expect("outside directory");
        symlink(&outside, repo.join(".xtrace")).expect("metadata directory symlink");
        assert!(read_unlocked(&repo, "config.toml", POINTER_MAX_BYTES).is_err());
        assert!(RepositoryInitLock::acquire(&repo).is_err());
    }

    #[test]
    fn cooperative_init_lock_serializes_writers() {
        let (_temp, repo) = repo();
        let first = RepositoryInitLock::acquire(&repo).expect("first lock");
        let second_repo = repo.clone();
        let waiter = std::thread::spawn(move || RepositoryInitLock::acquire(&second_repo));
        std::thread::sleep(Duration::from_millis(20));
        drop(first);
        assert!(waiter.join().expect("join").is_ok());
    }

    #[test]
    fn serialized_pointer_read_is_capped_before_parsing() {
        let (_temp, repo) = repo();
        let lock = RepositoryInitLock::acquire(&repo).expect("lock");
        let body = vec![b'x'; POINTER_MAX_BYTES + 1];
        lock.publish("oversized", &body, POINTER_MAX_BYTES + 1).expect("test publication");
        assert!(lock.read("oversized", POINTER_MAX_BYTES).is_err());
    }
}

fn read_at(
    directory: &File,
    name: &str,
    cap: usize,
    started: Instant,
) -> Result<Option<Vec<u8>>, CliError> {
    let file = match open_at(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(CliError::ProjectDirectoryMissing(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let before = validate_file(&file, directory, name)?;
    if before.len() > cap as u64 {
        return Err(CliError::StoreCorrupted("repository metadata exceeds its size limit".into()));
    }
    let mut bytes = Vec::with_capacity((before.len() as usize).min(cap));
    let mut limited = file.take((cap + 1) as u64);
    limited.read_to_end(&mut bytes).map_err(|_| io_error("read repository metadata"))?;
    check_budget(started)?;
    if bytes.len() > cap {
        return Err(CliError::StoreCorrupted("repository metadata exceeds its size limit".into()));
    }
    let after =
        limited.get_ref().metadata().map_err(|_| io_error("inspect repository metadata"))?;
    validate_metadata(&after)?;
    ensure_same(&before, &after)?;
    if after.len() != bytes.len() as u64 {
        return Err(CliError::StoreCorrupted("repository metadata changed during read".into()));
    }
    ensure_name_matches(directory, name, &after)?;
    Ok(Some(bytes))
}

fn open_directory(path: &Path) -> Result<File, CliError> {
    let fd = fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| io_error("open repository directory"))?;
    let file = File::from(fd);
    if !file.metadata().map_err(|_| io_error("inspect repository directory"))?.is_dir() {
        return Err(CliError::StoreCorrupted("repository path is not a directory".into()));
    }
    Ok(file)
}

fn open_existing_directory(parent: &File, name: &str) -> Result<File, CliError> {
    let file = open_at(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if !file.metadata().map_err(|_| io_error("inspect repository metadata directory"))?.is_dir() {
        return Err(CliError::StoreCorrupted("repository metadata path is not a directory".into()));
    }
    let named_fd = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| io_error("revalidate repository metadata directory"))?;
    let named = File::from(named_fd);
    let file_metadata =
        file.metadata().map_err(|_| io_error("inspect repository metadata directory"))?;
    let named_metadata =
        named.metadata().map_err(|_| io_error("revalidate repository metadata directory"))?;
    ensure_same(&file_metadata, &named_metadata)?;
    Ok(file)
}

fn validate_directory_name(parent: &File, name: &str, directory: &File) -> Result<(), CliError> {
    let named = open_existing_directory(parent, name)?;
    let directory_metadata =
        directory.metadata().map_err(|_| io_error("inspect repository metadata directory"))?;
    let named_metadata =
        named.metadata().map_err(|_| io_error("revalidate repository metadata directory"))?;
    ensure_same(&directory_metadata, &named_metadata)
}

fn open_or_create_directory(parent: &File, name: &str) -> Result<File, CliError> {
    let created = match fs::mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
        Ok(()) => true,
        Err(error) if error == rustix::io::Errno::EXIST => false,
        Err(_) => return Err(io_error("create repository metadata directory")),
    };
    if created {
        parent.sync_all().map_err(|_| io_error("sync repository directory"))?;
    }
    let directory = open_existing_directory(parent, name)?;
    if created {
        fs::fchmod(&directory, Mode::from_bits_truncate(0o700))
            .map_err(|_| io_error("secure new repository metadata directory"))?;
    }
    Ok(directory)
}

fn open_at(parent: &File, name: &str, flags: OFlags, mode: Mode) -> Result<File, CliError> {
    let fd = fs::openat(parent, name, flags, mode).map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            CliError::ProjectDirectoryMissing("repository metadata is missing".into())
        } else {
            CliError::StoreCorrupted("repository metadata path is unsafe or unavailable".into())
        }
    })?;
    Ok(File::from(fd))
}

fn validate_file(file: &File, directory: &File, name: &str) -> Result<std::fs::Metadata, CliError> {
    let metadata = file.metadata().map_err(|_| io_error("inspect repository metadata"))?;
    validate_metadata(&metadata)?;
    ensure_name_matches(directory, name, &metadata)?;
    Ok(metadata)
}

fn validate_metadata(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(CliError::StoreCorrupted(
            "repository metadata must be a single-link regular file".into(),
        ));
    }
    Ok(())
}

fn ensure_name_matches(
    directory: &File,
    name: &str,
    metadata: &std::fs::Metadata,
) -> Result<(), CliError> {
    let named = open_at(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let named_metadata =
        named.metadata().map_err(|_| io_error("inspect repository metadata name"))?;
    ensure_same(metadata, &named_metadata)
}

fn ensure_same(left: &std::fs::Metadata, right: &std::fs::Metadata) -> Result<(), CliError> {
    if same_identity(left, right) {
        Ok(())
    } else {
        Err(CliError::StoreCorrupted("repository metadata changed during validation".into()))
    }
}

fn same_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn check_budget(started: Instant) -> Result<(), CliError> {
    if started.elapsed() > BUDGET {
        Err(CliError::StoreUnavailable(
            "repository metadata operation exceeded its time budget".into(),
        ))
    } else {
        Ok(())
    }
}

fn io_error(operation: &str) -> CliError {
    CliError::StoreUnavailable(format!("{operation} failed"))
}
