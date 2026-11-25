//! Spawn counter for the `/bin/ls` probe, compiled only with the `spawn-counter` feature.
//!
//! Lane tests enable it through `[dev-dependencies]`, so release builds never contain it.

use std::cell::Cell;

thread_local! {
    static LS_SPAWNS: Cell<u64> = const { Cell::new(0) };
}

/// Number of `/bin/ls` probes started by the calling thread since it began.
#[must_use]
pub fn ls_spawns_on_this_thread() -> u64 {
    LS_SPAWNS.with(Cell::get)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "only the macOS probe spawns"))]
pub(crate) fn record_ls_spawn() {
    LS_SPAWNS.with(|count| count.set(count.get() + 1));
}

#[cfg(target_os = "linux")]
thread_local! {
    static LINUX_ACL_PROBES: Cell<Option<[u64; 3]>> = const { Cell::new(None) };
}

/// Linux ACL syscall attempts on this thread, by directory, named file and file descriptor.
#[cfg(target_os = "linux")]
pub fn set_linux_acl_probe_counting(enabled: bool) {
    LINUX_ACL_PROBES.with(|counts| counts.set(enabled.then_some([0; 3])));
}

/// Snapshot enabled Linux ACL syscall counters.
#[cfg(target_os = "linux")]
pub fn linux_acl_probe_counts() -> Option<[u64; 3]> {
    LINUX_ACL_PROBES.with(Cell::get)
}

#[cfg(target_os = "linux")]
pub(crate) enum LinuxAclProbe {
    Directory,
    NamedFile,
    DescriptorFile,
}

#[cfg(target_os = "linux")]
pub(crate) fn record_linux_acl_probe(probe: LinuxAclProbe) {
    LINUX_ACL_PROBES.with(|counts| {
        if let Some(mut current) = counts.get() {
            let count = &mut current[probe as usize];
            *count = count.saturating_add(1);
            counts.set(Some(current));
        }
    });
}
