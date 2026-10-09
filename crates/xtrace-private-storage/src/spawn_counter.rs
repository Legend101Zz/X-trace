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
