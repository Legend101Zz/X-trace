# Local security model (v0.0.1)

Status: lane P draft, grounded in the code at this commit. Every claim names where it is enforced or says it is not
proven yet. Normative detail for storage is ADR 0008; this page is the user-facing summary and the limits.

## What X-trace protects

Recordings can contain request data, tokens and application state. The goal is that, on a supported host, only the
owning OS user (and the processes that user starts) can read, replace or block the recordings, and that nothing is
reachable from another machine.

* **Loopback only.** The daemon binds `127.0.0.1` (or `::1`); non-loopback bind addresses are rejected at
  construction (`crates/xtrace-daemon/src/config.rs`, `LoopbackPolicy`). There is no remote mode in v0.0.1.
* **Private storage.** The project data root and the files in it are admitted by `xtrace-private-storage`: owner is
  the current user, mode exactly `0700` for directories, owner-only files, no extra ACL entries on the private leaf
  (Linux POSIX ACLs; macOS `ls -ldeO` listing), ancestors owned by the user or root and not group/other writable,
  symlink/hardlink swaps and FIFO/device planting detected, ownership-ignoring mounts refused (ADR 0008).
* **Identity before signalling.** `xtrace stop` and `restart` signal only the PID recorded in
  `<project data root>/.daemon/daemon.json` (0600), and only after the process start time (`ps -o lstart=`), the
  executable path and the `daemon` command line all match what `xtrace record` stored. A PID that fails the check
  is never signalled; a daemon holding the project lock that `record` did not start is refused. The tool never
  signals by process name or pattern and never escalates to SIGKILL.
* **No secrets in lifecycle output.** The daemon bootstrap secret is not written to `daemon.json` or printed by
  `record`/`stop`/`restart` (asserted in `crates/xtrace-cli/tests/lifecycle_journey.rs`). The one-shot bootstrap
  file lives under the private root.
* **Packs are located by executable path, not trusted by location.** Installed packs are discovered relative to the
  executable only (never environment variables or the working directory; `pack_discovery.rs`). Admission of a
  discovered pack into `xtrace run` is NOT wired yet and the trust table is empty, so nothing can be reported as
  verified; v0.0.1 ships no release signing key and every packaged pack is marked non-release (`docs/packaging.md`).

## Where state lives

| Platform | Data home (override with `XTRACE_DATA_HOME`) |
|---|---|
| macOS | `~/Library/Application Support/xtrace` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/xtrace` |

Per project: `projects/<project_id>/{metadata.sqlite3, objects/**, runtime/**, exports/**, .daemon/**}`. The installer
never creates or deletes the data home, and uninstall leaves it and the pre-upgrade `backups/` untouched.
(The authoritative state-surface list for the canary crawler is shared with lane C and lands with that work.)

## Not supported (the tool refuses rather than guessing)

* Windows and any non-Unix host: private-storage admission is Unix-only; lifecycle commands return
  `DaemonUnsupportedPlatform`, `doctor` reports `unavailable`.
* Data homes on NFS/SMB/FUSE or `noowners`/ownership-ignoring mounts: uid and mode say nothing there, so admission
  fails closed.
* A data home reached through a symlinked path component: refused (on macOS use the physical path, not `/var` ->
  `/private/var`).
* A `ps` that lacks `-o lstart=`/`-o command=` (BusyBox): lifecycle commands fail with
  `XTR-LIFECYCLE-IDENTITY-UNAVAILABLE` and change nothing.

## What is NOT protected

* **Same-user malware or any process running as you.** It can read the data home and the bootstrap file. Local
  permissions are the only boundary; there is no encryption at rest in v0.0.1.
* **Root.** Admission trusts root-owned ancestors.
* **Events not yet written to a segment when the daemon stops.** `stop` seals open recordings as partial but
  in-memory staged events are lost until the daemon flushes on shutdown (request P-002 item 4). This is a data-loss
  limit, not a confidentiality one.
* **Capture depth.** `record --capture-depth` is accepted and reported but not yet enforced
  (`capture_depth_enforced: false`).

## Known measurement gaps (honest status)

* Offline proof (no network egress during a full journey) and the permission audit over every created path are not
  built yet; the negative matrix for the viewer lives with lane Q.
* `xtrace doctor` checks private-storage admission, the daemon lock, store schema (older schema = warning, newer or
  unreadable = failure), recordings left open, and pack discovery. A full SQLite integrity and object-hash scan,
  the sanitized support bundle (`--bundle`, exits 9) and retention are not implemented.
* The daemon-lock probe is a momentary try-lock: a daemon start overlapping the probe can see a spurious
  "already running", and the probe creates `.daemon/project.lock` on a project that never ran a daemon.
