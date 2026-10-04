# ADR 0007: Process provenance classification for builder quiescence

- Status: Accepted (root decision 2026-10-04, pending reviews)
- Context: The release runner proves that nothing it started can still write the
  shared builder caches before it releases the builder leases. After a command
  it scans every process born during the run. On both supported hosts an
  unprivileged scanner cannot read the descriptor table of other users'
  processes, so such a process is an "uninspectable" unknown that must exit
  within one absolute 120 s settle window or the run fails closed. The real
  focused run of commit 1cc05a9 on macOS hit this: 67 other-user launchd
  daemons (amfid, spindump, mdworker_shared, securityd_system, nfcd,
  MTLCompilerService and others) were spawned by the system during the run, the
  identity union exceeded its 64-record bound, the settle failed, and both
  leases were retained for manual recovery although nothing in the run's own
  process tree was involved. On Linux, `/proc/<pid>/fd` of root-owned processes
  and kernel threads is unreadable to the `runner` user (readdir needs ptrace
  read access), so hosted runners have the same defect.

## Decision

An uninspectable identity is positively classified as a non-descendant of the
run by provenance: a structural fact about how the process came to exist, read
without privilege. This is not a UID or process-name exemption: the same user
and the same executable name can be classified or not, depending only on
provenance.

macOS. At command start the runner records its own resource coalition id
(`proc_pidinfo(PROC_PIDCOALITIONINFO)` through ctypes) and the command root's.
Coalition membership is inherited across fork and exec and survives
reparenting to launchd. An uninspectable identity whose coalition id is readable
(read twice, equal) and differs from every recorded run coalition is classified
`non-descendant-coalition`. Unreadable, inconsistent, or equal coalition ids
(for example a setuid exec from our tree or an unrelated process of the same
application) stay uncertain. At classification time the start time is re-read
through a separate `ps` call and must equal the scan identity, and the process
must still be live and not owned in a fresh snapshot, so PID reuse cannot be
classified.

Linux. For the lifetime of each command the runner is a child subreaper
(`prctl(PR_SET_CHILD_SUBREAPER, 1)` through ctypes, verified with
`PR_GET_CHILD_SUBREAPER`, cleared afterwards). Orphaned descendants therefore
reparent to the runner and keep a parent chain that reaches it. The runner
records every identity (pid and start time) whose chain reaches it. An
uninspectable identity that was never in that set, whose parent chain does not
reach the runner in two independent snapshots, and whose start time is consistent
is classified `non-descendant-subreaper`. Orphans that reparent to the runner and
persist for 0.5 s are adopted into the owned set and follow the existing
owned-tree drain rules; their zombies, and only those, are reaped. Nothing is
ever signaled that is not owned. If `prctl` fails, nothing is classified.

All existing bounds and fail-closed rules stay: 64 identity samples, the 64 KiB
and 512-node owner record, one absolute 120 s settle budget that is never reset,
and two full quiet scans after the latest uncertainty. Classified identities do
not block settling but are recorded in the receipt with their classification and
evidence (pid, start time, same/other user class, coalition ids), bounded to 64
samples with a truthful total and truncation flag. A descendant-set overflow, an
unavailable mechanism, or an unsupported platform disables classification and the
run behaves exactly as before.

## Alternatives considered

- Privileged inspection (sudo lsof, endpoint security, a helper daemon): rejected.
  It requires authorization the owner has not granted, widens the trusted
  computing base, is unavailable to ordinary CI runs, and was explicitly
  forbidden.
- A UID or process-name rule (ignore root or Apple or system processes):
  rejected. An inheriting child can change UID (setuid exec), names are
  attacker-controlled, and earlier floors showed that other-UID processes were
  once the only evidence of a real leftover.
- A CI-only relaxation: rejected. The failure that blocked the local floor is a
  host property, not a CI one, and a weaker rule in one place would make receipts
  from different hosts incomparable.
- Waiting longer or raising the 120 s window or the 64-record bound: rejected;
  daemons that never exit would still fail and the bounds are safety limits.

## Consequences

- Foreign launchd, kernel and system processes no longer block quiescence, so
  real runs and the real-scanner tests can pass on a busy host.
- Provenance proves non-descent in the fork tree, not that a process cannot write the
  builder caches. The residual is work that reaches the caches without being a descendant:
  launchd or XPC activation, LaunchServices (`open`), `launchctl submit`, `osascript`,
  `systemd-run` and D-Bus activation, `at` and cron, Docker (a daemon or VM runs it; the Linux
  runner user is in the docker group), persistent build daemons that outlive a run (Gradle,
  sccache, Bazel servers), ptrace injection into a non-descendant, and setuid exec, which
  keeps ancestry but defeats descriptor inspection (such a process stays uncertain because it
  is a descendant).
- These routes are out of the threat model only because the callers are constrained, not
  because provenance covers them: `leased_run` enforces an argv[0] basename allowlist (cargo,
  gradlew, npm, npx, node, git, java, and python only as `-B -m unittest` or
  `-B -m tools.release.*`) and refuses shells and launchers (open, launchctl, osascript,
  docker, systemd-run, at, sh) with exit code 77; builders run with `--no-daemon`; the 23
  gates contain no launcher. A pre-existing daemon is outside the baseline. Receipts record
  this residual as `provenanceResidual`. Adding a command or a gate that delegates work
  needs its own review.
- A leased run gets a private HOME inside its admitted scratch and an allowlisted environment;
  `--pass-env` refuses names that load code or redirect the build (LD_*, DYLD_*, NODE_OPTIONS,
  PYTHONPATH, JAVA_TOOL_OPTIONS, BASH_ENV, RUSTC_WRAPPER, RUSTFLAGS, CARGO_*, GIT_*, *_PROXY and
  similar); the host HOME is passed only by an explicit `--pass-env HOME`, recorded in the receipt.
- On Linux every live non-baseline direct child of the runner except its own registered
  ps/lsof helpers is adopted into the owned set at once (no grace period), so a daemon that
  escapes just before the command root exits is drained or fails closed, never classified.
- On macOS the coalition flavor of `proc_pidinfo` is declared in SDK headers but is
  not a documented stable API; XPC services and LaunchServices apps get their own
  coalitions, so they are classified non-descendant even when started on our
  behalf. This is the delegated-work residual above.
- The mechanism is process-wide state on Linux (the subreaper flag) and is enabled
  only for supervised runs that ask for it (the floor CLI and `leased_run`).

## Test obligations

- Fakes for every syscall and for `ps`: classification success, unreadable,
  equal coalition, inconsistent reads, PID reuse, unreadable run coalition,
  prctl failure, descendant-set overflow, orphan adoption timing, zombie reaping,
  evidence bounds, and unsupported platforms.
- Scanner and run-level tests proving classified identities leave the blocking
  list while unclassified ones still fail closed at the deadline.
- One real-host test per OS that observes (own descendants are never classified,
  the subreaper flag is cleared) and is allowed to skip classification but never to
  fail open.
- Receipts (floor and `leased_run`) carry the evidence; the sanitizer is unchanged.
