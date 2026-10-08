# ADR 0008: Private-storage admission policy

- Status: Accepted (root decision 2026-10-08, ordered by the owner in S0b after the architecture review finding F1)
- Context: X-trace keeps recordings, the SQLite store, broker material, Java pack
  snapshots and release scratch in local directories that must be readable and
  writable by the owning user only. Every later slice (store, attach, broker per
  ADR 0004, release tooling) trusts one admission policy for "this directory and
  this file are private". The policy was changed four times during S0b to fit real
  hosts and was recorded nowhere. This ADR fixes it. It describes the policy, not
  the crate layout that implements it, so a consolidation of the code does not
  change it.

  Why private storage exists: recordings can contain request data, tokens and
  application state. The store must not be readable, replaceable or blockable by
  another local user or by anything that can redirect a path.

  Threats the policy addresses:
  - other local users reading or writing the directory, or any ancestor of it;
  - POSIX or NFSv4-style ACL entries that grant access the mode bits do not show;
  - symlink and hardlink swaps of a component, of the leaf or of a named file,
    between check and use;
  - mounts that ignore ownership (`noowners`, `MNT_IGNORE_OWNERSHIP`, network or
    FUSE filesystems), where uid and mode say nothing;
  - a FIFO or device planted under a file name, which would block an open
    forever (denial of service);
  - releasing POSIX locks by closing a second descriptor on a live SQLite file.

  Realities found in S0b that shaped the rules:
  - Hosted Linux runners: `/tmp` is mode 1777 (so scratch roots must live under
    a private directory), and `/home` carries an ACL (default ACL on the runner
    image, shown as `+` by `ls`). Walking from `/` with a strict "no ACL anywhere"
    rule refused every root below `/home` (evidence in the S0b Linux CI report).
    The release tooling's Python admission already allowed this layout.
  - macOS external volumes: `ls -ldeO /Volumes` reports the `hidden` flag, which
    the first parser refused, so every root below `/Volumes` failed. ACLs on
    macOS directories commonly appear as deny-only entries.
  - On macOS an unprivileged process has no ACL query without FFI, so ACLs are read
    from `ls -ldeO` output. Each probe is a process spawn, so admission cost grows
    with path depth against a fixed deadline (review finding F3).

## Decision

### Roles

Every directory the policy judges has exactly one of four roles:

- Private leaf: the directory that holds private state. Owned by the current
  user, mode exactly `0700`.
- Traversed component: any ancestor walked from `/` down to the leaf or container.
  Owner is the current user or root; no group or other write bit.
- Container: a managed parent whose children are created as private leaves (for
  example the Java pack snapshot root). Same checks as a traversed component, and
  every child created or opened in it is admitted afresh as a strict private leaf,
  so an inherited ACL on a child fails closed.

- Sealed: a private leaf deliberately made read-only at a fixed mode, `0500` for a
  retained Java pack snapshot. Same owner and ACL rules as the private leaf; the
  mode must equal the sealed mode exactly.

Every admitted directory, whatever its role, must also pass the traversed rule,
because the ancestor walk applies it to the final component too.

Named files inside a private leaf are a separate object, judged as files (below).

### Policy table

All rows apply on every revalidation. "Refuse" means the operation returns the
sanitized `Unavailable` error; no repair of permissions is ever attempted.

| Check | Private leaf / Sealed | Traversed component / container | Named file |
|---|---|---|---|
| Object type | directory, not a symlink | directory, not a symlink | regular file only; FIFO, socket, device, symlink refused |
| Owner | current user | current user or root (uid 0) | current user |
| Mode | exactly `0700` (Sealed: exactly its sealed mode, `0500`) | no `g+w`, no `o+w` | no group or other bits at all |
| Link count | n/a | n/a | ordinary private file: exactly 1; managed immutable object file (hard-linked on purpose for deduplication): at least 1 (0 refused) |
| Filesystem | owner-enforcing local type (see below) | same | same device as the directory |
| Linux ACL (xattr) | any `posix_acl_access` or `posix_acl_default` refused | no ACL admitted; access ACL admitted only if well formed and no entry other than the owning user grants write; any well-formed default ACL admitted | no ACL (path probe) |
| macOS ACL (`ls -ldeO`) | deny-only entries from the fixed vocabulary admitted; any allow entry refused | same as leaf | same as leaf |
| macOS BSD flags | `sunlnk`, `restricted`, `hidden` admitted; any other flag refused | same | same |
| Name syntax | single safe path component | n/a | single safe path component |

Owner-enforcing local filesystems: on Linux ext4 (the ext2/3/4 magic), XFS and
Btrfs for the store and private roots; on macOS `apfs` and `hfs`, and never a mount
flagged `MNT_IGNORE_OWNERSHIP`. Anything else, including network, FUSE, overlay,
tmpfs and unrecognised types, is refused. Decision: the Java attach cache and
snapshot roles will again admit tmpfs (ext4, XFS, Btrfs and tmpfs), restoring their
pre-S0b behaviour, because runtime and temp directories are commonly tmpfs. The
store and the private-state roots stay on the narrower list. The code change has
landed: callers ask for `FilesystemProfile::Ephemeral` explicitly, Java attach's cache,
snapshot, sealed-snapshot and ancestor-walk admission do, and the default stays the
durable list.

Well-formed Linux ACL means: version 2, at most 64 entries, known tags,
permission bits at most 7, undefined ids on unnamed tags, and a user-object entry
present. The default ACL on a traversed directory only shapes future children and
cannot change who may write into the directory itself, so it is validated for
shape only. The leaf is strict because it is the object we create files in.

Why macOS is the same for leaf and traversal: the macOS listing cannot
distinguish access from inherited entries, and deny-only entries cannot grant
anyone access, so one rule covers all roles. Allow entries are refused because they
can grant access the mode bits hide. ACL principals and owner names outside
ASCII letters, digits and `_ . -` fail closed; owner and group names in the
listing use that set, and ACL principal names (`user:` or `group:`, at most 128
bytes) additionally admit `$`. The parser refuses what it cannot classify.

### Walk and descriptor rules

- The path is resolved from `/` one component at a time with no-follow `openat`;
  every component is held as a descriptor. At most 128 components.
- Each component is verified by descriptor identity (device, inode, owner, mode)
  before and after the ACL probe; the identity must also equal the `lstat` of
  the path. Any mismatch, symlink or non-directory refuses.
- A private root is a non-cloneable capability that holds its directory
  descriptor. The whole chain is revalidated before each independent operation
  (read, write, create, rename, remove, sync), not once at open.
- Directory identity compares device, inode, owner and mode. Size is excluded from
  file identity because a live database or WAL grows between probes; a
  size-sensitive identity would refuse a healthy store.
- Descriptor-free validation of named files: validating an existing file that may
  be a live SQLite file uses `statat` without following links, the path-based ACL
  probe, then a second `statat` that must equal the first. It never opens a second
  descriptor, because closing any descriptor on a file releases all POSIX
  (fcntl) locks the process holds on that file. Opening for use goes through the
  non-blocking opener, which refuses FIFOs without waiting for a peer.
- The final directory is judged with its role after the traversed rule, then the
  chain is verified again (before and after, so a swap during the probe is caught).
- Creation is exclusive and uses `0600` files and `0700` directories; existing
  unsafe objects are refused, never chmod-repaired.

### Deadline semantics

- Each public entry point is one operation with one absolute deadline of 750 ms
  (`ADMISSION_BUDGET`), created at entry and passed to every step, including every
  ACL probe in the walk and the directory fsync of a create. N components do not
  get N budgets. Sealed-directory admission of several paths shares one deadline.
- An already-expired deadline refuses before any probe is spawned. Reaching the
  deadline anywhere refuses the operation (fail closed). A timeout refusal is
  indistinguishable from any other refusal and is never retried inside the policy.
- An owned ACL probe process is polled at 1 ms and is killed and reaped when the
  deadline passes. Cleanup has its own bound of 100 ms past the admission deadline;
  if the child cannot be reaped within it the verdict is refuse and the failure is
  reported.

### ACL probe memoization and the batched macOS probe

Memoization (macOS only; Linux probes are two cheap xattr reads and are strict, with
no memo):

- A verdict is remembered inside one operation only and dropped with it. It is never
  carried between operations, threads or processes and never keyed by path alone.
- The key is the directory's state read from the held descriptor: device, inode,
  owner, mode and ctime. Any chmod, chown, ACL or xattr edit, and any child create
  or remove, advances ctime, so a changed directory misses and is probed again.
- On macOS the listing verdict does not depend on the role (the ACL rule is the
  same for every role), so one verdict serves a directory in any role for that
  state within the operation. Role-specific mode and owner rules are still applied
  on every use.
- A verdict is stored only if it was admit and the descriptor state was unchanged
  across the probe. A busy directory is therefore still admitted, but its verdict is
  too old to reuse. Refusals and timeouts are never reused. A hit is additionally
  gated by the usual named-path versus descriptor identity checks.

Batched probe: to bound cost at depth, a walk lists all of its directories with one
`/bin/ls -ldeOi` spawn.

- Any path containing a control character is refused before the spawn. Any
  ambiguity (non-ASCII output, carriage return, a header without a numeric inode,
  an entry that matches no operand or two entries for one operand, a different
  number of entries than operands, output over 512 KiB) discards the whole batch.
- Because `ls` sorts operands, entries are matched to operands by exact trailing
  path (longest match), not by position, and are bound to a directory by (device,
  inode) taken with `lstat` before and after the run.
- A realtime/monotonic consistency check applies: the realtime clock must not go
  backwards and must agree with the monotonic clock over the run to within 50 ms,
  otherwise the batch is dropped.
- A batched listing is used for a directory only if that descriptor's ctime is at
  least 20 ms older than the moment the batch was taken (and not in the future);
  otherwise that directory is probed alone. Each listing is still validated by the
  normal single-directory parser. A discarded batch falls back to per-directory
  probes, never to admission.

### Fail-closed rules

- Unknown platform, unknown filesystem, unparseable ACL listing, unexpected ACL
  vocabulary, a probe that fails to spawn, produces non-UTF-8 output, exits
  non-zero, exceeds its output bound or is killed: refuse.
- A missing xattr (`ENODATA` and equivalent) is "no ACL"; a failing xattr read
  for any other reason is refuse.
- The release tooling's Python admission (`tools/release/private_roots.py`) is
  intended to reach the same verdict as the Rust policy for the same layout on
  Linux. They are not yet tied together by shared golden vectors (a known gap, see
  test obligations).

### Out of scope (explicit non-guarantees)

- A hostile process running as the same user: it can already read and write
  everything the policy protects.
- Privileged actors: root, a privileged remount, a bind mount or overlay installed
  after admission, kernel or filesystem bugs, and replacement of the filesystem
  under a held descriptor.
- Confidentiality against backups, indexers (Spotlight) or snapshot tooling that
  the user runs.
- Time-of-check windows shorter than one operation: the policy revalidates around
  each operation, it does not make a file system transaction.

### Pack snapshot cache (Sealed role in use)

Retained Java pack snapshots are built under a private `.incoming-*` name, fully
verified, sealed to `0500`, and renamed into place. A pack holds a shared per-snapshot
use lease while in use; eviction (oldest unleased snapshot, bound of four retained)
never removes a leased snapshot. Retained snapshots are re-admitted with the Sealed
role under one shared deadline and one memo. A partial incoming directory is residue
and is swept; it is not admitted.

### Known limitations

- The macOS listing parser is ASCII-only: a path containing non-ASCII characters is
  refused (fail closed) on macOS. This predates S0b and is accepted until a native
  ACL query replaces the text oracle.

## Alternatives considered

- Strict "no ACL at all" on every component: rejected. It refuses stock
  GitHub-hosted runners and common home layouts (`/home` default ACL), and macOS
  directories with deny-only ACLs, while giving no extra protection for an
  ancestor that is merely walked and gives no non-owner write.
- Ignoring ACLs on ancestors entirely and checking only mode: rejected. A named
  write grant in an access ACL is exactly the access the mode bits hide.
- The native macOS ACL API (`acl_get_fd_np`, `getattrlist` security extension):
  not available without `unsafe`/FFI, which this workspace forbids outside audited
  crates. It would remove the spawn cost and the text parser and remains the
  preferred long-term replacement; the table above would not change.
- A per-process TTL cache for system ancestors (`/`, `/Users`, `/Volumes`):
  rejected for now. It would carry a verdict across operations and across a
  remount; per-operation memoization gives most of the saving without that.
- A CI-only relaxation: rejected for the same reason as in ADR 0007; a weaker rule
  in one place makes receipts from different hosts incomparable. The CI fix is to
  place scratch under a private directory, not to relax the product.
- Opening files to validate them (fstat plus ACL query on the descriptor):
  rejected for live SQLite files because closing the extra descriptor drops the
  process's POSIX locks on that file.
- Admitting only local APFS/ext4: too narrow; XFS, Btrfs and HFS+ are
  owner-enforcing and appear on developer hosts.

## Consequences

- Residual risks accepted: default ACLs on ancestors are admitted (a future child
  created there inherits entries, which is why the leaf and container children are
  strict); the `hidden` flag is admitted because it only affects display; an
  ancestor owned by root is trusted; ACL names containing characters outside the
  accepted set make directory-service users with a domain or a space fail closed.
- macOS admission depends on parsing `ls -ldeO` output and spawns a process per
  probed directory per operation. The deadline makes slowness a refusal, not a
  bypass: a loaded machine (Spotlight, SSD wake) can refuse spuriously. Denial of
  service by refusal is acceptable; unsafe admission is not.
- Memoization and batching reduce spawns to roughly one per walk plus one per
  directory that changed recently, but do not remove them. A native query (see
  alternatives) is the long-term fix.
- Linux: under heavy parallel I/O the parent-directory fsync inside
  `create_private_child` dominates the 750 ms budget (about 90 ms on average, 558 ms
  maximum observed). The budget still includes it. The residual is refusal under
  extreme I/O load, which fails closed.
- The batched probe trusts the clock only within the 50 ms and 20 ms tolerances
  above; a root-controlled clock is out of scope.
- The Linux ACL decision uses xattrs read through the held descriptor; filesystems
  without xattr support in the admitted set are treated as having no ACL.
- Every change to this table is a security-contract change and needs its own review
  and an update to this ADR and its tests.

## Test obligations

Existing:
- Policy-table tests over the pure policy functions (owner, mode, Linux ACL bytes,
  macOS listing text, filesystem type, flags, roles including Sealed).
- Real-entry-point tests: admission through the public operations, including a
  default ACL (and a read-only named-user ACL) admitted on a walked component and
  refused as the private leaf, writable named-user refused, symlink replacement of
  an ancestor, FIFO refused without waiting, hardlink refused, and an unsupported
  container unable to create private files.
- Probe-count and spawn-count tests: each distinct directory state is probed once
  per operation, nothing is reused across operations, and a walk spawns one batched
  `ls`.
- Expired-deadline test: an expired deadline refuses before any probe; a stuck
  owned probe is reaped within its cleanup bound.
- Tricky-name test against the real `ls` (spaces, prefix chains, unusual
  characters) for the batch splitter.
- Batch-binding tests (inode and device mismatch, ctime quiet period, clock step).
- POSIX-lock-survival test: a lock held on a file survives name-based validation.
- Runner-shape default-ACL test on a real filesystem.

Gaps (not yet covered):
- Shared Python and Rust golden vectors (listing text to verdict) for
  `tools/release/private_roots.py`.
- Named-file rows in the policy table (file owner, mode, link count, ACL) are not
  yet pinned as a table; they are covered only by the real-entry-point tests.
