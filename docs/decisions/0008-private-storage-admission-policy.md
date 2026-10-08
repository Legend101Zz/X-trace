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

Every directory the policy judges has exactly one role:

- Private leaf: the directory that holds private state. Owned by the current
  user, mode exactly `0700`.
- Traversed component: any ancestor walked from `/` down to the leaf or container.
  Owner is the current user or root; no group or other write bit.
- Container: a managed parent whose children are created as private leaves (for
  example the Java pack snapshot root). Same checks as a traversed component, and
  every child created or opened in it is admitted afresh as a strict private leaf,
  so an inherited ACL on a child fails closed.

Named files inside a private leaf are a fourth object, judged as files (below).

### Policy table

All rows apply on every revalidation. "Refuse" means the operation returns the
sanitized `Unavailable` error; no repair of permissions is ever attempted.

| Check | Private leaf | Traversed component / container | Named file |
|---|---|---|---|
| Object type | directory, not a symlink | directory, not a symlink | regular file only; FIFO, socket, device, symlink refused |
| Owner | current user | current user or root (uid 0) | current user |
| Mode | exactly `0700` | no `g+w`, no `o+w` | no group or other bits at all |
| Link count | n/a | n/a | exactly 1 (hardlink refused) |
| Filesystem | owner-enforcing local type | owner-enforcing local type | same device as the directory |
| Linux ACL (xattr) | any `posix_acl_access` or `posix_acl_default` refused | no ACL admitted; access ACL admitted only if well formed and no entry other than the owning user grants write; any well-formed default ACL admitted | no ACL (path probe) |
| macOS ACL (`ls -ldeO`) | deny-only entries from the fixed vocabulary admitted; any allow entry refused | same as leaf | same as leaf |
| macOS BSD flags | `sunlnk`, `restricted`, `hidden` admitted; any other flag refused | same | same |
| Name syntax | single safe path component | n/a | single safe path component |

Owner-enforcing local filesystems: on Linux the ext2/3/4, XFS and Btrfs types; on
macOS `apfs` and `hfs`, and never a mount flagged `MNT_IGNORE_OWNERSHIP`. Anything
else, including network, FUSE, overlay-unknown and unrecognised types, is refused.

Well-formed Linux ACL means: version 2, at most 64 entries, known tags,
permission bits at most 7, undefined ids on unnamed tags, and a user-object entry
present. The default ACL on a traversed directory only shapes future children and
cannot change who may write into the directory itself, so it is validated for
shape only. The leaf is strict because it is the object we create files in.

Why macOS is the same for leaf and traversal: the macOS listing cannot
distinguish access from inherited entries, and deny-only entries cannot grant
anyone access, so one rule covers all roles. Allow entries are refused because they
can grant access the mode bits hide. ACL principals and owner names outside
`[A-Za-z0-9_.-]` fail closed (the parser refuses what it cannot classify).

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
- Creation is exclusive and uses `0600` files and `0700` directories; existing
  unsafe objects are refused, never chmod-repaired.

### Deadline semantics

- One admission operation has one absolute deadline of 750 ms (`ADMISSION_BUDGET`),
  created at operation start and passed to every step, including every ACL probe
  in the walk. N components do not get N budgets.
- Reaching the deadline anywhere refuses the operation (fail closed). A refusal
  from timeout is indistinguishable from any other refusal and is never retried
  silently inside the policy.
- An owned ACL probe process is polled at 1 ms and is killed and reaped when the
  deadline passes. Cleanup has its own bound of 100 ms past the admission deadline;
  if the child cannot be reaped within it the verdict is refuse and the failure is
  reported.

### ACL probe memoization

On macOS, probe verdicts may be reused only within one admission operation, and
only for a directory whose identity is unchanged. The key is
(device, inode, owner, mode) taken from the held descriptor at the time of the
probe. Verdicts are never carried between operations, never stored in a process
global, and never keyed by path alone. A changed key re-probes. The leaf is probed
under the strict-leaf role even when an ancestor with the same identity was
cached under the traversal role (role is part of the verdict). A verdict is cached
only when it is "admit"; a refusal or a timeout is not reused.

### Fail-closed rules

- Unknown platform, unknown filesystem, unparseable ACL listing, unexpected ACL
  vocabulary, a probe that fails to spawn, produces non-UTF-8 output, exits
  non-zero, exceeds its output bound or is killed: refuse.
- A missing xattr (`ENODATA` and equivalent) is "no ACL"; a failing xattr read
  for any other reason is refuse.
- Every public path through the policy, including the release tooling's Python
  admission (`tools/release/private_roots.py`), must reach the same verdict for
  the same layout on Linux. The Python and Rust copies are kept equal by shared
  golden vectors (see test obligations).

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
- Memoization reduces spawns to one per distinct directory per operation but does
  not remove them. A native query (see alternatives) is the long-term fix.
- The Linux ACL decision uses xattrs read through the held descriptor; filesystems
  without xattr support in the admitted set are treated as having no ACL.
- Every change to this table is a security-contract change and needs its own review
  and an update to this ADR and its tests.

## Test obligations

- Policy-table test: one case per row above, per platform, pinning admit or refuse
  (including role: a default ACL admitted on a walked component but refused on the
  leaf; an allow entry refused on macOS at every role; `hidden` admitted and an
  unknown flag refused; a mode 1777 ancestor refused; owner mismatch refused).
- Probe-count test: asserts the number of ACL probe spawns per admission and per
  `create_private_child` on macOS (each distinct directory identity at most once
  per operation, and none reused across two operations).
- POSIX-lock-survival test: hold a POSIX lock on a file, validate it by name, and
  show the lock is still held.
- Runner-shape default-ACL test: a real filesystem directory with a default ACL
  (and a read-only named-user access ACL) is admitted as a traversed component and
  refused as the private leaf; a writable named-user entry is refused in both.
- Refusal tests for FIFO, symlink, hardlink, ancestor replaced by a symlink, and
  unsupported container capability creating files.
- Deadline test: an expired deadline refuses without spawning; a stuck owned probe
  is reaped within its cleanup bound.
- Golden vectors: a shared file of ACL listing text to verdict consumed by both the
  Rust parser tests and the Python admission tests.
