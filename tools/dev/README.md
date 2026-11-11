# Local agent tools

Run these Bash scripts from the worktree on macOS or Linux. They need Python 3 and Git, not just, sccache, or shellcheck.

Set two machine-local variables before use:

```bash
export XTRACE_DEV_CACHE=<cache-root>
export XTRACE_DEV_SCRATCH=<short-scratch-root>
```

Both roots must already exist, belong to you, and have mode 0700. Use absolute
paths on a volume with ownership enabled. Ancestors must belong to you or root
and must not allow group/other writes; system temporary directories are unsafe.
The scratch root must be at most 24 bytes long. Keep the roots separate.

`source tools/dev/env.sh [ID]` exports shared dependency caches, a per-worktree
Cargo target directory, and private test scratch (bash or zsh; it does not change shell options).
IDs: lowercase `[a-z0-9-]` basename (first 7 chars, trailing `-` stripped, `wt` if empty) + `-` + 4 SHA-256 hex chars.
Hash the canonical worktree path; explicit IDs hash the string, or realpath for existing absolute paths.
Set `XTRACE_DEV_VERBOSE=1` to print exports.
Rustup keeps its existing toolchain; only Cargo's registry/git cache moves.
When sccache is available, it becomes the compiler wrapper with a 40G cache.
Run **prep outside the sandbox**, with network access, before starting agents:

```bash
tools/dev/prep.sh --adapters --browsers
```

Prep fetches locked Cargo dependencies, installs both npm workspaces, and
resolves Java dependencies with strict verification. `--adapters` builds Node,
Java distributions and test classes, and checks the built viewer against its
committed embedded assets. `--browsers` installs Playwright Chromium.
CLI integration tests on GitHub need these artifacts.

Run **compile-only checks inside the sandbox**. Tests run on GitHub:

```bash
tools/dev/check.sh rust:xtrace-domain
tools/dev/check.sh rust:xtrace-cli:doctor_journey
tools/dev/check.sh java:attach-helper
tools/dev/check.sh node
tools/dev/check.sh web
tools/dev/check.sh py:tools.dev.test_dev_tools
tools/dev/check.sh fmt
tools/dev/check.sh diff
```

`check.sh help` lists parts. Commands are printed and the first failure stops
the script. Rust runs cargo check and clippy, or compiles a named test with
`--no-run`. Java compiles main and test sources with strict verification. Node
checks generation and types. Web checks types and contrast; `web:<file>` is
rejected. Python compiles source without writing bytecode: `py:a.b` selects
`a/b.py`, or `a/b/__init__.py` for a regular package. For a namespace package
without an initializer, it compiles the immediate `.py` files in the directory.
A missing module or empty namespace package is an error. Network is for lockfile fetches
only; new or upgraded dependencies require a ticket.

`tools/dev/clean.sh` previews orphan removal; `--apply` deletes orphans, never active worktree entries.
`--keep-days N` retains orphans with any mtime within N days (default 0: remove all orphans).
Only cache `target/*` and scratch `*` entries are eligible.
Symlinks and nested mounts are refused before deletion.
Dependency caches stay intact; cache maintenance commands are suggestions only.

Before release, the owner runs `bash tools/dev/macos-release-check.sh` on a Mac
from a clean checkout after prep. This is the local test exception from the
2026-11-11 owner decision (W2-R27a); normal agent checks remain compile-only.
The script header lists prerequisites. It runs release tooling, Node and web on
both Node 22 and 24, Java tests on locally installed JDKs 17/21/25, Rust workspace tests, release
diagnostic guards, and the arm64 package journey. It continues after a suite
fails and prints each suite's exit code. Private logs stay in a new scratch
directory. Exit 1 means a suite failed; exit 2 means coverage is incomplete.
Node discovery checks every absolute PATH directory and Homebrew's versioned
bin directories. Set `XTRACE_NODE_22_BIN` and `XTRACE_NODE_24_BIN` to select
other directories containing executable `node` and `npm` commands. Each override
must report the matching Node major version. Each suite records its full Node
version; each unavailable version is a named Node and web coverage gap.
Missing JDKs, an unsupported package architecture, and the hosted-only
other-UID check are named gaps. The manual macOS workflow retains the
other-UID check; the local script alone cannot certify it.
Hosted `macos.yml` now runs only on manual dispatch; Linux `ci-ok` gates development.
