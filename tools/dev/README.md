# Local agent tools

Run these Bash scripts from the worktree. They support macOS and Linux and
need Python 3 and Git. They do not need just, sccache, or shellcheck.

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
Cargo target directory, and private test scratch (bash or zsh; it does not
change shell options). IDs come from the worktree basename via `devid.py`:
lowercased, other characters replaced by hyphens; names over 12 characters keep
a 7-character prefix plus a 4-character hash, so sibling worktrees never share
a directory. Cleanup recognizes basename IDs only. Set `XTRACE_DEV_VERBOSE=1` to print exports.
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
CLI integration tests need these artifacts; most local work needs only units.

Run **checks inside the sandbox**, offline:

```bash
tools/dev/check.sh rust:xtrace-core
tools/dev/check.sh rust:xtrace-cli:java_synthetic_adapter
tools/dev/check.sh java:attach-helper 'dev.xtrace.*'
tools/dev/check.sh node
tools/dev/check.sh web:src/App.test.tsx
tools/dev/check.sh py:tools.dev.test_dev_tools
tools/dev/check.sh fmt
tools/dev/check.sh diff
```

`check.sh help` lists parts. Commands are printed and the first failure stops
the script. Rust crate checks compile, run library tests, then run clippy.

`tools/dev/clean.sh` shows disk usage and orphan/old directories without deleting
them. `--apply` deletes them; `--keep-days N` changes the default seven-day age.
Only cache `target/*` and scratch `*` entries are eligible. Even active worktree
entries expire by age. Symlinks and nested mounts are refused before deletion.
Dependency caches stay intact; cache maintenance commands are suggestions only.

Run tool tests with a private temporary base beneath your scratch root:
`TMPDIR="$XTRACE_DEV_SCRATCH" python3 -B -m unittest tools.dev.test_dev_tools`.
