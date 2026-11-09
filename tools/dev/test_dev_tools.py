"""Offline checks for the agent environment, dispatch, and cleanup boundaries."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

from tools.dev.devid import MAX_ID_LENGTH, worktree_id
import unittest
import zlib


SCRIPTS = Path(__file__).resolve().parent


class DevToolsTests(unittest.TestCase):
    """Use disposable Git metadata; never change the checkout's Git state."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devtools-", dir=os.environ.get("XTRACE_DEV_TEST_ROOT")
        )
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.cache = self.base / "cache"
        self.cache.mkdir(mode=0o700)
        self.scratch = self.base / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.repo = self.base / "Main_Repo"
        self.repo.mkdir()
        self.git("init", "--quiet", str(self.repo))
        # A minimal synthetic fixture commit avoids identity config and commit hooks.
        tree = self.git_object("tree", b"")
        commit = self.git_object(
            "commit",
            f"tree {tree}\nauthor Test <test@example.invalid> 0 +0000\n"
            f"committer Test <test@example.invalid> 0 +0000\n\nfixture\n".encode(),
        )
        (self.repo / ".git" / "refs" / "heads" / "fixture").write_text(commit + "\n")
        (self.repo / ".git" / "HEAD").write_text("ref: refs/heads/fixture\n")
        token = self.base.name.removeprefix("devtools-")[:6]
        self.worktree = self.base / f"T0C_{token}_Long"
        self.git("worktree", "add", "--quiet", "--detach", str(self.worktree))
        self.identifier = worktree_id(str(self.worktree))
        self.environ = os.environ.copy()
        self.environ.update(XTRACE_DEV_CACHE=str(self.cache), XTRACE_DEV_SCRATCH=str(self.scratch))
        self.environ.pop("XTRACE_DEV_VERBOSE", None)

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, check=True, capture_output=True, text=True
        )

    def git_object(self, kind, body):
        data = kind.encode() + b" " + str(len(body)).encode() + b"\0" + body
        digest = hashlib.sha1(data).hexdigest()
        directory = self.repo / ".git" / "objects" / digest[:2]
        directory.mkdir(exist_ok=True)
        (directory / digest[2:]).write_bytes(zlib.compress(data))
        return digest

    def short_scratch(self):
        """Find an existing private short root without writing outside the test base."""
        candidate = Path(os.environ.get("XTRACE_DEV_SCRATCH", self.base))
        for path in (candidate, *candidate.parents):
            if len(os.fsencode(path)) <= 24 and stat.S_IMODE(path.stat().st_mode) == 0o700:
                self.addCleanup(shutil.rmtree, path / self.identifier, True)
                return path
        self.fail("Set TMPDIR or XTRACE_DEV_SCRATCH to an owner-only short root on an ownership-enabled volume")

    def run_script(self, name, *args, env=None):
        return subprocess.run(
            ["bash", str(SCRIPTS / name), *args], cwd=self.worktree,
            env=self.environ if env is None else env, capture_output=True, text=True,
        )

    def source_env(self, env=None, identifier=None):
        command = 'script=$1; shift; source "$script" "$@" && python3 -B -c "import json, os; print(json.dumps(dict(os.environ)))"'
        args = ["bash", "-c", command, "env-test", str(SCRIPTS / "env.sh")]
        if identifier is not None:
            args.append(identifier)
        return subprocess.run(
            args, cwd=self.worktree, env=self.environ if env is None else env,
            capture_output=True, text=True,
        )

    def test_env_rejects_invalid_roots(self):
        valid = dict(self.environ, XTRACE_DEV_SCRATCH=str(self.short_scratch()))
        for name in ("XTRACE_DEV_CACHE", "XTRACE_DEV_SCRATCH"):
            for value in (None, "relative"):
                with self.subTest(name=name, value=value):
                    env = valid.copy()
                    if value is None:
                        env.pop(name, None)
                    else:
                        env[name] = value
                    result = self.source_env(env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(name, result.stderr)
        result = self.source_env(dict(valid, XTRACE_DEV_CACHE=str(self.base / "missing")))
        self.assertNotEqual(result.returncode, 0)
        self.cache.chmod(0o777)
        result = self.source_env(valid)
        self.cache.chmod(0o700)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("writable", result.stderr)
        too_long = self.base / ("x" * 25)
        too_long.mkdir(mode=0o700)
        result = self.source_env(dict(valid, XTRACE_DEV_SCRATCH=str(too_long)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("too long", result.stderr)
        ancestor = self.base / "writable"
        ancestor.mkdir(mode=0o700)
        leaf = ancestor / "private"
        leaf.mkdir(mode=0o700)
        ancestor.chmod(0o777)
        result = self.source_env(dict(valid, XTRACE_DEV_CACHE=str(leaf)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ancestor", result.stderr)

    def test_env_paths_id_and_idempotence(self):
        scratch = self.short_scratch()
        env = dict(self.environ, XTRACE_DEV_SCRATCH=str(scratch))
        expected = {
            "XTRACE_DEV_ID": self.identifier,
            "CARGO_HOME": str(self.cache / "cargo-home"),
            "CARGO_TARGET_DIR": str(self.cache / "target" / self.identifier),
            "GRADLE_USER_HOME": str(self.cache / "gradle"),
            "NPM_CONFIG_CACHE": str(self.cache / "npm"),
            "PLAYWRIGHT_BROWSERS_PATH": str(self.cache / "pw"),
            "SCCACHE_DIR": str(self.cache / "sccache"),
            "SCCACHE_CACHE_SIZE": "40G",
            "TMPDIR": str(scratch / self.identifier / "tmp"),
            "XTRACE_TEST_PRIVATE_SCRATCH": str(scratch / self.identifier / "priv"),
            "XTRACE_TEST_SCRATCH_ROOT": str(scratch / self.identifier / "rel"),
        }
        for _ in range(2):
            result = self.source_env(env)
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = json.loads(result.stdout)
            for name, value in expected.items():
                self.assertEqual(actual[name], value, name)
            for suffix in ("tmp", "priv", "rel"):
                self.assertEqual(stat.S_IMODE((scratch / self.identifier / suffix).stat().st_mode), 0o700)
        env["XTRACE_DEV_VERBOSE"] = "1"
        result = self.source_env(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, value in expected.items():
            self.assertEqual(result.stdout.splitlines().count(f"{name}={value}"), 1)
        # A sanitized traversal attempt is confined to a single safe ID.
        explicit = f"../{self.identifier}"
        safe = worktree_id(explicit)
        self.addCleanup(shutil.rmtree, scratch / safe, True)
        result = self.source_env(env, identifier=explicit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[-1])["XTRACE_DEV_ID"], safe)
        result = self.source_env(env, identifier=str(self.worktree))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[-1])["XTRACE_DEV_ID"], self.identifier)

    def test_env_rejects_linked_root_and_existing_scratch(self):
        scratch = self.short_scratch()
        env = dict(self.environ, XTRACE_DEV_SCRATCH=str(scratch))
        linked_cache = self.base / "linked-cache"
        linked_cache.symlink_to(self.cache, target_is_directory=True)
        result = self.source_env(dict(env, XTRACE_DEV_CACHE=str(linked_cache)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe directory", result.stderr)
        parent = scratch / self.identifier
        parent.mkdir(mode=0o700)
        (parent / "tmp").symlink_to(self.cache, target_is_directory=True)
        result = self.source_env(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe directory", result.stderr)
        (parent / "tmp").unlink()
        (parent / "tmp").mkdir(mode=0o755)
        result = self.source_env(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owner-only", result.stderr)

    def test_sccache_is_optional(self):
        scratch = self.short_scratch()
        env = dict(self.environ, XTRACE_DEV_SCRATCH=str(scratch))
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        executable = bin_dir / "sccache"
        executable.write_text("#!/usr/bin/env bash\nexit 0\n")
        executable.chmod(0o700)
        env["PATH"] = str(bin_dir) + os.pathsep + os.environ["PATH"]
        result = self.source_env(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["RUSTC_WRAPPER"], "sccache")

    def cleanup_entries(self):
        target = self.cache / "target"
        target.mkdir(mode=0o700)
        old_worktree = self.base / "Old_Ticket"
        self.git("worktree", "add", "--quiet", "--detach", str(old_worktree))
        removed_worktree = self.base / "Gone_Ticket"
        self.git("worktree", "add", "--quiet", "--detach", str(removed_worktree))
        self.git("worktree", "remove", str(removed_worktree))
        old_id = worktree_id(str(old_worktree))
        gone_id = worktree_id(str(removed_worktree))
        retained, removable = [], []
        for parent in (target, self.scratch):
            for name in (self.identifier, old_id, gone_id, ".orphan"):
                entry = parent / name
                entry.mkdir(mode=0o700)
                (entry / "canary").write_text("keep or remove only as specified\n")
                if name == old_id:
                    old = time.time() - 10 * 86400
                    os.utime(entry / "canary", (old, old))
                    os.utime(entry, (old, old))
                (retained if name in (self.identifier, old_id) else removable).append(entry)
        shared_cache = self.cache / "cargo-home"
        shared_cache.mkdir(mode=0o700)
        (shared_cache / "canary").write_text("keep\n")
        retained.append(shared_cache)
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (outside / "canary").write_text("keep\n")
        retained.append(outside)
        return retained, removable

    def test_clean_dry_run_preserves_everything(self):
        retained, removable = self.cleanup_entries()
        result = self.run_script("clean.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        for entry in retained + removable:
            self.assertTrue((entry / "canary").exists(), entry)
        for entry in removable:
            self.assertIn(f"Would delete: {entry}", result.stdout)
        self.assertIn("Before:", result.stdout)
        self.assertIn("After:", result.stdout)
        self.assertIn("Suggestion: npm cache verify", result.stdout)

    def test_clean_apply_keeps_old_active_entries_and_removes_orphans(self):
        retained, removable = self.cleanup_entries()
        result = self.run_script("clean.sh", "--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        for entry in removable:
            self.assertFalse(entry.exists(), entry)
            self.assertIn(f"Deleted: {entry}", result.stdout)
        for entry in retained:
            self.assertTrue((entry / "canary").exists(), entry)

    def test_clean_keep_days_uses_newest_deep_orphan_mtime(self):
        retained, removable = self.cleanup_entries()
        recent = []
        old = time.time() - 10 * 86400
        for entry in removable:
            os.utime(entry / "canary", (old, old))
            if entry.name == ".orphan":
                deep = entry / "nested" / "deep"
                deep.mkdir(parents=True)
                (deep / "recent").write_text("recent activity\n")
                os.utime(deep, (old, old))
                os.utime(deep.parent, (old, old))
                recent.append(entry)
            os.utime(entry, (old, old))
        result = self.run_script("clean.sh", "--apply", "--keep-days", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        for entry in retained + recent:
            self.assertTrue((entry / "canary").exists(), entry)
        for entry in recent:
            self.assertTrue((entry / "nested" / "deep" / "recent").exists(), entry)
        for entry in removable:
            if entry not in recent:
                self.assertFalse(entry.exists(), entry)

    def test_clean_refuses_symlinks_before_any_deletion(self):
        retained, removable = self.cleanup_entries()
        for location in (self.scratch / "z-link", removable[0] / "nested-link"):
            with self.subTest(location=location):
                location.symlink_to(retained[-1], target_is_directory=True)
                result = self.run_script("clean.sh", "--apply")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symlink", result.stderr)
                for entry in retained + removable:
                    self.assertTrue((entry / "canary").exists(), entry)
                location.unlink()

    def test_clean_refuses_unsafe_roots_and_target(self):
        for name in ("XTRACE_DEV_CACHE", "XTRACE_DEV_SCRATCH"):
            for value in (None, "/", str(Path.home()), "relative", str(self.base / "..")):
                with self.subTest(name=name, value=value):
                    env = self.environ.copy()
                    if value is None:
                        env.pop(name, None)
                    else:
                        env[name] = value
                    result = self.run_script("clean.sh", "--apply", env=env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("clean.sh:", result.stderr)
        target = self.cache / "target"
        target.symlink_to(self.base, target_is_directory=True)
        result = self.run_script("clean.sh", "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        target.unlink()
        env = dict(self.environ, XTRACE_DEV_SCRATCH=str(self.cache))
        result = self.run_script("clean.sh", "--apply", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-nested", result.stderr)

    def test_check_unknown_part_exits_two(self):
        env = self.environ.copy()
        env.pop("XTRACE_DEV_CACHE", None)
        result = self.run_script("check.sh", "unknown-part", env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)
        self.assertNotIn("env.sh:", result.stderr)

    def test_check_help_lists_no_test_running_part(self):
        result = self.run_script("check.sh", "help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Compile-only", result.stdout)
        for command in ("npm test", "vitest", "unittest", "Gradle test"):
            self.assertNotIn(command, result.stdout)

    def test_check_dispatch_is_compile_only_and_stops_at_first_failure(self):
        scratch = self.short_scratch()
        env = dict(self.environ, XTRACE_DEV_SCRATCH=str(scratch))
        scripts = self.worktree / "tools" / "dev"
        scripts.mkdir(parents=True)
        for name in ("check.sh", "env.sh", "devid.py"):
            shutil.copyfile(SCRIPTS / name, scripts / name)
        (scripts / "test_dev_tools.py").write_text("value = 1\n")
        package = self.worktree / "sample_package"
        package.mkdir()
        (package / "__init__.py").write_text("value = 1\n")
        bin_dir = self.base / "commands"
        bin_dir.mkdir()
        log = self.base / "commands.jsonl"
        env["PATH"] = str(bin_dir) + os.pathsep + os.environ["PATH"]
        env["XTRACE_COMMAND_LOG"] = str(log)
        env.pop("CARGO_NET_OFFLINE", None)
        env.pop("NPM_CONFIG_OFFLINE", None)
        stub = '''#!INTERPRETER
import json
import os
from pathlib import Path
import sys
if Path(sys.argv[0]).name == "python3" and sys.argv[1:3] != ["-B", "-c"]:
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
record = {
    "command": [Path(sys.argv[0]).name, *sys.argv[1:]],
    "cwd": os.getcwd(),
    "cargo_offline": os.environ.get("CARGO_NET_OFFLINE"),
    "npm_offline": os.environ.get("NPM_CONFIG_OFFLINE"),
}
with open(os.environ["XTRACE_COMMAND_LOG"], "a") as output:
    output.write(json.dumps(record) + "\\n")
sys.exit(37 if sys.argv[1:2] == [os.environ.get("XTRACE_FAIL_COMMAND")] else 0)
'''.replace("INTERPRETER", os.sys.executable)
        for name in ("cargo", "npm", "node", "python3"):
            path = bin_dir / name
            path.write_text(stub)
            path.chmod(0o700)
        gradle = self.worktree / "adapters" / "java" / "gradlew"
        gradle.parent.mkdir(parents=True)
        gradle.write_text(stub)
        gradle.chmod(0o700)
        compile_code = 'import sys; [compile(open(path, "rb").read(), path, "exec") for path in sys.argv[1:]]'
        cases = [
            ("rust:demo", [], [
                ["cargo", "check", "-p", "demo", "--all-targets", "--all-features", "--locked"],
                ["cargo", "clippy", "-p", "demo", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"],
            ]),
            ("rust:demo:integration", [], [
                ["cargo", "test", "-p", "demo", "--test", "integration", "--no-run", "--locked"],
            ]),
            ("java:attach-helper", [], [
                ["gradlew", "-p", "adapters/java", "--no-daemon", "--dependency-verification", "strict", ":attach-helper:compileJava", ":attach-helper:compileTestJava"],
            ]),
            ("java", [], [
                ["gradlew", "-p", "adapters/java", "--no-daemon", "--dependency-verification", "strict", "compileJava", "compileTestJava"],
            ]),
            ("node", [], [
                ["npm", "run", "generate:check", "--prefix", "adapters/node"],
                ["npm", "run", "typecheck", "--prefix", "adapters/node"],
            ]),
            ("web", [], [
                ["npm", "run", "typecheck", "--prefix", "web/app"],
                ["node", "web/app/scripts/check-contrast.mjs"],
            ]),
            ("py:tools.dev.test_dev_tools", [], [["python3", "-B", "-c", compile_code, "tools/dev/test_dev_tools.py"]]),
            ("py:sample_package", [], [["python3", "-B", "-c", compile_code, "sample_package/__init__.py"]]),
            ("py:tools.dev", [], [["python3", "-B", "-c", compile_code, "tools/dev/devid.py", "tools/dev/test_dev_tools.py"]]),
            ("fmt", [], [["cargo", "fmt", "--all", "--check"]]),
        ]
        for part, extra, expected in cases:
            with self.subTest(part=part):
                log.write_text("")
                result = subprocess.run(
                    ["bash", str(scripts / "check.sh"), part, *extra],
                    env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                records = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual([record["command"] for record in records], expected)
                self.assertTrue(all(record["cwd"] == str(self.worktree) for record in records))
                self.assertTrue(all(record["cargo_offline"] is None for record in records))
                self.assertTrue(all(record["npm_offline"] is None for record in records))
                self.assertEqual(len([line for line in result.stdout.splitlines() if line.startswith("+")]), len(expected))
        log.write_text("")
        result = subprocess.run(
            ["bash", str(scripts / "check.sh"), "web:src/main.test.tsx"],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not supported", result.stderr)
        result = subprocess.run(
            ["bash", str(scripts / "check.sh"), "py:missing.module"],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("No Python source found for module: missing.module", result.stderr)
        env["XTRACE_FAIL_COMMAND"] = "clippy"
        result = subprocess.run(
            ["bash", str(scripts / "check.sh"), "rust:demo"],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 37)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([record["command"][1] for record in records], ["check", "clippy"])

    def test_python_compile_checks_source_without_bytecode(self):
        env = dict(self.environ, XTRACE_DEV_SCRATCH=str(self.short_scratch()))
        scripts = self.worktree / "tools" / "dev"
        scripts.mkdir(parents=True)
        for name in ("check.sh", "env.sh", "devid.py"):
            shutil.copyfile(SCRIPTS / name, scripts / name)
        package = self.worktree / "sample_package"
        package.mkdir()
        source = package / "__init__.py"
        source.write_text("value = 1\n")
        for module in ("sample_package", "tools.dev", "tools.dev.devid"):
            with self.subTest(module=module):
                result = subprocess.run(
                    ["bash", str(scripts / "check.sh"), f"py:{module}"],
                    env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.worktree.rglob("__pycache__")), [])
        self.assertEqual(list(self.worktree.rglob("*.pyc")), [])
        source.write_text("value =\n")
        result = subprocess.run(
            ["bash", str(scripts / "check.sh"), "py:sample_package"],
            env=env, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SyntaxError", result.stderr)
        self.assertEqual(list(self.worktree.rglob("*.pyc")), [])


class WorktreeIdTests(unittest.TestCase):
    def test_every_name_has_a_readable_prefix_and_hash(self):
        for name, prefix in (("Agent_Ready", "agent-r"), ("ab---", "ab"), ("!!!", "wt"), ("", "wt")):
            with self.subTest(name=name):
                digest = hashlib.sha256(name.encode()).hexdigest()[:4]
                self.assertEqual(worktree_id(name), f"{prefix}-{digest}")

    def test_previously_colliding_names_get_distinct_short_ids(self):
        names = ["agent_ready", "agent-ready", "Agent-Ready", "agent-ready-a", "agent-ready-b", "agent-ready-c", "agent-ready-campaign"]
        ids = [worktree_id(name) for name in names]
        self.assertEqual(len(set(ids)), len(ids))
        for value in ids:
            self.assertLessEqual(len(value), MAX_ID_LENGTH)
            self.assertRegex(value, r"^[a-z0-9-]{1,7}(?<!-)-[0-9a-f]{4}$")

    def test_same_basename_in_different_parents_is_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "one" / "agent-ready"
            second = Path(temporary) / "two" / "agent-ready"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            self.assertNotEqual(worktree_id(str(first)), worktree_id(str(second)))

    def test_existing_absolute_paths_use_realpath_but_explicit_strings_do_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Agent_Ready"
            path.mkdir()
            alias = Path(temporary) / "alias"
            alias.symlink_to(path, target_is_directory=True)
            canonical = os.path.realpath(path)
            digest = hashlib.sha256(os.fsencode(canonical)).hexdigest()[:4]
            self.assertEqual(worktree_id(str(path)), f"agent-r-{digest}")
            self.assertEqual(worktree_id(str(alias)), worktree_id(str(path)))
            for explicit in (str(path / "missing"), os.path.relpath(path)):
                with self.subTest(explicit=explicit):
                    digest = hashlib.sha256(os.fsencode(explicit)).hexdigest()[:4]
                    self.assertTrue(worktree_id(explicit).endswith(f"-{digest}"))

if __name__ == "__main__":
    unittest.main()
