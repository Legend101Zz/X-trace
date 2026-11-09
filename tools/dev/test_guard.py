"""Exercise the hook as a subprocess; command strings are data, never executed."""

import json
from pathlib import Path
import subprocess
import unittest


GUARD = Path(__file__).resolve().parents[2] / ".claude" / "hooks" / "guard.sh"

ALLOW = [
    "kill 1234", "kill $PID", 'kill -TERM "$pid"',
    'git commit -m "ban sudo and pkill"', "grep -rn pkill docs/",
    'echo "rm -rf /"', "git push origin fix-f", "git push -u origin agent-ready",
    "rm -rf target/foo", "rm -rf /Volumes/XTraceCache/xt/target/abc",
    "cargo test -p xtrace-domain", "cat > f <<'EOF'\ndon't\nEOF",
    'echo ";" pkill x', 'echo "|" sudo ls', 'echo "\n" killall Dock',
    r"echo \; pkill x", 'printf "%s" "$(pgrep x)"',
    "git push origin feature/main", "git push origin main:feature",
    "git push --push-option main origin feat", "git -c key=value status",
    "git push main", "command -v pkill", "rm -f /", "rm -rf -- target/foo",
    'bash -c \'echo "sudo pkill rm -rf /"\'', "eval 'echo sudo'",
    'echo "bad\' sudo pkill',
    "# pkill; sudo ls\necho fine", "echo # don't; sudo ls\necho fine",
    'rm -rf ""', 'printf "%s" "" sudo pkill', "echo word#suffix pkill",
    "git push origin feature --push-option=main",
    'xargs sh -c \'echo "kill 1234"\'',
]

DENY = {
    "pkill": ["pkill -f x", "/usr/bin/pkill foo", "pkill\tfoo", "bash -c 'pkill x'",
              'sh -c "pkill -f vite"', "A=b pkill x", "env A=b /usr/bin/pkill x",
              "env -u NAME command -- pkill x", "nohup pkill x", "time -p pkill x",
              "nice -n 5 pkill x", "exec -a custom pkill x", "timeout 5 pkill x",
              "timeout -s TERM 5 env A=b pkill x", "xargs -n 1 pkill",
              "xargs -I{} /usr/bin/pkill {}", "eval 'pkill x'",
              "true; pkill x", "true && pkill x", "false || pkill x",
              "true | pkill x", "true & pkill x", "true\npkill x", "(pkill x)",
              "pkill x; echo 'unterminated"],
    "sudo": ["sudo ls", "bash -lc 'sudo make install'", "/usr/bin/sudo ls"],
    "killall": ["killall Dock"],
    "diskutil": ["diskutil list"],
    "kill through xargs": ["ps aux | grep x | awk '{print $2}' | xargs kill -9",
                           "xargs -n 1 command kill", "xargs --max-args=1 kill",
                           'xargs sh -c \'kill -TERM "$@"\''],
    "kill of a computed PID list": ['kill "$(pgrep x)"', "kill $(pgrep node)",
                                    "kill `pgrep x`", 'kill "`pgrep x`"',
                                    "kill -TERM $(pgrep x)", "kill '$(pgrep x)'"],
    "docker prune": ["docker system prune -a", "docker image prune",
                     "docker --context local container prune", "docker builder prune"],
    "rm -r of a root, home or volume path": [
        "rm -rf /", "rm -rf /*", "rm -rf ~/*", 'rm -rf "$HOME"', "rm -fr ${HOME}/",
        "rm -R /Users", "rm --recursive /Volumes/*", "rm -rf /Users/*/",
        "rm -rf ~", "rm -rf ~/", "rm -rf $HOME/", "rm -rf $HOME/*",
        "rm -rf /Volumes/", "rm -rf -- /", "rm -rf target/foo /",
    ],
    "direct push to main": [
        "git push origin main", "git push -u origin main",
        "git push --set-upstream origin main", "git push origin HEAD:refs/heads/main",
        "git -C wt push origin main", "git -c key=value -C wt push origin HEAD:main",
        "git push origin x:refs/heads/main", "git push --repo=origin main",
    ],
    "force push": [
        "git -C wt push --force origin feat", "git push -f origin x", "git push origin +x:y",
        "git push --force-with-lease origin feat", "git push --mirror origin",
        "git push --force-with-lease=refs/heads/feat origin feat",
    ],
}

# Cover each protected target with quotes and a trailing slash, without expanding it.
DENY["rm -r of a root, home or volume path"].extend(
    f"rm -rf {quote}{target}{suffix}{quote}"
    for target in ("/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/",
                   "$HOME/*", "/Users", "/Users/*", "/Volumes", "/Volumes/*")
    for quote in ("", "'", '"')
    for suffix in ("", "/")
)
DENY["pkill"].extend([
    "echo # don't hide the next command\npkill x", "echo word#suffix; pkill x",
    "zsh -ec 'pkill x'", "env A=b command nice -n 2 timeout 5 pkill x",
    "bash -ec 'sh -c \"pkill x\"'",
])
DENY["direct push to main"].extend([
    "git push origin HEAD:main", "git push origin refs/heads/main",
])


class GuardTests(unittest.TestCase):
    def run_guard(self, command):
        return subprocess.run(
            [str(GUARD)], input=json.dumps({"tool_input": {"command": command}}),
            capture_output=True, text=True, check=False,
        )

    def test_allow(self):
        for command in ALLOW:
            with self.subTest(command=command):
                result = self.run_guard(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_deny(self):
        for rule, commands in DENY.items():
            for command in commands:
                with self.subTest(command=command, rule=rule):
                    result = self.run_guard(command)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(rule, result.stderr)
                    self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
