#!/usr/bin/env bash
# PreToolUse guard for Bash calls (Claude Code). Denies the commands AGENTS.md forbids.
# Input: the hook JSON on stdin. Exit 2 with a reason on stderr blocks the call.
# This is a guardrail, not a sandbox: it matches the command text only.
set -euo pipefail
cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))')
deny() { echo "Blocked by .claude/hooks/guard.sh: $1 (see AGENTS.md, Rules)." >&2; exit 2; }
re() { printf '%s' "$cmd" | grep -Eq -- "$1"; }
re '(^|[;&|(` ])(pkill|killall)([ ;&|)]|$)'           && deny "pkill/killall"
re '(^|[;&|(` ])kill( +-[A-Za-z0-9]+)* +[$`(]'          && deny "kill of a computed PID list"
re '(^|[;&|(` ])sudo([ ;&|)]|$)'                         && deny "sudo"
re '(^|[;&|(` ])diskutil([ ;&|)]|$)'                     && deny "diskutil"
re 'docker( +[a-z]+)? +prune|docker +system +prune'      && deny "docker prune"
re 'rm +(-[A-Za-z]*[rR][A-Za-z]* +)+["'"'"']?(/|~|\$HOME|\$\{HOME\}|/Volumes|/Users)/?["'"'"']?( |;|&|$)' && deny "rm -r of a root, home or volume path"
re 'git +push.*(--force|-f( |$)|--mirror)'               && deny "force push"
re 'git +push( +[^ ]+)? +([^ ]*:)?(refs/heads/)?main( |$)' && deny "direct push to main (use a pull request)"
exit 0
