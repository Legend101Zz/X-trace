@AGENTS.md

## Claude Code notes

- In this repo, Claude Code is the orchestrator (ADR 0012). It writes tickets, launches Codex workers, reviews diffs,
  commits, opens pull requests, reads CI and merges. Keep the root context lean: workers and subagents write reports
  to files, and the orchestrator reads the summaries.
- `.claude/settings.json` installs a `PreToolUse` guard (`.claude/hooks/guard.sh`) that denies the forbidden
  commands listed in AGENTS.md. Do not disable it.
