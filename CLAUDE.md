@AGENTS.md

## Claude Code notes

- In this repo, Claude Code is the orchestrator (ADR 0012). It writes tickets, launches Codex workers, reviews diffs,
  commits, opens pull requests, reads CI and merges. Keep the root context lean: workers and subagents write reports
  to files, and the orchestrator reads the summaries.
- Claude only orchestrates and reviews; Codex workers write all code, tests, docs, ADRs and merge-conflict resolutions
  (`gpt-6.1-sol` for code, `gpt-6.1-terra` for docs). Claude commits reviewed diffs under the owner's identity and closes issues.
- Compile only locally; GitHub CI runs tests. Track every ticket in a GitHub issue and each wave in a tracking issue
  with a checklist. Reference ticket issues in PRs with `Refs #N`.
- `.claude/settings.json` installs a `PreToolUse` guard (`.claude/hooks/guard.sh`) that denies the forbidden
  commands listed in AGENTS.md. Do not disable it.
