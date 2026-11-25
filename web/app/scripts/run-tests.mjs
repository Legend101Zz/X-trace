import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { constants } from 'node:os';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const outcomePath = process.env.XTRACE_WEB_TEST_OUTCOME_PATH;
const childEnv = { ...process.env };
delete childEnv.XTRACE_WEB_TEST_OUTCOME_PATH;

// Keep npm test's original order, inherited output and && short-circuit. Only the
// wrapper sees the private outcome path; test output cannot declare a stage result.
for (const [stage, entry, args] of [
  ['vitest', '../node_modules/vitest/vitest.mjs', ['run']],
  ['contrast', './check-contrast.mjs', process.argv.slice(2)],
]) {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL(entry, import.meta.url)), ...args], {
    stdio: 'inherit',
    env: childEnv,
  });
  const status = result.status ?? (result.signal ? 128 + constants.signals[result.signal] : 1);
  if (status !== 0) {
    // Diagnostic admission or write errors must never replace the command's status.
    // Signals/startup errors do not provide a completed subcommand result.
    if (result.status !== null && outcomePath && isAbsolute(outcomePath)) {
      try {
        writeFileSync(outcomePath, `${JSON.stringify({ schemaVersion: 1, subcommand: stage, exitCode: status })}\n`, {
          flag: 'wx', mode: 0o600,
        });
      } catch { /* The sanitizer will report unavailable evidence. */ }
    }
    process.exit(status);
  }
}
