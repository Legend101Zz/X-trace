#!/usr/bin/env node
import { analyze, FRAMEWORKS, type Framework } from "./analyzer.js";

function usage(message: string): never {
  process.stderr.write(`xtrace-node-static: ${message}\n`);
  process.stderr.write(
    "usage: xtrace-node-static --source-root DIR --framework express|fastify|nest [--max-files N] [--max-file-bytes N]\n",
  );
  process.exit(2);
}

function main(argv: string[]): void {
  let root: string | undefined;
  let framework: Framework | undefined;
  let maxFiles = 20000;
  let maxFileBytes = 1 << 20;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = argv[i + 1];
    if (arg === "--source-root" && value !== undefined) {
      root = value;
      i++;
    } else if (arg === "--framework" && value !== undefined) {
      if (!(FRAMEWORKS as readonly string[]).includes(value)) usage("unknown framework " + value);
      framework = value as Framework;
      i++;
    } else if (arg === "--max-files" && value !== undefined) {
      maxFiles = Number.parseInt(value, 10);
      i++;
    } else if (arg === "--max-file-bytes" && value !== undefined) {
      maxFileBytes = Number.parseInt(value, 10);
      i++;
    } else {
      usage("unknown or incomplete argument " + String(arg));
    }
  }
  if (!Number.isFinite(maxFiles) || maxFiles < 1) usage("--max-files must be a positive integer");
  if (!Number.isFinite(maxFileBytes) || maxFileBytes < 1) usage("--max-file-bytes must be a positive integer");
  if (root === undefined) usage("--source-root is required");
  if (framework === undefined) usage("--framework is required");
  const lines = analyze({ root, framework, maxFiles, maxFileBytes });
  process.stdout.write(lines.join("\n") + "\n");
}

main(process.argv.slice(2));
