// The one generation template (plugin and options) used by both `npm run generate` and
// `generate:check`; only the output directory differs.
import { spawnSync } from "node:child_process";

export function templateFor(directory) {
  return JSON.stringify({
    version: "v2",
    plugins: [{
      local: "protoc-gen-es",
      out: directory,
      opt: "target=ts,import_extension=js",
    }],
  });
}

export function generate(workspace, schema, directory) {
  const result = spawnSync(
    "npm",
    ["exec", "--", "buf", "generate", schema, "--template", templateFor(directory)],
    { cwd: workspace, stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Buf generation failed with status ${result.status}`);
}
