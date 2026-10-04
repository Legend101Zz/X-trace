// `npm run generate`: regenerate the checked-in protobuf bindings in their canonical form, so a clean
// checkout stays clean. Always runs (no entry-point guard); any failure exits non-zero.
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeTree } from "./generated-normalize.mjs";
import { generate } from "./generated-template.mjs";

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const checkedIn = join(workspace, "packages/protocol/src/gen");
const schema = resolve(workspace, "../../schema/proto");

generate(workspace, schema, checkedIn);
await normalizeTree(checkedIn);
