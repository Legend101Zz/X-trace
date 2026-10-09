import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { composeTemplate } = require("../express-instrument.cjs") as typeof import("../express-instrument.cjs");

test("composeTemplate never guesses: regex, array, odd mount characters and unseen mounts stay unresolved", () => {
  assert.equal(composeTemplate("/x/:id", { baseUrl: "" }), "/x/:id");
  assert.equal(composeTemplate(/x/, { baseUrl: "" }), "");
  assert.equal(composeTemplate(["/a"], { baseUrl: "" }), "");
  assert.equal(composeTemplate("/ping", { baseUrl: "/sub" }), "", "a mount the patch did not see (sub-app) is not guessed");
  assert.equal(composeTemplate("no-slash", {}), "");
  assert.equal(composeTemplate("/" + "a".repeat(2000), {}), "");
});
