import assert from "node:assert/strict";
import test from "node:test";
import { assertJourney, scenario } from "./express-journey.js";

test("Express 4: route template, mounted routers, middleware order, handler and error-handler frames", async () => {
  const result = await scenario("express4-app");
  assertJourney(result);
  assert.deepEqual(result.handlerEvidence, { invoked: 6, withContext: 6, posted: 6 });
});
