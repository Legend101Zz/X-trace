import test from "node:test";
import { assertJourney, scenario } from "./express-journey.js";

test("Express 5: route template, mounted routers, middleware order, handler and error-handler frames", async () => {
  assertJourney(await scenario("express5-app"));
});
