import assert from "node:assert/strict";
import { once } from "node:events";
import * as http from "node:http";
import { createRequire } from "node:module";
import test from "node:test";
import type { CaptureEvent, HttpCaptureTransport, RecordingSummary } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const { installHttpCapture } = require("../http-capture.cjs") as typeof import("../http-capture.cjs");
const modules = require("../modules.cjs") as typeof import("../modules.cjs");
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const manifest = require("../manifest.cjs") as typeof import("../manifest.cjs");

test("route template: literal unmounted path only, never concrete values", () => {
  const { resolveExpressRoute } = modules;
  assert.equal(resolveExpressRoute({ route: { path: "/owners/:id" }, baseUrl: "" }), "/owners/:id");
  assert.equal(resolveExpressRoute({ route: { path: "/owners/:id" } }), "/owners/:id");
  assert.equal(resolveExpressRoute({ route: { path: "/x" }, baseUrl: "/api/7" }), "", "mounted router base may hold values");
  assert.equal(resolveExpressRoute({ route: { path: /^\/a/ }, baseUrl: "" }), "");
  assert.equal(resolveExpressRoute({ route: { path: ["/a", "/b"] } }), "");
  assert.equal(resolveExpressRoute({ route: { path: "no-slash" } }), "");
  assert.equal(resolveExpressRoute({}), "");
  assert.equal(resolveExpressRoute(undefined), "");
});

test("express module detects by resolvability and declares the route capability", () => {
  const present = modules.expressModule(() => "/somewhere/express/package.json");
  assert.deepEqual(present.detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  assert.equal(present.descriptor.capability, "http.server.route_template");
  const absent = modules.expressModule(() => { throw new Error("not found"); });
  assert.deepEqual(absent.detect({ nodeVersion: process.version, packageVersion: "" }), { supported: false, reason: "express_not_found" });
  assert.deepEqual(absent.detect({ nodeVersion: "v20.1.0", packageVersion: "" }), { supported: false, reason: "node_runtime_unsupported" });
  assert.ok(manifest.buildManifest().capabilities.includes("http.server.route_template"));
});

test("a resolved route reaches the summary and clears route_unavailable for that recording only", async () => {
  const summaries: RecordingSummary[] = [];
  const transport: HttpCaptureTransport = {
    start: () => true,
    event: (_id: string, _event: CaptureEvent) => true,
    finish: (_id, _f, _d, _x, summary) => { if (summary) summaries.push(summary); return true; },
    onFailure() {},
    close() {},
  };
  context.setCaptureProfile({ limitations: ["route_unavailable", "values_unavailable"], holdStart: true });
  installHttpCapture(transport);
  context.registerRouteResolver(modules.resolveExpressRoute);
  const server = http.createServer((request, response) => {
    // Express sets req.route when a route layer matches; unmatched requests (404) have none.
    if (request.url?.startsWith("/owners/")) (request as unknown as { route: { path: string } }).route = { path: "/owners/:id" };
    response.statusCode = request.url?.startsWith("/owners/") ? 200 : 404;
    response.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    for (const path of ["/owners/42?token=canary", "/nothing"]) {
      await new Promise<void>((resolve, reject) => {
        http.get({ host: "127.0.0.1", port: address.port, path, agent: false }, (res) => { res.resume(); res.on("end", resolve); }).on("error", reject);
      });
    }
    await new Promise((resolve) => setTimeout(resolve, 30));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
  assert.equal(summaries.length, 2);
  const [matched, unmatched] = summaries as [RecordingSummary, RecordingSummary];
  assert.equal(matched.route, "/owners/:id");
  assert.equal(matched.httpStatus, 200);
  assert.equal(matched.outcome, "responded");
  assert.ok(!matched.limitations?.includes("route_unavailable"));
  assert.ok(matched.limitations?.includes("values_unavailable"));
  assert.equal(unmatched.route, "");
  assert.equal(unmatched.httpStatus, 404);
  assert.ok(unmatched.limitations?.includes("route_unavailable"));
  assert.ok(!JSON.stringify(summaries).includes("canary"));
});
