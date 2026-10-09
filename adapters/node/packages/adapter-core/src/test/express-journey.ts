import assert from "node:assert/strict";
import { once } from "node:events";
import * as http from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { CaptureEvent, HttpCaptureTransport, RecordingSummary } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const { installHttpCapture } = require("../http-capture.cjs") as typeof import("../http-capture.cjs");
const { expressPatchStatus } = require("../express-instrument.cjs") as typeof import("../express-instrument.cjs");
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const modules = require("../modules.cjs") as typeof import("../modules.cjs");

const here = dirname(fileURLToPath(import.meta.url));
const nodeRoot = join(here, "../../../..");

interface Seen {
  id: string;
  events: CaptureEvent[];
  routes: string[];
  summary?: RecordingSummary | undefined;
  order: string[];
}

function recordingTransport(seen: Map<string, Seen>): HttpCaptureTransport {
  const entry = (id: string): Seen => {
    let found = seen.get(id);
    if (!found) { found = { id, events: [], routes: [], order: [] }; seen.set(id, found); }
    return found;
  };
  return {
    start(id) { entry(id).order.push("start"); return true; },
    event(id, event) { const e = entry(id); e.events.push(event); e.order.push(`event:${event.kind}`); return true; },
    route(id, route) { const e = entry(id); e.routes.push(route); e.order.push(`route:${route}`); return true; },
    finish(id, _f, _d, _x, summary) { const e = entry(id); e.summary = summary; e.order.push("finish"); return true; },
    onFailure() {},
    close() {},
  };
}

async function get(port: number, path: string): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path, agent: false }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); }).on("error", reject);
  });
}

function frames(recording: Seen): Array<[string, string]> {
  return recording.events.filter((event) => event.kind.startsWith("frame-")).map((event) => [event.kind, event.symbol]);
}

/** One test per Express major: the Layer patch needs the framework loaded after it is installed. */
export async function scenario(fixture: string): Promise<{ byPath: Map<string, Seen>; statuses: Map<string, number> }> {
  const seen = new Map<string, Seen>();
  const transport = recordingTransport(seen);
  context.setCaptureProfile({ limitations: ["route_unavailable", "values_unavailable"], holdStart: true });
  installHttpCapture(transport);
  const fixtureRequire = createRequire(join(nodeRoot, "examples", fixture, "app.js"));
  const module = modules.expressModule((specifier) => fixtureRequire.resolve(specifier), () => transport);
  assert.deepEqual(module.detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  module.install({ nodeVersion: process.version, packageVersion: "" });
  const before = expressPatchStatus().patched;
  const express = fixtureRequire("express") as () => {
    use(...args: unknown[]): void; get(path: string, ...handlers: unknown[]): void; listen(port: number, host: string): http.Server;
  };
  const Router = (express as unknown as { Router(): { get(path: string, ...handlers: unknown[]): void } }).Router;
  assert.equal(expressPatchStatus().patched, before + 1, "the Layer module of this Express was patched exactly once");

  const app = express();
  app.use(function requestLogger(_req: unknown, _res: unknown, next: () => void) { next(); });
  app.get("/owners/:id", function showOwner(_req: unknown, res: http.ServerResponse) { res.statusCode = 200; res.end("ok"); });
  const api = Router();
  api.get("/pets/:petId", function showPet(_req: unknown, res: http.ServerResponse) { res.end("pet"); });
  app.use("/api", api);
  const clinic = Router();
  clinic.get("/vets/:vetId", function showVet(_req: unknown, res: http.ServerResponse) { res.end("vet"); });
  app.use("/clinics/:clinicId", clinic);
  app.get("/boom", function explode() { throw new Error("SECRET_CANARY"); });
  app.use(function appErrorHandler(_err: unknown, _req: unknown, res: http.ServerResponse, _next: unknown) { res.statusCode = 500; res.end("failed"); });

  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const statuses = new Map<string, number>();
  try {
    for (const path of ["/owners/42?token=canary", "/api/pets/7", "/clinics/9/vets/3", "/boom", "/missing"]) {
      statuses.set(path, await get(address.port, path));
    }
    await new Promise((resolve) => setTimeout(resolve, 60));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
  const byPath = new Map<string, Seen>();
  const ordered = [...seen.values()];
  ["/owners/42", "/api/pets/7", "/clinics/9/vets/3", "/boom", "/missing"].forEach((path, index) => byPath.set(path, ordered[index]!));
  return { byPath, statuses };
}

export function assertJourney(result: Awaited<ReturnType<typeof scenario>>): void {
  const { byPath, statuses } = result;
  assert.equal(byPath.size, 5, "exactly one recording per request");
  assert.equal(statuses.get("/boom"), 500);
  assert.equal(statuses.get("/missing"), 404);

  const owner = byPath.get("/owners/42")!;
  assert.deepEqual(owner.routes, ["/owners/:id"], "the template is announced at match time");
  assert.equal(owner.summary?.route, "/owners/:id");
  assert.ok(owner.order.indexOf("route:/owners/:id") < owner.order.indexOf("finish"));
  assert.ok(!owner.summary?.limitations?.includes("route_unavailable"));
  assert.ok(owner.summary?.limitations?.includes("values_unavailable"));
  assert.deepEqual(frames(owner), [
    ["frame-enter", "node:http.Server.request"],
    ["frame-enter", "express.middleware:requestLogger"],
    ["frame-enter", "express.handler:showOwner"],
    ["frame-exit", "express.handler:showOwner"],
    ["frame-exit", "express.middleware:requestLogger"],
    ["frame-exit", "node:http.Server.request"],
  ], "middleware order and handler frames, nested as the calls nest");
  const [root, logger, handler] = owner.events;
  assert.equal(logger!.parentEventId, root!.eventId);
  assert.equal(handler!.parentEventId, logger!.eventId);

  assert.deepEqual(byPath.get("/api/pets/7")!.routes, ["/api/pets/:petId"], "mounted router composes with its literal mount path");
  assert.deepEqual(byPath.get("/clinics/9/vets/3")!.routes, ["/clinics/:clinicId/vets/:vetId"], "mount path params stay templates");

  const boom = byPath.get("/boom")!;
  assert.deepEqual(boom.routes, ["/boom"]);
  assert.equal(boom.summary?.httpStatus, 500);
  assert.equal(boom.summary?.outcome, "responded", "Express handled the error: nothing propagated to the root");
  assert.deepEqual(frames(boom).map(([kind, symbol]) => `${kind}:${symbol}`), [
    "frame-enter:node:http.Server.request",
    "frame-enter:express.middleware:requestLogger",
    "frame-enter:express.handler:explode",
    "frame-throw:express.handler:explode",
    "frame-enter:express.error_handler:appErrorHandler",
    "frame-exit:express.error_handler:appErrorHandler",
    "frame-exit:express.middleware:requestLogger",
    "frame-exit:node:http.Server.request",
  ]);
  assert.ok(!JSON.stringify(boom.events, (_k, v) => typeof v === "bigint" ? v.toString() : v).includes("SECRET_CANARY"));

  const missing = byPath.get("/missing")!;
  assert.deepEqual(missing.routes, []);
  assert.equal(missing.summary?.route, "");
  assert.equal(missing.summary?.httpStatus, 404);
  assert.ok(missing.summary?.limitations?.includes("route_unavailable"), "an unmatched request says its route is unavailable");
  assert.ok(!frames(missing).some(([, symbol]) => symbol.startsWith("express.handler")));
  for (const recording of byPath.values()) {
    assert.equal(recording.order.filter((entry) => entry === "start").length, 1);
    assert.equal(recording.order.filter((entry) => entry === "finish").length, 1);
    assert.equal(recording.events.filter((event) => event.symbol === "node:http.Server.request" && event.kind === "frame-enter").length, 1, "exactly one root per request");
  }
}

