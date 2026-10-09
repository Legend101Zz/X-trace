import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
import test from "node:test";
import type { Worker } from "node:worker_threads";
import type { CaptureEvent, HttpCaptureTransport } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const { events } = require("../runtime/events.cjs") as typeof import("../runtime/events.cjs");
const { ModuleRegistry } = require("../runtime/registry.cjs") as typeof import("../runtime/registry.cjs");
const { createHttpCaptureTransport } = require("../runtime/transport.cjs") as typeof import("../runtime/transport.cjs");

class Capture implements HttpCaptureTransport {
  readonly seen: CaptureEvent[] = [];
  finished?: { finalSequence: bigint; dropped: number; summary: unknown };
  accept = true;
  start(): boolean { return true; }
  event(_id: string, event: CaptureEvent): boolean { if (!this.accept) return false; this.seen.push(event); return true; }
  finish(_id: string, finalSequence: bigint, _d: bigint, dropped: number, summary?: unknown): boolean {
    this.finished = { finalSequence, dropped, summary };
    return true;
  }
  onFailure(): void {}
  close(): void {}
}

test("sequencer assigns contiguous recording_seq starting at 2 and counts drops", () => {
  const transport = new Capture();
  const ctx = context.createContext("GET", 1n);
  assert.equal(ctx.rootCreated, true);
  context.runInContext(ctx, () => {
    const enter = context.recordEvent(ctx, transport, events.frameEnter("root"));
    const exit = context.recordEvent(ctx, transport, events.frameExit("root", enter));
    transport.accept = false;
    assert.equal(context.recordEvent(ctx, transport, events.gap({ reason: "queue-full", count: 1, firstSequence: 4n, lastSequence: 4n })), "");
    transport.accept = true;
    context.recordEvent(ctx, transport, events.response("response-finish", enter));
    assert.ok(exit);
  });
  assert.deepEqual(transport.seen.map((event) => event.sequence), [2n, 3n, 4n]);
  assert.equal(ctx.droppedEvents, 1);
  context.finishContext(ctx, transport);
  assert.equal(transport.finished?.finalSequence, 4n);
  assert.equal(transport.finished?.dropped, 1);
});

test("events outside the owning async context are not recorded", () => {
  const transport = new Capture();
  const ctx = context.createContext("GET", 1n);
  assert.equal(context.recordEvent(ctx, transport, events.frameEnter("outside")), "");
  assert.equal(transport.seen.length, 0);
  assert.equal(ctx.droppedEvents, 0);
});

test("self-suppression: nothing recorded inside withoutCapture, and it does not count as a drop", () => {
  const transport = new Capture();
  const ctx = context.createContext("GET", 1n);
  context.runInContext(ctx, () => {
    context.withoutCapture(() => {
      assert.equal(context.recordEvent(ctx, transport, events.interactionStart({ kind: "outbound-http", driver: "node", method: "GET", summary: "xtrace transport" }, ""))
        , "");
    });
    assert.ok(context.recordEvent(ctx, transport, events.frameEnter("after")));
  });
  assert.equal(transport.seen.length, 1);
  assert.equal(ctx.droppedEvents, 0);
});

test("typed builders carry only the facts of their kind and never raw error text", () => {
  const secret = new Error("secret-canary-71c0");
  const thrown = events.frameThrow("f", "p", secret);
  assert.equal(thrown.exceptionType, "Error");
  assert.equal(JSON.stringify(thrown).includes("secret-canary"), false);
  assert.equal(events.frameThrow("f", "p", "text").exceptionType, "UnknownError");
  const link = events.asyncLink("p", "q");
  assert.equal(link.asyncParentEventId, "q");
  const interaction = events.interactionStart({ kind: "database", driver: "pg", method: "query", summary: "select ?" }, "p", "q");
  assert.equal(interaction.interaction?.summary, "select ?");
  assert.equal(interaction.asyncParentEventId, "q");
});

test("core registry disables a module whose detect() throws and keeps others", () => {
  const registry = new ModuleRegistry();
  let installed = 0;
  const good = { descriptor: { name: "good", capability: "http.server.request_root", limitationsWhenAbsent: ["route_unavailable"] }, detect: () => ({ supported: true as const }), install: () => { installed += 1; } };
  const throwing = { descriptor: { name: "bad-detect", capability: "framework.express", limitationsWhenAbsent: ["frameworks_uninstrumented"] }, detect: (): never => { throw new Error("detect exploded"); }, install: () => { installed += 100; } };
  const unsupported = { descriptor: { name: "old", capability: "framework.fastify", limitationsWhenAbsent: ["fastify_unsupported_version"] }, detect: () => ({ supported: false as const, reason: "version_not_pinned" }), install: () => { installed += 100; } };
  const failingInstall = { descriptor: { name: "bad-install", capability: "db.pg", limitationsWhenAbsent: ["database_calls_unobserved"] }, detect: () => ({ supported: true as const }), install: (): never => { throw new Error("patch failed"); } };
  const env = { nodeVersion: process.version, packageVersion: "" };
  for (const module of [good, throwing, unsupported, failingInstall]) registry.tryInstall(module, env);
  assert.equal(installed, 1);
  assert.deepEqual(registry.capabilities(), ["http.server.request_root"]);
  assert.deepEqual(registry.statuses().map((s) => `${s.name}:${s.state}`), ["good:installed", "bad-detect:disabled", "old:disabled", "bad-install:disabled"]);
  assert.deepEqual(registry.limitations(), [
    "database_calls_unobserved", "fastify_unsupported_version", "frameworks_uninstrumented", "module_install_failed", "version_not_pinned",
  ]);
  assert.equal(JSON.stringify(registry.statuses()).includes("exploded"), false);
});

test("transport: finish carries the resolved summary and still reserves its terminal slot", () => {
  class FakeWorker extends EventEmitter { readonly sent: Array<Record<string, unknown>> = []; postMessage(m: Record<string, unknown>): void { this.sent.push(m); } ref(): void {} }
  const worker = new FakeWorker();
  const transport = createHttpCaptureTransport(worker as unknown as Worker);
  assert.equal(transport.start("r", "GET", 1n), true);
  assert.equal(transport.finish("r", 2n, 5n, 0, { route: "/users/:id", httpStatus: 200, outcome: "responded" }), true);
  assert.deepEqual(worker.sent.at(-1)?.summary, { route: "/users/:id", httpStatus: 200, outcome: "responded" });
  assert.equal(transport.finish("r", 2n, 5n, 0), false);
});

test("manifest is deterministic and limitations shrink when a module installs", () => {
  const manifestModule = require("../manifest.cjs") as typeof import("../manifest.cjs");
  const first = JSON.stringify(manifestModule.buildManifest());
  assert.equal(first, JSON.stringify(manifestModule.buildManifest([...manifestModule.BUILTIN_MODULES].reverse())));
  const parsed = manifestModule.buildManifest();
  assert.equal(parsed.schema, 2);
  assert.ok(parsed.capabilities.includes("http.server.request_root"));
  const none = manifestModule.effectiveLimitations(new Set());
  const withHttp = manifestModule.effectiveLimitations(new Set(["node-http", "async-context"]));
  assert.ok(none.includes("http_root_unavailable") && none.includes("http_status_unavailable"));
  assert.equal(withHttp.includes("http_root_unavailable"), false);
  assert.equal(withHttp.includes("http_status_unavailable"), false);
  assert.ok(withHttp.includes("route_unavailable"), "route needs a framework module");
  assert.ok(withHttp.includes("values_unavailable"), "baseline limitations never shrink");
});
