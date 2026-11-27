import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createRequire } from "node:module";
import test from "node:test";
import type { CaptureEvent, HttpCaptureTransport, RecordingSummary } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const { wrapRequestListener } = require("../http-capture.cjs") as typeof import("../http-capture.cjs");
const { instrumentFastifyInstance } = require("../fastify-instrument.cjs") as typeof import("../fastify-instrument.cjs");
const {
  instrumentNestController,
  instrumentNestRouterExecutionContext,
  instrumentNestService,
  nestPatchStatus,
  resetNestDiagnostics,
} = require("../nest-instrument.cjs") as typeof import("../nest-instrument.cjs");
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const manifest = require("../manifest.cjs") as typeof import("../manifest.cjs");
const modules = require("../modules.cjs") as typeof import("../modules.cjs");

interface Recorded {
  method: string;
  routes: string[];
  events: CaptureEvent[];
  summary?: RecordingSummary;
}

class RecordingTransport implements HttpCaptureTransport {
  readonly recordings = new Map<string, Recorded>();
  start(id: string, method: string): boolean {
    this.recordings.set(id, { method, routes: [], events: [] });
    return true;
  }
  event(id: string, event: CaptureEvent): boolean {
    this.recordings.get(id)?.events.push(event);
    return true;
  }
  route(id: string, route: string): boolean {
    this.recordings.get(id)?.routes.push(route);
    return true;
  }
  finish(id: string, _f: bigint, _d: bigint, _x: number, summary?: RecordingSummary): boolean {
    const rec = this.recordings.get(id);
    if (rec && summary) rec.summary = summary;
    return true;
  }
  onFailure(): void {}
  close(): void {}
  list(): Recorded[] {
    return [...this.recordings.values()];
  }
}

class UsersService {
  async findById(id: string): Promise<{ id: string }> {
    await Promise.resolve();
    if (id === "boom") throw new Error("nest-service-canary-99");
    return { id };
  }
}

class UsersController {
  constructor(private readonly usersService: UsersService) {}
  async getUser(id: string): Promise<{ id: string }> {
    return this.usersService.findById(id);
  }
}

test("nestModule detects @nestjs/core and declares framework.nest capability", () => {
  assert.ok(manifest.buildManifest().capabilities.includes("framework.nest"));
  assert.deepEqual(modules.nestModule(() => "/fake/@nestjs/core/package.json").detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  assert.deepEqual(modules.nestModule(() => { throw new Error("missing"); }).detect({ nodeVersion: process.version, packageVersion: "" }), { supported: false, reason: "nest_not_found" });
});

test("NestJS controller & service identity on Express attaches to the single HTTP root with no duplicates", async () => {
  const transport = new RecordingTransport();
  context.setCaptureProfile({ limitations: ["route_unavailable"], holdStart: true });
  try {
    const service = new UsersService();
    const controller = new UsersController(service);
    instrumentNestService(service, { hooks: { transport: () => transport } });

    // Simulate Nest's RouterExecutionContext creating an Express handler.
    class FakeRouterExecutionContext {
      create(instance: object, callback: (id: string) => unknown, _methodName: string) {
        return async (req: { params?: { id?: string } }, res: ServerResponse) => {
          const out = await callback.call(instance, req.params?.id ?? "1");
          res.statusCode = 200;
          (res as unknown as EventEmitter).emit("finish");
          return out;
        };
      }
    }
    assert.equal(instrumentNestRouterExecutionContext(FakeRouterExecutionContext.prototype), true);
    const execCtx = new FakeRouterExecutionContext();
    const expressHandler = execCtx.create(controller, UsersController.prototype.getUser, "getUser");

    const listener = wrapRequestListener((req, res) => {
      const r = req as IncomingMessage & { route?: { path: string }; params?: { id: string } };
      r.route = { path: "/users/:id" };
      r.params = { id: "42" };
      context.announceRoute(context.currentContext()!, transport, "/users/:id");
      return expressHandler(r, res);
    });

    const req = Object.assign(new EventEmitter(), { method: "GET", url: "/users/42" }) as unknown as IncomingMessage;
    const res = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true }) as unknown as ServerResponse;
    await listener(req, res);

    const recordings = transport.list();
    assert.equal(recordings.length, 1, "Nest must never create a duplicate HTTP root");
    const [rec] = recordings as [Recorded];
    assert.equal(rec.events.filter((e) => e.symbol === "node:http.Server.request" && e.kind === "frame-enter").length, 1);

    const frames = rec.events.filter((e) => e.kind.startsWith("frame-"));
    assert.deepEqual(
      frames.map((e) => `${e.kind}:${e.symbol}`),
      [
        "frame-enter:node:http.Server.request",
        "frame-enter:nest.controller:UsersController.getUser",
        "frame-enter:nest.service:UsersService.findById",
        "frame-exit:nest.service:UsersService.findById",
        "frame-exit:nest.controller:UsersController.getUser",
        "frame-exit:node:http.Server.request",
      ],
    );
    const ctrlEnter = frames.find((e) => e.kind === "frame-enter" && e.symbol === "nest.controller:UsersController.getUser")!;
    const svcEnter = frames.find((e) => e.kind === "frame-enter" && e.symbol === "nest.service:UsersService.findById")!;
    assert.equal(svcEnter.parentEventId, ctrlEnter.eventId);
  } finally {
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
});

test("NestJS controller & service identity on Fastify enriches the Fastify request without duplicate roots", async () => {
  const transport = new RecordingTransport();
  context.setCaptureProfile({ limitations: ["route_unavailable"], holdStart: true });
  try {
    const service = new UsersService();
    const controller = new UsersController(service);
    instrumentNestService(service, { hooks: { transport: () => transport } });
    instrumentNestController(controller, { hooks: { transport: () => transport } });

    const onRouteHandlers: Array<(opts: Record<string, unknown>) => void> = [];
    const onRequestHooks: Array<(req: unknown, rep: unknown, done: () => void) => void> = [];
    let registeredHandler!: (req: unknown, rep: unknown) => unknown;
    const fakeFastify = {
      version: "4.28.0",
      prefix: "",
      addHook(name: string, fn: (...a: unknown[]) => unknown) {
        if (name === "onRoute") onRouteHandlers.push(fn as (opts: Record<string, unknown>) => void);
        if (name === "onRequest") onRequestHooks.push(fn as (req: unknown, rep: unknown, done: () => void) => void);
      },
      route(opts: { method: string; url: string; handler: (req: unknown, rep: unknown) => unknown }) {
        for (const h of onRouteHandlers) h.call(this, opts);
        registeredHandler = opts.handler;
      },
    };
    assert.equal(instrumentFastifyInstance(fakeFastify, { transport: () => transport }), true);

    fakeFastify.route({
      method: "GET",
      url: "/nest/users/:id",
      handler: async function fastifyNestAdapter() {
        return controller.getUser("boom");
      },
    });

    const listener = wrapRequestListener(async (req, res) => {
      const fReq = Object.assign(req, { raw: req, routeOptions: { url: "/nest/users/:id", method: "GET", handler: registeredHandler } });
      const fRep = { raw: res, statusCode: 200 };
      for (const h of onRequestHooks) await new Promise<void>((resolve) => h.call(fakeFastify, fReq, fRep, resolve));
      try {
        await registeredHandler.call(fakeFastify, fReq, fRep);
      } catch {
        res.statusCode = 500;
      }
      (res as unknown as EventEmitter).emit("finish");
    });

    const req = Object.assign(new EventEmitter(), { method: "GET", url: "/nest/users/boom" }) as unknown as IncomingMessage;
    const res = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true }) as unknown as ServerResponse;
    await listener(req, res);

    assert.equal(transport.list().length, 1);
    const [rec] = transport.list() as [Recorded];
    assert.deepEqual(rec.routes, ["/nest/users/:id"]);
    const symbols = rec.events.map((e) => `${e.kind}:${e.symbol}`);
    assert.ok(symbols.includes("frame-enter:fastify.handler:root:fastifyNestAdapter"));
    assert.ok(symbols.includes("frame-enter:nest.controller:UsersController.getUser"));
    assert.ok(symbols.includes("frame-throw:nest.service:UsersService.findById"));
    assert.ok(symbols.includes("frame-throw:nest.controller:UsersController.getUser"));
    assert.equal(JSON.stringify(rec, (_k, v) => typeof v === "bigint" ? v.toString() : v).includes("nest-service-canary-99"), false);
  } finally {
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
});

test("NestJS outside any active HTTP root creates no fake root and records an honest missing-root gap", async () => {
  resetNestDiagnostics();
  const transport = new RecordingTransport();
  const gaps: Array<{ reason: string; symbol: string; role: string }> = [];
  const service = new UsersService();
  const controller = new UsersController(service);
  instrumentNestService(service, { hooks: { transport: () => transport, onMissingRootGap: (g) => gaps.push(g) } });
  instrumentNestController(controller, { hooks: { transport: () => transport, onMissingRootGap: (g) => gaps.push(g) } });

  const out = await controller.getUser("7");
  assert.deepEqual(out, { id: "7" });
  assert.equal(transport.list().length, 0, "no synthetic HTTP root is created");
  const status = nestPatchStatus();
  assert.equal(status.missingRootGaps, 2);
  assert.ok(status.limitations.includes("nest_missing_http_root"));
  assert.equal(gaps.length, 2);
  assert.equal(gaps[0]?.reason, "correlation-lost");
  assert.equal(gaps[0]?.symbol, "nest.controller:UsersController.getUser");
});
