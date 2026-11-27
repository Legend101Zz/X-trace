import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createRequire } from "node:module";
import test from "node:test";
import type { CaptureEvent, HttpCaptureTransport, RecordingSummary } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const { installHttpCapture, wrapRequestListener } = require("../http-capture.cjs") as typeof import("../http-capture.cjs");
const { fastifyPatchStatus, instrumentFastifyInstance, resolveFastifyRoute } = require("../fastify-instrument.cjs") as typeof import("../fastify-instrument.cjs");
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
  finish(id: string, _final: bigint, _duration: bigint, _dropped: number, summary?: RecordingSummary): boolean {
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

interface StubRoute {
  method: string;
  url: string;
  handler: (req: unknown, rep: unknown) => unknown;
  onRequest?: Array<(req: unknown, rep: unknown, done: () => void) => unknown>;
  preHandler?: Array<(req: unknown, rep: unknown, done: () => void) => unknown>;
  onError?: Array<(req: unknown, rep: unknown, err: unknown, done: () => void) => unknown>;
  onResponse?: Array<(req: unknown, rep: unknown, done: () => void) => unknown>;
  scope: StubFastify;
}

class StubFastify {
  version = "5.1.0";
  prefix = "";
  pluginName = "fastify -> root";
  private hooks: Record<string, Array<{ fn: (...a: unknown[]) => unknown; owner: StubFastify }>> = {
    onRegister: [],
    onRoute: [],
    onRequest: [],
    preHandler: [],
    onError: [],
    onResponse: [],
  };
  private routes: StubRoute[] = [];

  addHook(name: string, fn: (...a: unknown[]) => unknown): this {
    (this.hooks[name] ??= []).push({ fn, owner: this });
    return this;
  }

  register(plugin: (app: StubFastify, opts?: Record<string, unknown>) => void, opts: Record<string, unknown> = {}): this {
    if (Reflect.get(plugin, Symbol.for("skip-override"))) {
      plugin(this, opts);
      return this;
    }
    const child = Object.create(this) as StubFastify;
    const rawPrefix = typeof opts.prefix === "string" ? opts.prefix : "";
    child.prefix = `${this.prefix}${rawPrefix}`;
    child.pluginName = plugin.name || "anonymous";
    child.hooks = {
      onRegister: [...this.hooks.onRegister!],
      onRoute: [...this.hooks.onRoute!],
      onRequest: [...this.hooks.onRequest!],
      preHandler: [...this.hooks.preHandler!],
      onError: [...this.hooks.onError!],
      onResponse: [...this.hooks.onResponse!],
    };
    child.routes = this.routes;
    for (const h of this.hooks.onRegister!) h.fn.call(this, child, opts);
    plugin(child, opts);
    return this;
  }

  route(opts: { method: string; url: string; handler: (req: unknown, rep: unknown) => unknown }): this {
    const fullUrl = `${this.prefix}${opts.url}`;
    const routeOpts: Record<string, unknown> = { ...opts, url: fullUrl, prefix: this.prefix };
    for (const h of this.hooks.onRoute!) h.fn.call(this, routeOpts);
    this.routes.push({
      method: opts.method.toUpperCase(),
      url: String(routeOpts.url),
      handler: routeOpts.handler as (req: unknown, rep: unknown) => unknown,
      scope: this,
    });
    return this;
  }

  get(url: string, handler: (req: unknown, rep: unknown) => unknown): this {
    return this.route({ method: "GET", url, handler });
  }

  async dispatch(req: IncomingMessage & { raw?: unknown; routeOptions?: unknown; is404?: boolean }, res: ServerResponse, matchedUrl: string | undefined): Promise<void> {
    const route = matchedUrl ? this.routes.find((r) => r.url === matchedUrl && r.method === (req.method ?? "GET")) : undefined;
    const scope = route?.scope ?? this;
    const reply = { raw: res, statusCode: 200, context: { handler: route?.handler, config: { url: route?.url } } };
    req.raw = req;
    if (route) {
      req.routeOptions = { url: route.url, method: route.method, handler: route.handler };
    } else {
      req.is404 = true;
    }

    const runHookList = async (name: string, extraArgs: unknown[] = []) => {
      for (const entry of scope.hooks[name] ?? []) {
        await new Promise<void>((resolve, reject) => {
          let settled = false;
          const done = (err?: unknown) => {
            if (settled) return;
            settled = true;
            if (err) reject(err);
            else resolve();
          };
          try {
            const ret = entry.fn.call(scope, req, reply, ...extraArgs, done);
            if (ret && typeof (ret as PromiseLike<unknown>).then === "function") {
              Promise.resolve(ret).then(() => done(), (err) => done(err));
            } else if (entry.fn.length < 3 + extraArgs.length) {
              done();
            }
          } catch (err) {
            done(err);
          }
        });
      }
    };

    try {
      await runHookList("onRequest");
      if (!route) {
        res.statusCode = 404;
        (res as unknown as EventEmitter).emit("finish");
        return;
      }
      await runHookList("preHandler");
      await route.handler.call(scope, req, reply);
      await runHookList("onResponse");
      res.statusCode = reply.statusCode;
      (res as unknown as EventEmitter).emit("finish");
    } catch (error) {
      await runHookList("onError", [error]);
      res.statusCode = 500;
      (res as unknown as EventEmitter).emit("finish");
    }
  }
}

test("fastifyModule detection and manifest capability registration", () => {
  assert.ok(manifest.buildManifest().capabilities.includes("http.server.fastify"));
  assert.deepEqual(modules.fastifyModule(() => "/fake/fastify/package.json").detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  assert.deepEqual(modules.fastifyModule(() => { throw new Error("missing"); }).detect({ nodeVersion: process.version, packageVersion: "" }), { supported: false, reason: "fastify_not_found" });
  assert.deepEqual(modules.fastifyModule(() => "/fake/fastify/package.json").detect({ nodeVersion: "v20.0.0", packageVersion: "" }), { supported: false, reason: "node_runtime_unsupported" });
});

test("Fastify encapsulation scopes, lifecycle hooks (onRequest, preHandler, onResponse), and route announcement", async () => {
  const transport = new RecordingTransport();
  installHttpCapture(transport);
  context.setCaptureProfile({ limitations: ["route_unavailable", "values_unavailable"], holdStart: true });
  try {
    const app = new StubFastify();
    assert.equal(instrumentFastifyInstance(app, { transport: () => transport }), true);

    app.addHook("onRequest", function rootAuth(_req, _rep, done) {
      (done as () => void)();
    });
    app.get("/health", function healthCheck(_req, rep) {
      (rep as { statusCode: number }).statusCode = 200;
      return "ok";
    });
    app.register(function ordersPlugin(orders) {
      orders.addHook("preHandler", async function loadTenant() {
        await Promise.resolve();
      });
      orders.get("/:id", function showOrder(_req, rep) {
        (rep as { statusCode: number }).statusCode = 200;
        return "order";
      });
      orders.register(function itemsPlugin(items) {
        items.get("/:itemId", function showItem() { return "item"; });
      }, { prefix: "/items" });
    }, { prefix: "/orders" });

    // skip-override plugin remains in parent scope
    const sharedPlugin = Object.assign(function sharedHelper(inst: StubFastify) {
      inst.get("/shared", function sharedHandler() { return "shared"; });
    }, { [Symbol.for("skip-override")]: true });
    app.register(sharedPlugin);

    const listener = wrapRequestListener((req, res) => {
      const url = req.url ?? "";
      const matched = url.startsWith("/orders/42/items/9") ? "/orders/items/:itemId"
        : url.startsWith("/orders/42") ? "/orders/:id"
          : url === "/shared" ? "/shared"
            : url === "/health" ? "/health"
              : undefined;
      return app.dispatch(req, res, matched);
    });

    for (const [path] of [
      ["/orders/42?token=secret-canary-fastify"],
      ["/orders/42/items/9"],
      ["/shared"],
      ["/unknown"],
    ]) {
      const req = Object.assign(new EventEmitter(), { method: "GET", url: path }) as unknown as IncomingMessage;
      const res = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true }) as unknown as ServerResponse;
      await listener(req, res);
    }

    const recordings = transport.list();
    assert.equal(recordings.length, 4);
    const [orderRec, itemRec, sharedRec, missingRec] = recordings as [Recorded, Recorded, Recorded, Recorded];

    assert.deepEqual(orderRec.routes, ["/orders/:id"]);
    assert.equal(orderRec.summary?.route, "/orders/:id");
    assert.ok(!orderRec.summary?.limitations?.includes("route_unavailable"));

    const orderSymbols = orderRec.events.map((e) => `${e.kind}:${e.symbol}`);
    assert.ok(orderSymbols.includes("frame-enter:fastify.hook.onRequest:plugin:ordersPlugin@/orders"));
    assert.ok(orderSymbols.includes("frame-enter:fastify.hook.onRequest:plugin:ordersPlugin@/orders:rootAuth"));
    assert.ok(orderSymbols.includes("frame-enter:fastify.hook.preHandler:plugin:ordersPlugin@/orders:loadTenant"));
    assert.ok(orderSymbols.includes("frame-enter:fastify.handler:plugin:ordersPlugin@/orders:showOrder"));
    assert.ok(orderSymbols.includes("frame-enter:fastify.hook.onResponse:plugin:ordersPlugin@/orders"));

    const itemSymbols = itemRec.events.map((e) => e.symbol);
    assert.ok(itemSymbols.some((s) => s.includes("plugin:itemsPlugin@/orders/items")));

    const sharedSymbols = sharedRec.events.map((e) => e.symbol);
    assert.ok(sharedSymbols.includes("fastify.handler:root:sharedHandler"), "skip-override keeps parent root scope");

    assert.deepEqual(missingRec.routes, []);
    assert.ok(missingRec.summary?.limitations?.includes("route_unavailable"));
    assert.equal(JSON.stringify(recordings, (_k, v) => typeof v === "bigint" ? v.toString() : v).includes("secret-canary-fastify"), false);
  } finally {
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
});

test("Fastify onError hook records safe exception without leaking error message, and reports unsupported shapes/hooks", async () => {
  const transport = new RecordingTransport();
  installHttpCapture(transport);
  context.setCaptureProfile({ limitations: ["route_unavailable"], holdStart: true });
  try {
    const app = new StubFastify();
    assert.equal(instrumentFastifyInstance(app, { transport: () => transport }), true);
    app.addHook("onError", function customErrorHook() { /* observe only */ });
    app.get("/explode", function explodeRoute() {
      throw new Error("canary-fastify-err-991");
    });

    const listener = wrapRequestListener((req, res) => app.dispatch(req, res, "/explode"));
    const req = Object.assign(new EventEmitter(), { method: "GET", url: "/explode" }) as unknown as IncomingMessage;
    const res = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true }) as unknown as ServerResponse;
    await listener(req, res);

    const [rec] = transport.list();
    assert.ok(rec);
    assert.ok(rec.events.some((e) => e.kind === "frame-throw" && e.symbol.includes("explodeRoute")));
    assert.ok(rec.events.some((e) => e.kind === "exception" && e.exception?.type === "Error" && e.exception.message === ""));
    assert.ok(rec.events.some((e) => e.kind === "frame-enter" && e.symbol.includes("customErrorHook")));
    assert.equal(JSON.stringify(rec, (_k, v) => typeof v === "bigint" ? v.toString() : v).includes("canary-fastify-err-991"), false);

    // Unsupported shapes & versions report explicit limitations cleanly without throwing.
    assert.equal(instrumentFastifyInstance({}), false);
    assert.equal(instrumentFastifyInstance({ version: "3.29.0", addHook() {} }), false);
    const minimalStub = {
      addHook(name: string) {
        if (name === "onRegister" || name === "onRoute") throw new Error("unsupported hook");
      },
    };
    assert.equal(instrumentFastifyInstance(minimalStub, { transport: () => transport }), true);
    const status = fastifyPatchStatus();
    assert.ok(status.unsupported >= 2);
    assert.ok(status.limitations.includes("fastify_hooks_unavailable"));
    assert.ok(status.limitations.includes("fastify_version_unsupported"));
    assert.ok(status.limitations.includes("fastify_encapsulation_unobserved"));
    assert.ok(status.limitations.includes("fastify_on_route_unsupported"));

    assert.equal(resolveFastifyRoute({ routeOptions: { url: "/users/:id" } }), "/users/:id");
    assert.equal(resolveFastifyRoute({ routeOptions: { url: "/users/:id" }, is404: true }), "");
    assert.equal(resolveFastifyRoute({ routeOptions: { url: "no-leading-slash" } }), "");
  } finally {
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
});
