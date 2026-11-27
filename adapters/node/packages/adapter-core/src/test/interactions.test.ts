import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import * as http from "node:http";
import { createRequire } from "node:module";
import { Duplex } from "node:stream";
import test from "node:test";
import type { CaptureEvent, HttpCaptureTransport } from "../runtime/transport.cjs";
import { encodeEvent } from "../worker-core.js";

const require = createRequire(import.meta.url);
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const manifest = require("../manifest.cjs") as typeof import("../manifest.cjs");
const modules = require("../modules.cjs") as typeof import("../modules.cjs");
const interactions = require("../interactions/index.cjs") as typeof import("../interactions/index.cjs");

class RecordingTransport implements HttpCaptureTransport {
  readonly events: CaptureEvent[] = [];
  start(): boolean { return true; }
  event(_id: string, event: CaptureEvent): boolean {
    this.events.push(event);
    return true;
  }
  finish(): boolean { return true; }
  onFailure(): void {}
  close(): void {}
}

test("interaction redaction strips credentials, query params, literals, quotes, and bounds sizes", () => {
  const sql = interactions.sanitizeSql(
    "/* secret comment */ SELECT * FROM \"public\".\"users\" WHERE email = 'alice@example.com' AND token = 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig1234' AND id = 42 -- line secret",
  );
  assert.equal(sql.statementKind, "select");
  assert.equal(sql.schema, "public");
  assert.equal(sql.table, "users");
  assert.equal(sql.summary.includes("alice@example.com"), false);
  assert.equal(sql.summary.includes("eyJ"), false);
  assert.equal(sql.summary.includes("secret"), false);
  assert.equal(sql.summary.includes("'"), false);
  assert.equal(sql.summary.includes("\""), false);
  assert.equal(sql.summary.includes("`"), false);

  const mysqlSql = interactions.sanitizeSql("INSERT INTO `billing`.`invoices` (`secret`, `amount`) VALUES ('hunter2', 99)");
  assert.equal(mysqlSql.statementKind, "insert");
  assert.equal(mysqlSql.schema, "billing");
  assert.equal(mysqlSql.table, "invoices");
  assert.equal(mysqlSql.summary.includes("`"), false);
  assert.equal(mysqlSql.summary.includes("hunter2"), false);

  const literalDecoy = interactions.sanitizeSql("SELECT 'err FROM secret_token' FROM users");
  assert.equal(literalDecoy.statementKind, "select");
  assert.equal(literalDecoy.schema, "");
  assert.equal(literalDecoy.table, "users");
  assert.equal(JSON.stringify(literalDecoy).includes("secret_token"), false);

  const insertDecoy = interactions.sanitizeSql("INSERT INTO logs VALUES ('FROM db.secret_val'), ($$INTO other.secret_dollar$$)");
  assert.equal(insertDecoy.statementKind, "insert");
  assert.equal(insertDecoy.schema, "");
  assert.equal(insertDecoy.table, "logs");
  assert.equal(JSON.stringify(insertDecoy).includes("secret_val"), false);
  assert.equal(JSON.stringify(insertDecoy).includes("secret_dollar"), false);

  const longSql = interactions.sanitizeSql(`SELECT * FROM users WHERE col IN (${Array.from({ length: 200 }, (_, i) => String(i)).join(",")})`);
  assert.ok(Buffer.byteLength(longSql.summary, "utf8") <= 512);
  assert.ok(longSql.summary.endsWith("..."));

  const target = interactions.sanitizeHttpTarget("https://admin:superpass@api.example.com:8443/v1/orders?token=secret-token-canary&page=2#frag", { method: "post" });
  assert.equal(target.method, "POST");
  assert.equal(target.host, "api.example.com");
  assert.equal(target.port, 8443);
  assert.equal(target.summary, "POST /v1/orders");
  assert.equal(JSON.stringify(target).includes("superpass"), false);
  assert.equal(JSON.stringify(target).includes("secret-token-canary"), false);

  const extra = interactions.sanitizeInteractionFacts({
    kind: "outbound-http",
    driver: "fetch",
    method: "GET",
    summary: "GET /ok",
    host: "user:pw@sub.example.com",
    // @ts-expect-error verify runtime stripping of extra properties
    headers: { Authorization: "Bearer secret" },
    query: "a=b",
  });
  assert.deepEqual(Object.keys(extra).sort(), ["driver", "host", "kind", "method", "summary"]);
  assert.equal(extra.host, "sub.example.com");

  const ex = interactions.safeExceptionFacts(Object.assign(new Error("password=canary-err"), { code: "ECONNREFUSED" }));
  assert.equal(ex.type, "Error");
  assert.equal(ex.message, "ECONNREFUSED");
  assert.equal(JSON.stringify(ex).includes("canary-err"), false);
});

test("pg Client and Pool deduplicate queries, omit parameter values, and capture rejections safely", async () => {
  const transport = new RecordingTransport();
  class FakeClient {
    host = "pg.internal";
    port = 5432;
    database = "orders_db";
    async query(_sql: unknown, _values?: unknown): Promise<{ rows: unknown[] }> {
      return { rows: [] };
    }
  }
  class FakePool {
    options = { connectionString: "postgres://dbuser:secret-pg-pass@pg.internal:5432/orders_db?sslmode=require" };
    private readonly client = new FakeClient();
    async query(sql: unknown, values?: unknown): Promise<{ rows: unknown[] }> {
      if (sql === "FAIL") throw Object.assign(new Error("pg-secret-canary-77"), { code: "23505" });
      return this.client.query(sql, values);
    }
  }

  interactions.instrumentPgModule({ Client: FakeClient, Pool: FakePool }, { transport: () => transport });
  const pool = new FakePool();
  const client = new FakeClient();
  const ctx = context.createContext("POST", 1n);

  await context.runInContext(ctx, async () => {
    await pool.query("SELECT id FROM orders WHERE customer_email = $1", ["secret-email-canary@example.com"]);
    await client.query("UPDATE public.accounts SET secret = 'topsecret' WHERE id = 7");
    await assert.rejects(() => pool.query("FAIL", ["secret-param-canary"]));
  });

  const starts = transport.events.filter((e) => e.kind === "interaction-start");
  const ends = transport.events.filter((e) => e.kind === "interaction-end");
  const exceptions = transport.events.filter((e) => e.kind === "exception");

  assert.equal(starts.length, 3, "Pool.query delegates to Client.query without double counting");
  assert.equal(ends.length, 3);
  assert.equal(exceptions.length, 1);
  assert.equal(starts[0]?.interaction?.driver, "pg");
  assert.equal(starts[0]?.interaction?.schema, "orders_db");
  assert.equal(starts[0]?.interaction?.table, "orders");
  assert.equal(starts[0]?.interaction?.host, "pg.internal");
  assert.equal(starts[1]?.interaction?.schema, "public");
  assert.equal(starts[1]?.interaction?.table, "accounts");
  assert.equal(exceptions[0]?.exception?.message, "23505");

  const dump = JSON.stringify(transport.events, (_k, v) => typeof v === "bigint" ? v.toString() : v);
  for (const secret of ["secret-pg-pass", "secret-email-canary", "topsecret", "pg-secret-canary-77", "secret-param-canary"]) {
    assert.equal(dump.includes(secret), false, `secret ${secret} must never appear`);
  }

  const encoded = encodeEvent({ type: "event", ...starts[0]!, eventId: "e2", sequence: 2n });
  assert.equal(encoded.interaction?.schema, "orders_db");
  assert.equal(encoded.interaction?.table, "orders");
});

test("mysql/mysql2 query and execute capture sanitized interactions and callback errors", async () => {
  const transport = new RecordingTransport();
  class FakeMysqlConn {
    config = { host: "mysql.internal", port: 3306, database: "catalog" };
    query(_sql: string, _values: unknown[], cb: (err: unknown, res?: unknown) => void): void {
      if (_sql.includes("FAIL")) cb(new Error("mysql-secret-canary"));
      else cb(null, []);
    }
    async execute(_sql: string, _values?: unknown[]): Promise<unknown[]> {
      return [];
    }
  }

  interactions.instrumentMysqlConnection(FakeMysqlConn, "mysql2", { transport: () => transport });
  const conn = new FakeMysqlConn();
  const ctx = context.createContext("GET", 1n);

  await context.runInContext(ctx, async () => {
    await new Promise<void>((resolve) => {
      conn.query("SELECT * FROM `products` WHERE sku = 'abc' AND api_key = 'AKIAIOSFODNN7EXAMPLE'", [], () => resolve());
    });
    await conn.execute("DELETE FROM `audit`.`tokens` WHERE id = ?", ["raw-token-canary"]);
    await new Promise<void>((resolve) => {
      conn.query("FAIL", [], () => resolve());
    });
  });

  assert.equal(transport.events.filter((e) => e.kind === "interaction-start").length, 3);
  assert.equal(transport.events.filter((e) => e.kind === "interaction-end").length, 3);
  assert.equal(transport.events.filter((e) => e.kind === "exception").length, 1);
  assert.equal(transport.events[0]?.interaction?.driver, "mysql2");
  assert.equal(transport.events[0]?.interaction?.table, "products");
  assert.equal(transport.events[0]?.interaction?.schema, "catalog");

  const dump = JSON.stringify(transport.events, (_k, v) => typeof v === "bigint" ? v.toString() : v);
  for (const secret of ["AKIAIOSFODNN7EXAMPLE", "raw-token-canary", "mysql-secret-canary"]) {
    assert.equal(dump.includes(secret), false);
  }
});

test("outbound HTTP (node:http.request, fetch, undici) captures status/errors, keeps listenerCount untouched, and honors withoutCapture", async (t) => {
  const transport = new RecordingTransport();
  const origFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = origFetch;
  });

  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("/fail")) throw Object.assign(new Error("fetch-secret-canary"), { code: "ETIMEDOUT" });
    return { status: 201 } as Response;
  }) as typeof fetch;

  const fakeUndici = {
    async request(_url: string) {
      return { statusCode: 204 };
    },
  };
  interactions.instrumentUndiciModule(fakeUndici, { transport: () => transport });
  interactions.installHttpClientCapture({ transport: () => transport });

  // In-memory http.Agent avoids any TCP/network calls while exercising real http.request.
  const okAgent = new http.Agent();
  (okAgent as unknown as { createConnection: (opts: unknown, cb: (e: null, s: Duplex) => void) => Duplex }).createConnection = (_opts, cb) => {
    const stream = new Duplex({
      read() {},
      write(_chunk, _enc, next) { next(); },
    });
    queueMicrotask(() => {
      stream.push("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
      stream.push(null);
    });
    cb(null, stream);
    return stream;
  };
  const errAgent = new http.Agent();
  (errAgent as unknown as { createConnection: (opts: unknown, cb: (e: Error) => void) => void }).createConnection = (_opts, cb) => {
    queueMicrotask(() => cb(Object.assign(new Error("http-err-canary"), { code: "ECONNREFUSED" })));
  };

  const ctx = context.createContext("POST", 1n);
  await context.runInContext(ctx, async () => {
    // 1. node:http.request success
    await new Promise<void>((resolve, reject) => {
      const req = http.request({
        host: "payments.internal",
        port: 8080,
        path: "/v1/charges?token=query-secret-canary",
        method: "POST",
        auth: "svc:auth-secret-canary",
        headers: { Authorization: "Bearer header-secret-canary" },
        agent: okAgent,
      }, (res) => {
        res.resume();
        res.on("end", resolve);
      });
      req.on("error", reject);
      req.end();
    });

    // 2. node:http.request failure: listenerCount("error") stays 0 before user attaches their own listener
    await new Promise<void>((resolve) => {
      const req = http.request({ host: "down.internal", port: 8081, path: "/ping", agent: errAgent });
      assert.equal(req.listenerCount("error"), 0, "instrumentation must never add an error listener");
      req.on("error", () => resolve());
      req.end();
    });

    // 3. globalThis.fetch success & rejection + undici
    await globalThis.fetch("https://user:pass@api.example.com:8443/v2/items?api_key=fetch-query-canary", {
      method: "PUT",
      headers: { Authorization: "Bearer fetch-header-canary" },
    });
    await assert.rejects(() => globalThis.fetch("https://api.example.com/fail"));
    await fakeUndici.request("http://undici.internal:9000/status?secret=undici-canary");

    // 4. Self-suppression inside withoutCapture
    await context.withoutCapture(async () => {
      await globalThis.fetch("https://xtrace.internal/suppressed");
    });
  });

  const starts = transport.events.filter((e) => e.kind === "interaction-start");
  const ends = transport.events.filter((e) => e.kind === "interaction-end");
  const exceptions = transport.events.filter((e) => e.kind === "exception");

  assert.equal(starts.length, 5);
  assert.equal(ends.length, 5);
  assert.equal(exceptions.length, 2);
  assert.equal(ends[0]?.interaction?.statusCode, 200);
  assert.equal(ends[0]?.interaction?.summary, "POST /v1/charges");
  assert.equal(ends[2]?.interaction?.statusCode, 201);
  assert.equal(ends[2]?.interaction?.host, "api.example.com");
  assert.equal(ends[4]?.interaction?.driver, "undici");
  assert.equal(ends[4]?.interaction?.statusCode, 204);

  const dump = JSON.stringify(transport.events, (_k, v) => typeof v === "bigint" ? v.toString() : v);
  for (const secret of [
    "query-secret-canary",
    "auth-secret-canary",
    "header-secret-canary",
    "http-err-canary",
    "fetch-query-canary",
    "fetch-header-canary",
    "fetch-secret-canary",
    "undici-canary",
    "suppressed",
  ]) {
    assert.equal(dump.includes(secret), false, `canary ${secret} leaked`);
  }

  // Module capability checks
  assert.ok(manifest.buildManifest().capabilities.includes("interactions.pg"));
  assert.ok(manifest.buildManifest().capabilities.includes("interactions.mysql"));
  assert.ok(manifest.buildManifest().capabilities.includes("interactions.outbound_http"));
  assert.deepEqual(modules.pgModule(() => "/fake/pg/package.json").detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  assert.deepEqual(modules.mysqlModule(() => "/fake/mysql2/package.json").detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  assert.deepEqual(modules.outboundHttpModule().detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
});
