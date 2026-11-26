import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runBaseline } from "../../lib/baseline.mjs";
import { startPostgres } from "../../lib/stack.mjs";
import { VendureFixture, builtImage } from "./fixture.mjs";

const name = role => "xtrace-camp-node-vendure-b1-" + role;
const ids = { net: "a".repeat(64), db: "b".repeat(64), worker: "c".repeat(64), app: "d".repeat(64) };
const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
const fail = (stderr = "") => ({ status: 1, stdout: "", stderr });
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vendure-owned-test-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  return dir;
}
function created(args, id) {
  fs.writeFileSync(args[args.indexOf("--cidfile") + 1], id, { flag: "wx", mode: 0o600 });
  return ok(id + "\n");
}
function stub(handler, logged) {
  const calls = [];
  const owner = new VendureFixture((args, options) => {
    calls.push(args);
    return handler(args, options);
  }, logged);
  return { owner, calls };
}

test("the image comes only from the private build receipt", t => {
  const dir = temporary(t);
  assert.throws(() => builtImage(dir));
  const file = path.join(dir, "vendure-image.id");
  fs.writeFileSync(file, "fixture:latest");
  assert.throws(() => builtImage(dir));
  fs.writeFileSync(file, "sha256:" + ids.app + "\n");
  assert.equal(builtImage(dir), "sha256:" + ids.app);
  fs.renameSync(file, file + ".source");
  fs.symlinkSync(file + ".source", file);
  assert.throws(() => builtImage(dir));
});

test("a colliding network creation grants no lookup or removal", () => {
  const { owner, calls } = stub(() => ({ ...fail(), stdout: ids.net }));
  assert.throws(() => owner.createNetwork(name("net")));
  owner.cleanup();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].slice(0, 2), ["network", "create"]);
  assert.ok(calls[0][2].startsWith(name("net") + "-"));
});

test("unreached container roles cannot be observed or removed", t => {
  const { owner, calls } = stub(() => assert.fail("unexpected fixture call"));
  for (const read of [() => owner.logs(name("app")), () => owner.exec(name("db"), ["placeholder"]),
    () => owner.hostPort(name("app"), 3000), () => owner.running(name("worker"))]) assert.throws(read);
  assert.equal(owner.collect({ app: name("app"), worker: name("worker") }, temporary(t)), null);
  owner.cleanup();
  assert.deepEqual(calls, []);
});

test("failed container creation without a cidfile grants no ownership", () => {
  const { owner, calls } = stub(() => ({ ...fail(), stdout: ids.app }));
  assert.throws(() => owner.runDetached(name("app"), []));
  owner.cleanup();
  assert.deepEqual(calls.map(args => args[0]), ["create"]);
});

test("a private cidfile survives nonzero or thrown creation for cleanup", () => {
  for (const thrown of [false, true]) {
    const { owner, calls } = stub(args => {
      if (args[0] !== "create") return ok();
      created(args, ids.db);
      if (thrown) throw new Error("simulated creation interruption");
      return fail();
    });
    assert.throws(() => owner.runDetached(name("db"), []));
    owner.cleanup();
    assert.deepEqual(calls.slice(1), [["rm", "-f", "-v", ids.db]]);
  }
});

test("malformed or conflicting receipts grant no collection or cleanup", () => {
  for (const [fileId, output] of [["unknown", ids.db], [ids.db, ids.app], [ids.db, "unexpected"]]) {
    const { owner, calls } = stub(args => { created(args, fileId); return ok(output); });
    assert.throws(() => owner.runDetached(name("db"), []));
    assert.throws(() => owner.id(name("db")));
    owner.cleanup();
    assert.equal(calls.length, 1);
  }
});

test("a created but unstarted container is released by ID", () => {
  const { owner, calls } = stub(args => args[0] === "create" ? ok(ids.app) : args[0] === "start" ? fail() : ok());
  assert.throws(() => owner.runDetached(name("app"), []));
  owner.cleanup();
  assert.deepEqual(calls.slice(1), [["start", ids.app], ["rm", "-f", "-v", ids.app]]);
});

test("database operations, readiness and logs use only recorded IDs", t => {
  const dir = temporary(t);
  const { owner, calls } = stub(args => {
    if (args[0] === "create") return created(args, ids[args[args.indexOf("--name") + 1].split("-").at(-1)]);
    if (args[0] === "network") return ok(ids.net);
    if (args[0] === "port") return ok("127.0.0.1:41234\n");
    if (args[0] === "logs") return ok("fixture log");
    if (args[0] === "inspect") return ok(args[2].includes("Running") ? "true" : "exited 0");
    return ok();
  });
  owner.createNetwork(name("net"));
  for (const role of ["db", "worker", "app"]) owner.runDetached(name(role), ["--network", owner.network]);
  owner.exec(name("db"), ["psql"]);
  assert.equal(owner.hostPort(name("app"), 3000), 41234);
  assert.equal(owner.running(name("worker")), true);
  assert.equal(owner.collect({ app: name("app"), worker: name("worker") }, dir), "0");
  assert.equal(fs.readFileSync(path.join(dir, "worker.log"), "utf8"), "fixture log");
  owner.cleanup();
  for (const args of calls.filter(a => a[0] !== "create" && a[1] !== "create")) {
    assert.ok(!args.some(value => value.startsWith("xtrace-camp-node-")));
  }
  assert.deepEqual(calls.slice(-4), [["rm", "-f", "-v", ids.app], ["rm", "-f", "-v", ids.worker],
    ["rm", "-f", "-v", ids.db], ["network", "rm", ids.net]]);
});

test("a failed cleanup still attempts later handles and retains only failed identities", () => {
  let removing = false;
  const { owner, calls } = stub(args => {
    if (args[0] === "network" && args[1] === "create") return ok(ids.net);
    if (args[0] === "create") return ok(args.includes(name("db")) ? ids.db : ids.worker);
    if (args[0] === "rm" && args.at(-1) === ids.worker && !removing) return fail("unexpected removal failure");
    return ok();
  });
  owner.createNetwork(name("net"));
  for (const role of ["db", "worker"]) owner.runDetached(name(role), []);
  assert.throws(() => owner.cleanup(), /cleanup failed/);
  assert.deepEqual(calls.slice(-3), [["rm", "-f", "-v", ids.worker], ["rm", "-f", "-v", ids.db], ["network", "rm", ids.net]]);
  removing = true;
  owner.cleanup();
  assert.deepEqual(calls.at(-1), ["rm", "-f", "-v", ids.worker]);
  const n = calls.length;
  owner.cleanup();
  assert.equal(calls.length, n);
});

test("only a precisely matching already-absent identity discharges a tracked handle", () => {
  let absent = ids.app;
  const { owner } = stub(args => args[0] === "create" ? ok(ids.db) : args[0] === "rm"
    ? fail("Error: No such container: " + absent) : ok());
  owner.runDetached(name("db"), []);
  assert.throws(() => owner.cleanup());
  absent = ids.db;
  owner.cleanup();
  assert.throws(() => owner.id(name("db")));
});

test("foreground completion checks the created container's terminal exit", async () => {
  for (const [state, expected] of [["exited 0", 0], ["exited 7", 7], ["running 0", null], ["exited 999", null]]) {
    const { owner, calls } = stub(args => args[0] === "create" ? ok(ids.app) : ok(state), async (args, log, options) => {
      assert.deepEqual(args, ["start", "--attach", ids.app]);
      assert.equal(log, "private.log");
      assert.ok(options.timeoutMs > 0 && options.timeoutMs <= 3600000);
      return 0;
    });
    const completion = owner.runLogged(name("app"), [], "private.log");
    if (expected === null) await assert.rejects(completion, /foreground exit unavailable/);
    else assert.equal(await completion, expected);
    owner.cleanup();
    assert.equal(calls.find(args => args[0] === "inspect").at(-1), ids.app);
  }
});

test("nonzero and signalled attached commands cannot gain success from a later state read", async () => {
  for (const status of [null, 9]) {
    const { owner, calls } = stub(args => args[0] === "create" ? ok(ids.app) : ok(), () => status);
    assert.equal(await owner.runLogged(name("app"), [], "private.log"), status);
    owner.cleanup();
    assert.deepEqual(calls.map(args => args[0]), ["create", "rm"]);
  }
});

test("a partial baseline startup emits a bounded failure and never samples uncreated roles", async t => {
  const root = temporary(t);
  const previous = process.exitCode;
  t.after(() => { process.exitCode = previous; });
  const { owner, calls } = stub(args => args[1] === "create" ? ok(ids.net) : ok());
  const result = await runBaseline({ project: "vendure", n: 1, root, fixture: owner, keep: true,
    buildStack() { throw new Error("synthetic private startup detail"); }, scenarios() { assert.fail(); } });
  const receipt = JSON.parse(fs.readFileSync(path.join(result.outDir, "receipt.json")));
  assert.equal(result.status, "failed");
  assert.equal(receipt.appContainerExitCodeAtTeardown, null);
  assert.equal(receipt.appLogSha256, null);
  assert.ok(!JSON.stringify(receipt).includes("synthetic private"));
  assert.equal(calls.length, 2);
  assert.ok(calls[0][2].startsWith(name("net") + "-"));
  assert.deepEqual(calls[1], ["network", "rm", ids.net]);
});

test("a failed app log read still collects its owned worker before teardown", t => {
  const dir = temporary(t);
  const { owner, calls } = stub(args => {
    if (args[0] === "create") return ok(args.includes(name("app")) ? ids.app : ids.worker);
    if (args[0] === "logs") return args[1] === ids.app ? fail() : ok("worker");
    if (args[0] === "inspect") return ok("running 0");
    return ok();
  });
  owner.runDetached(name("worker"), []);
  owner.runDetached(name("app"), []);
  assert.throws(() => owner.collect({ app: name("app"), worker: name("worker") }, dir), /logs unavailable/);
  assert.equal(fs.readFileSync(path.join(dir, "worker.log"), "utf8"), "worker");
  owner.cleanup();
  assert.deepEqual(calls.slice(-2), [["rm", "-f", "-v", ids.app], ["rm", "-f", "-v", ids.worker]]);
});

test("a failed baseline finalizer cannot preserve a successful scenario verdict", async t => {
  const previous = process.exitCode;
  t.after(() => { process.exitCode = previous; });
  for (const failure of ["collect", "cleanup"]) {
    const root = temporary(t);
    const calls = [];
    const fixture = {
      createNetwork() {},
      collect() { calls.push("collect"); if (failure === "collect") throw new Error("private marker"); return "0"; },
      cleanup() { calls.push("cleanup"); if (failure === "cleanup") throw new Error("private marker"); },
    };
    const result = await runBaseline({ project: "vendure", n: 1, root, fixture,
      buildStack: () => ({}), scenarios: () => [{ id: "mock", run: () => ({ assertions: { observed: true } }) }] });
    const receipt = JSON.parse(fs.readFileSync(path.join(result.outDir, "receipt.json")));
    assert.deepEqual(calls, ["collect", "cleanup"]);
    assert.equal(receipt.status, "failed");
    assert.equal(receipt.releaseAcceptance, false);
    assert.ok(!JSON.stringify(receipt).includes("private marker"));
  }
});

test("the reached PostgreSQL readiness path uses its exact created database and network", async () => {
  const { owner, calls } = stub(args => {
    if (args[0] === "network") return ok(ids.net);
    if (args[0] === "create") return created(args, ids.db);
    return ok();
  });
  owner.createNetwork(name("net"));
  const waits = [];
  await startPostgres({ netName: owner.network, dbName: name("db"), database: "fixture", password: "fixture" },
    owner, async ms => { waits.push(ms); });
  const creation = calls.find(args => args[0] === "create");
  assert.equal(creation[creation.indexOf("--network") + 1], ids.net);
  assert.deepEqual(calls.filter(args => args[0] === "exec").map(args => args.slice(1, 3)),
    [[ids.db, "pg_isready"], [ids.db, "psql"], [ids.db, "psql"]]);
  assert.deepEqual(waits, [1500]);
  owner.cleanup();
});

test("a database command failure exposes a finite reason and honors explicit readiness status checks", () => {
  const { owner } = stub(args => {
    if (args[0] === "create") return ok(ids.db);
    if (args[0] === "exec") return fail("private database marker");
    return ok();
  });
  owner.runDetached(name("db"), []);
  assert.throws(() => owner.exec(name("db"), ["psql"]), { message: "Vendure owned database command failed" });
  assert.equal(owner.exec(name("db"), ["pg_isready"], { allowFail: true }).status, 1);
  owner.cleanup();
});

test("collection distinguishes an active app from an observed exit", t => {
  for (const [state, expected] of [["created 0", null], ["running 0", null], ["exited 0", "0"], ["exited 9", "9"]]) {
    const { owner, calls } = stub(args => args[0] === "create" ? ok(ids.app) : args[0] === "inspect" ? ok(state) : ok());
    owner.runDetached(name("app"), []);
    assert.equal(owner.collect({ app: name("app"), worker: name("worker") }, temporary(t)), expected);
    assert.deepEqual(calls.filter(args => args[0] === "inspect"), [["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", ids.app]]);
    owner.cleanup();
  }
});

test("a kept successful fixture transfers only its creation handles to a private exclusive receipt", async t => {
  const root = temporary(t);
  const { owner, calls } = stub(args => {
    if (args[0] === "network") return ok(ids.net);
    if (args[0] === "create") return ok(ids.app);
    return args[0] === "inspect" ? ok("running 0") : ok();
  });
  const result = await runBaseline({ project: "vendure", n: 1, root, fixture: owner, keep: true,
    buildStack: ({ names }) => { owner.runDetached(names.app, []); return {}; },
    scenarios: () => [{ id: "mock", run: () => ({ assertions: { observed: true } }) }] });
  assert.equal(result.status, "passed");
  const file = path.join(result.outDir, "kept-fixture.json");
  const bytes = fs.readFileSync(file);
  assert.deepEqual(JSON.parse(bytes), { network: ids.net, containers: { [name("app")]: ids.app } });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.throws(() => owner.recordKeptHandles(result.outDir));
  assert.deepEqual(fs.readFileSync(file), bytes);
  assert.ok(!calls.some(args => args.includes("rm")));
  owner.cleanup();
});

test("a failed keep receipt falls back to owned cleanup", async t => {
  const previous = process.exitCode;
  t.after(() => { process.exitCode = previous; });
  let cleaned = false;
  const fixture = { createNetwork() {}, collect: () => null,
    recordKeptHandles() { throw new Error("private marker"); }, cleanup() { cleaned = true; } };
  const result = await runBaseline({ project: "vendure", n: 1, root: temporary(t), fixture, keep: true,
    buildStack: () => ({}), scenarios: () => [{ id: "mock", run: () => ({ assertions: { observed: true } }) }] });
  assert.equal(result.status, "failed");
  assert.equal(cleaned, true);
  const receipt = fs.readFileSync(path.join(result.outDir, "receipt.json"), "utf8");
  assert.ok(!receipt.includes("private marker"));
});
