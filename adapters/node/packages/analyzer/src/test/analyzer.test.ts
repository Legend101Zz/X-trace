import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { analyze, type Framework } from "../analyzer.js";

const FIXTURES = path.resolve(import.meta.dirname, "../../test-fixtures");
const CONTRACT = path.resolve(import.meta.dirname, "../../../../../../schema/fixtures/static-claim-contract.json");

interface Claim {
  type: string;
  method: string;
  routeParts: string[];
  routeBasis: string;
  handler?: string;
  limitations: string[];
  evidence: { path: string; startLine: number };
}

function run(fixture: string, framework: Framework): { claims: Claim[]; lines: Record<string, unknown>[] } {
  const lines = analyze({ root: path.join(FIXTURES, fixture), framework }).map(
    (line) => JSON.parse(line) as Record<string, unknown>,
  );
  return { claims: lines.filter((l) => l["type"] === "claim") as unknown as Claim[], lines };
}

function find(claims: Claim[], method: string, parts: string[]): Claim {
  const hit = claims.filter((c) => c.method === method && JSON.stringify(c.routeParts) === JSON.stringify(parts));
  assert.equal(hit.length, 1, `${method} ${JSON.stringify(parts)} in ${JSON.stringify(claims.map((c) => [c.method, c.routeParts]))}`);
  return hit[0] as Claim;
}

test("express_router_mount_prefix_join", () => {
  const { claims } = run("express-basic", "express");
  // app.use(API + '/users', usersRouter) with API a const: prefix is a resolved constant.
  const list = find(claims, "GET", ["/api/users", "/"]);
  assert.equal(list.routeBasis, "concatenated");
  assert.deepEqual(list.limitations, []);
  assert.equal(list.handler, "list");
  find(claims, "GET", ["/api/users", "/:id"]);
  // router.route('/:id/posts').get(...).post(...)
  find(claims, "GET", ["/api/users", "/:id/posts"]);
  find(claims, "POST", ["/api/users", "/:id/posts"]);
  // named export of a router, mounted from another file
  find(claims, "DELETE", ["/admin", "/users/:id"]);
  // require() call as the mounted router, prefix from a constant in another file
  find(claims, "GET", ["/v2", "/status"]);
});

test("express_app_routes_and_non_routes", () => {
  const { claims } = run("express-basic", "express");
  const health = find(claims, "GET", ["/health"]);
  assert.equal(health.routeBasis, "literal");
  assert.deepEqual(health.limitations, []);
  find(claims, "POST", ["/items/:itemId"]);
  // axios.get('/remote', ...) and app.get('env') are not routes
  assert.equal(claims.filter((c) => JSON.stringify(c.routeParts).includes("remote")).length, 0);
  assert.equal(claims.filter((c) => JSON.stringify(c.routeParts).includes("env")).length, 0);
});

test("express_all_is_unconstrained_with_ambiguity_code", () => {
  const { claims } = run("express-basic", "express");
  for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) {
    assert.deepEqual(find(claims, method, ["/any"]).limitations, ["mapping_method_unconstrained"]);
  }
});

test("computed_route_yields_limitation", () => {
  const { claims } = run("express-basic", "express");
  const computed = claims.find((c) => c.routeParts.includes("{unresolved}"));
  assert.ok(computed, "computed route claim present");
  assert.equal(computed.routeBasis, "computed");
  assert.deepEqual(computed.limitations, ["route_constant_unresolved"]);
});

test("unmounted_router_is_flagged_not_dropped", () => {
  const { claims } = run("express-basic", "express");
  const lonely = find(claims, "GET", ["/lonely"]);
  assert.deepEqual(lonely.limitations, ["mount_unresolved"]);
  // an unknown prefix must not keep literal confidence
  assert.equal(lonely.routeBasis, "computed");
});

test("unresolvable_fastify_register_makes_the_scan_incomplete", () => {
  const { claims, lines } = run("fastify-unresolved", "fastify");
  find(claims, "GET", ["/ping"]);
  assert.ok(lines.some((l) => l["type"] === "diagnostic" && l["code"] === "unsupported_syntax"));
  const end = lines[lines.length - 1] as { complete: boolean; incompleteReasons: string[] };
  assert.equal(end.complete, false);
  assert.deepEqual(end.incompleteReasons, ["unsupported_syntax"]);
});

test("fastify_register_prefix_join", () => {
  const { claims, lines } = run("fastify-basic", "fastify");
  find(claims, "GET", ["/ping"]);
  const user = find(claims, "GET", ["/v1", "/users/:id"]);
  assert.equal(user.routeBasis, "concatenated");
  find(claims, "POST", ["/v1", "/users"]);
  find(claims, "GET", ["/multi"]);
  find(claims, "HEAD", ["/multi"]);
  const end = lines[lines.length - 1] as { complete: boolean };
  assert.equal(end.complete, true);
});

test("nest_controller_prefix_join", () => {
  const { claims } = run("nest-basic", "nest");
  // setGlobalPrefix('v1') applies to every controller
  const all = find(claims, "GET", ["v1", "cats", ""]);
  assert.equal(all.handler, "CatsController#findAll");
  find(claims, "GET", ["v1", "cats", ":id"]);
  find(claims, "POST", ["v1", "cats", ""]);
  find(claims, "GET", ["v1", "cats", "a"]);
  find(claims, "GET", ["v1", "cats", "b"]);
  for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) {
    assert.deepEqual(find(claims, method, ["v1", "dogs", "bark"]).limitations, ["mapping_method_unconstrained"]);
  }
  assert.equal(claims.filter((c) => JSON.stringify(c.routeParts).includes("nope")).length, 0);
});

test("parse_error_makes_the_scan_incomplete_but_keeps_other_claims", () => {
  const { claims, lines } = run("broken", "express");
  find(claims, "GET", ["/good"]);
  assert.ok(lines.some((l) => l["type"] === "diagnostic" && l["code"] === "parse_error" && l["path"] === "app.js"));
  const end = lines[lines.length - 1] as { complete: boolean; incompleteReasons: string[] };
  assert.equal(end.complete, false);
  assert.deepEqual(end.incompleteReasons, ["parse_error"]);
});

test("file_budget_makes_the_scan_incomplete", () => {
  const lines = analyze({ root: path.join(FIXTURES, "express-basic"), framework: "express", maxFiles: 2 });
  const end = JSON.parse(lines[lines.length - 1] as string) as { incompleteReasons: string[] };
  assert.deepEqual(end.incompleteReasons, ["budget_exceeded"]);
});

test("output_is_deterministic_and_follows_the_shared_contract", () => {
  const first = analyze({ root: path.join(FIXTURES, "express-basic"), framework: "express" });
  assert.deepEqual(first, analyze({ root: path.join(FIXTURES, "express-basic"), framework: "express" }));
  const contract = JSON.parse(fs.readFileSync(CONTRACT, "utf8")) as {
    limitationCodes: string[];
    frameworkFamilies: string[];
    diagnosticCodes: string[];
  };
  for (const [fixture, framework] of [
    ["express-basic", "express"],
    ["fastify-basic", "fastify"],
    ["nest-basic", "nest"],
    ["broken", "express"],
  ] as [string, Framework][]) {
    const { lines } = run(fixture, framework);
    const header = lines[0] as { framework: string; contractVersion: number };
    assert.equal(header.contractVersion, 1);
    assert.ok(contract.frameworkFamilies.includes(header.framework));
    for (const line of lines) {
      if (line["type"] === "claim") {
        for (const code of (line as unknown as Claim).limitations) assert.ok(contract.limitationCodes.includes(code), code);
      }
      if (line["type"] === "diagnostic") assert.ok(contract.diagnosticCodes.includes(line["code"] as string));
    }
  }
});

test("analyzer_does_not_import_target", () => {
  const marker = path.join(os.tmpdir(), "xtrace-node-analyzer-marker");
  const processMarker = path.join(process.cwd(), "xtrace-node-analyzer-process-marker");
  fs.rmSync(marker, { force: true });
  fs.rmSync(processMarker, { force: true });
  const { claims } = run("side-effect", "express");
  find(claims, "GET", ["/side-effect"]);
  assert.equal(fs.existsSync(marker), false, "analyzed code must not run");
  assert.equal(fs.existsSync(processMarker), false, "analyzed code must not start processes");
});

test("analyzer_sources_contain_no_execution_apis", () => {
  const dir = path.resolve(import.meta.dirname, "../../src");
  const forbidden = /child_process|\beval\s*\(|new Function|vm\.run|require\s*\(|import\s*\(|worker_threads/;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".ts")) continue;
    const text = fs.readFileSync(path.join(dir, name), "utf8");
    assert.equal(forbidden.test(text.replace(/isRequire|requireTarget|"require"|`require`|require\('x'\)|require\(\)/g, "")), false, name);
  }
});

test("workspace_tsc_is_the_pinned_compiler_not_the_parser_alias", () => {
  // `typescript-parser` (npm alias of typescript@6) also ships a `tsc` bin. If link order ever lets it
  // own `.bin/tsc`, the whole Node workspace would silently compile with the wrong compiler.
  const nodeRoot = path.resolve(import.meta.dirname, "../../../..");
  const tsc = fs.realpathSync(path.join(nodeRoot, "node_modules/.bin/tsc"));
  assert.ok(!tsc.includes(`${path.sep}typescript-parser${path.sep}`), `tsc resolves to the alias: ${tsc}`);
  const pkg = JSON.parse(fs.readFileSync(path.join(nodeRoot, "node_modules/typescript/package.json"), "utf8")) as {
    version: string;
  };
  const root = JSON.parse(fs.readFileSync(path.join(nodeRoot, "package.json"), "utf8")) as {
    devDependencies?: Record<string, string>;
  };
  assert.equal(pkg.version, root.devDependencies?.["typescript"]);
});

test("build_outputs_are_skipped_only_next_to_a_project_file_and_test_sources_are_excluded", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-analyzer-"));
  try {
    const write = (rel: string, body: string): void => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    };
    const app = "const express = require('express');\nconst app = express();\n";
    write("package.json", "{}");
    write("src/dist/routes.js", `${app}app.get('/in-dist-package', h);\n`);
    write("dist/generated.js", `${app}app.get('/build-output', h);\n`);
    write("src/users.spec.js", `${app}app.get('/spec', h);\n`);
    write("src/__tests__/t.js", `${app}app.get('/under-tests', h);\n`);
    const lines = analyze({ root: dir, framework: "express" }).map((l) => JSON.parse(l) as Record<string, unknown>);
    const claims = lines.filter((l) => l["type"] === "claim") as unknown as Claim[];
    const paths = claims.map((c) => JSON.stringify(c.routeParts));
    assert.deepEqual(paths, ['["/in-dist-package"]']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
