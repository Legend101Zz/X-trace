// Instrumented-run orchestration for Node campaigns (directus, medusa, vendure).
// Launches the application on the host under the packaged `xtrace run --node-adapter ...`,
// injects privacy canaries (never logged or serialized), runs the pinned scenarios, sends
// SIGTERM cleanly to the launcher pid and awaits drain, then reads recordings back through
// the packaged viewer API (`xtrace open --viewer --no-browser`), compares semantic effect
// fingerprints against the baseline receipt, and writes `instrumented-N/receipt.json`.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { container, net, PREFIX } from "./docker.mjs";
import { runScenarios } from "./harness.mjs";
import { cleanLaunchEnv, sleep } from "./stack.mjs";

const CANARY_LOCATIONS = {
  "authorization-header": "Authorization header on dedicated canary requests",
  "cookie-header": "Cookie header on scenario and canary requests",
  "query-token": "unread query parameter xt_token on dedicated canary requests",
  "json-body-password": "JSON body field password on dedicated canary requests",
  "env-var": "application environment variable XTRACE_CANARY_ENV",
  "focused-business-secret": "JSON body field note on dedicated canary requests",
};

const REQUEST_SYMBOL = /^http\.request ([A-Z]+) (\S+)$/;
const ROUTELESS_REQUEST_SYMBOL = /^http\.request ([A-Z]+)$/;
const RESPONSE_SYMBOL = /^http\.response (\d{3})$/;
const NODE_SOURCE_EXT = /\.(?:[cm]?js|[cm]?ts)$/;
const ACCEPTED_BINDINGS = new Set(["verified", "observed_unattested"]);

function findReadiness(doc) {
  if (!doc || typeof doc !== "object") return null;
  if (typeof doc.url === "string" && typeof doc.origin === "string") {
    return { origin: doc.origin, url: doc.url };
  }
  const values = Array.isArray(doc) ? doc : Object.values(doc);
  for (const v of values) {
    const r = findReadiness(v);
    if (r) return r;
  }
  return null;
}

function bootstrapToken(url) {
  const m = /#(?:.*?[?&])?(?:token=)?([A-Za-z0-9_-]{43})(?:$|&)/.exec(url);
  return m ? m[1] : null;
}

class ViewerClient {
  constructor(origin) {
    this.origin = origin.replace(/\/+$/, "");
    const m = /^http:\/\/([^:/]+):(\d+)$/.exec(this.origin);
    if (!m) throw new Error("viewer origin must be http://127.0.0.1:<port>");
    this.host = m[1];
    this.port = Number(m[2]);
    this.cookie = null;
  }

  _req(method, reqPath, body = null) {
    return new Promise((resolve, reject) => {
      const headers = {
        Host: `${this.host}:${this.port}`,
        "Sec-Fetch-Site": "same-origin",
        "X-XTrace-Client": "viewer-v1",
        Accept: "application/json",
      };
      if (this.cookie) headers.Cookie = this.cookie;
      let payload = null;
      if (method === "POST") {
        headers.Origin = this.origin;
        headers["Content-Type"] = "application/json";
        payload = body !== null ? Buffer.from(body) : Buffer.alloc(0);
        headers["Content-Length"] = String(payload.length);
      }
      const req = http.request(
        { hostname: this.host, port: this.port, path: reqPath, method, headers, timeout: 60000 },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const raw = Buffer.concat(chunks);
            const hdrs = {};
            for (const [k, v] of Object.entries(res.headers)) {
              hdrs[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
            }
            resolve({ status: res.statusCode || 0, headers: hdrs, data: raw });
          });
        },
      );
      req.on("timeout", () => {
        req.destroy(new Error("viewer request timeout"));
      });
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async exchange(token) {
    const res = await this._req("POST", "/api/v1/auth/exchange", JSON.stringify({ token }));
    if (res.status !== 200) throw new Error(`viewer token exchange failed: HTTP ${res.status}`);
    const sc = res.headers["set-cookie"] || "";
    this.cookie = sc ? sc.split(";", 1)[0] : null;
    if (!this.cookie) throw new Error("viewer exchange returned no session cookie");
  }

  async get(reqPath) {
    const res = await this._req("GET", reqPath);
    const text = res.data.toString("utf8");
    try {
      return { status: res.status, doc: JSON.parse(text) };
    } catch {
      return { status: res.status, doc: { _nonJson: true, bytes: res.data.length } };
    }
  }
}

function listRecordingIds(xtrace, projectDir, env) {
  const ids = new Set();
  let after = null;
  for (let page = 0; page < 20; page += 1) {
    const args = ["recording", "list", "--project-dir", projectDir, "--limit", "200"];
    if (after) args.push("--after", after);
    const r = spawnSync(xtrace, args, { env, encoding: "utf8", timeout: 60000 });
    if (r.status !== 0) {
      throw new Error(`recording list before launch exited ${r.status}`);
    }
    const raw = JSON.parse(r.stdout || "{}");
    const doc = raw.data || raw;
    const rows = doc.recordings;
    if (!Array.isArray(rows)) throw new Error("recording list returned invalid rows");
    for (const row of rows) {
      if (!row || typeof row !== "object" || !row.recording_id) {
        throw new Error("recording list returned invalid row");
      }
      ids.add(row.recording_id);
    }
    after = doc.next_after || null;
    if (!after) return ids;
  }
  throw new Error("recording snapshot exceeded pagination bound");
}

function startViewer(xtrace, projectDir, env, logPath, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const errFd = fs.openSync(logPath, "a", 0o600);
    const proc = spawn(xtrace, ["open", "--project-dir", projectDir, "--viewer", "--no-browser"], {
      env,
      stdio: ["ignore", "pipe", errFd],
      detached: true,
    });
    try { fs.closeSync(errFd); } catch {}
    let settled = false;
    let buf = "";
    const stop = () => {
      try { process.kill(-proc.pid, "SIGTERM"); } catch {}
      try { proc.kill("SIGTERM"); } catch {}
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      stop();
      reject(new Error("viewer readiness line not seen"));
    }, timeoutMs);
    proc.stdout.on("data", (chunk) => {
      if (settled) return;
      buf += chunk.toString("utf8");
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("{")) continue;
        try {
          const ready = findReadiness(JSON.parse(trimmed));
          if (ready) {
            settled = true;
            clearTimeout(timer);
            resolve({ proc, ready, stop });
            return;
          }
        } catch {}
      }
    });
    proc.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    proc.on("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`viewer exited early with ${code}`));
    });
  });
}

async function collectApi(client, outDir, beforeIds, maxRecordings = 400) {
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const listing = [];
  let after = null;
  for (let page = 0; page < 20; page += 1) {
    const q = "/api/v1/recordings?limit=200" + (after ? `&after=${encodeURIComponent(after)}` : "");
    const { status, doc } = await client.get(q);
    fs.writeFileSync(path.join(outDir, `recordings-page-${page}.json`), JSON.stringify(doc, null, 1) + "\n", { mode: 0o600 });
    if (status !== 200) {
      return { ok: false, reason: `recordings list HTTP ${status}`, recordings: [], details: {} };
    }
    listing.push(...(doc.recordings || []));
    after = doc.nextAfter || null;
    if (!after || listing.length >= maxRecordings) break;
  }
  const freshListing = listing.filter((r) => r?.recordingId && !beforeIds.has(r.recordingId)).slice(0, maxRecordings);
  fs.writeFileSync(path.join(outDir, "recordings.json"), JSON.stringify({ recordings: freshListing }, null, 1) + "\n", { mode: 0o600 });
  const details = {};
  for (const rec of freshListing) {
    const rid = rec.recordingId;
    const events = [];
    let cursor = null;
    let first = null;
    for (let p = 0; p < 40; p += 1) {
      const q = `/api/v1/recordings/${encodeURIComponent(rid)}?limit=1000` + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");
      const { status, doc } = await client.get(q);
      if (status !== 200) {
        first = first || { _http: status, events: [] };
        break;
      }
      if (!first) {
        const { events: _ev, ...rest } = doc;
        first = rest;
      }
      events.push(...(doc.events || []));
      cursor = doc.nextCursor || null;
      if (!cursor) break;
    }
    const detail = { ...(first || {}), recordingId: rid, events };
    if (rec.openedAt !== undefined) detail._openedAt = rec.openedAt;
    details[rid] = detail;
    fs.writeFileSync(path.join(outDir, `recording-${rid}.json`), JSON.stringify(detail, null, 1) + "\n", { mode: 0o600 });
  }
  return { ok: true, reason: "", recordings: freshListing, details };
}

function requestInfo(detail) {
  for (const ev of detail.events || []) {
    const sym = ev.symbol || "";
    const m = REQUEST_SYMBOL.exec(sym);
    if (m) return { method: m[1], route: m[2] };
  }
  return null;
}

function routelessMethod(detail) {
  if (requestInfo(detail)) return null;
  for (const ev of detail.events || []) {
    const m = ROUTELESS_REQUEST_SYMBOL.exec(ev.symbol || "");
    if (m) return m[1];
  }
  return null;
}

function recordingHttpStatus(detail) {
  const o = detail.outcome;
  if (o && typeof o === "object" && Number.isInteger(o.httpStatus) && o.httpStatus >= 100 && o.httpStatus <= 599) {
    return o.httpStatus;
  }
  for (const ev of detail.events || []) {
    const m = RESPONSE_SYMBOL.exec(ev.symbol || "");
    if (m) return Number(m[1]);
  }
  return null;
}

function trimRoute(r) {
  const stripped = String(r || "").split("?", 1)[0].replace(/\/+$/, "");
  return stripped || "/";
}

function hasParam(route) {
  return route.includes("{") || /(?:^|\/):[^/]+/.test(route);
}

function normalizeParamShape(route) {
  return trimRoute(route)
    .split("/")
    .map((seg) => (seg.startsWith("{") && seg.endsWith("}")) || seg.startsWith(":") ? "<P>" : seg)
    .join("/");
}

function templateRegex(template) {
  const parts = trimRoute(template)
    .split("/")
    .map((seg) => {
      if ((seg.startsWith("{") && seg.endsWith("}")) || seg.startsWith(":")) return "[^/?#]+";
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    });
  return new RegExp("^" + parts.join("/") + "/?(?:\\?.*)?$");
}

function routeMatches(recordedRoute, scenarioRoute, literalRoutes) {
  const rec = trimRoute(recordedRoute);
  const want = trimRoute(scenarioRoute);
  if (rec === want) return true;
  const recHasParam = hasParam(rec);
  const wantHasParam = hasParam(want);
  if (recHasParam && wantHasParam) {
    return normalizeParamShape(rec) === normalizeParamShape(want);
  }
  if (recHasParam && !wantHasParam) {
    return templateRegex(rec).test(want);
  }
  if (!recHasParam && wantHasParam) {
    if (literalRoutes.has(rec)) return false;
    return templateRegex(want).test(rec);
  }
  return false;
}

function recordingMatches(detail, method, route, literalRoutes, allowRouteless = false) {
  const info = requestInfo(detail);
  if (info) {
    if (info.method !== method) return false;
    if (routeMatches(info.route, route, literalRoutes)) return true;
    return false;
  }
  if (allowRouteless) {
    return routelessMethod(detail) === method;
  }
  return false;
}

function eventKindName(ev) {
  return String(ev?.kind || "").replace(/^recording_event_kind:/, "");
}

function hasRootFrame(detail) {
  return (detail.events || []).some((ev) => eventKindName(ev) === "frame_enter" && ev.symbol === "node:http.Server.request");
}

function countDbInteractions(detail) {
  return (detail.events || []).filter((ev) => {
    const k = eventKindName(ev);
    return k === "database_start" || k === "database_end" || ev?.interaction?.kind === "database";
  }).length;
}

function countOutboundHttp(detail) {
  return (detail.events || []).filter((ev) => {
    const k = eventKindName(ev);
    return k === "outbound_http_start" || k === "outbound_http_end" || ev?.interaction?.kind === "outbound_http";
  }).length;
}

function bindingState(ev) {
  const s = ev?.source && typeof ev.source === "object" ? ev.source : {};
  for (const holder of [ev, s]) {
    for (const key of ["sourceBinding", "binding"]) {
      const v = holder?.[key];
      if (typeof v === "string" && v.length > 0) {
        const norm = v.toLowerCase().replace("source_binding_", "").replace(/-/g, "_");
        return ACCEPTED_BINDINGS.has(norm) ? "ok" : "bad";
      }
    }
  }
  return "missing";
}

function isMatchedNodeSourceFrame(ev) {
  if (eventKindName(ev) !== "frame_enter") return false;
  const s = ev.source;
  return Boolean(
    s &&
      typeof s === "object" &&
      typeof s.path === "string" &&
      NODE_SOURCE_EXT.test(s.path) &&
      Number.isInteger(s.startLine) &&
      s.startLine >= 1 &&
      s.status === "matched",
  );
}

function recordingHasSource(detail) {
  return (detail.events || []).some((ev) => isMatchedNodeSourceFrame(ev) && bindingState(ev) === "ok");
}

function recordingSourceBindingProblems(detail) {
  const out = new Set();
  for (const ev of detail.events || []) {
    if (!isMatchedNodeSourceFrame(ev)) continue;
    const state = bindingState(ev);
    if (state === "bad") out.add("source-binding-unacceptable");
    else if (state === "missing") out.add("source-binding-missing");
  }
  return out;
}

function collectLimitations(details) {
  const out = new Set();
  for (const d of Object.values(details)) {
    for (const list of [d.limitations, d.sessionContext?.limitations]) {
      if (Array.isArray(list)) {
        for (const item of list) {
          if (typeof item === "string" && item) out.add(item);
        }
      }
    }
  }
  return [...out].sort();
}

function analyzeNodeRecordings(details, scenarioResults, scenarioSpecs = {}) {
  const allDetails = Object.values(details);
  const literalRoutes = new Set();
  for (const sc of scenarioResults) {
    for (const req of sc.requests || []) {
      const r = trimRoute(req.route);
      if (!hasParam(r)) literalRoutes.add(r);
    }
  }
  const verdicts = {};
  const allMatchedScenarioDetails = new Map();
  for (const sc of scenarioResults) {
    const spec = scenarioSpecs[sc.id] || {};
    const allowRouteless = Boolean(spec.allowRouteless);
    const groups = new Map();
    for (const req of sc.requests || []) {
      const key = `${req.method} ${req.route}`;
      if (!groups.has(key)) groups.set(key, { method: req.method, route: req.route, statuses: [] });
      groups.get(key).statuses.push(req.status);
    }
    const items = [];
    const matchedScenarioDetails = new Map();
    const frameSymbols = new Set();
    let dbCount = 0;
    let outboundCount = 0;
    for (const grp of groups.values()) {
      const matched = allDetails.filter((d) => recordingMatches(d, grp.method, grp.route, literalRoutes, allowRouteless));
      const problems = [];
      if (!matched.length) {
        problems.push("no-recording-for-route");
      } else if (matched.length < grp.statuses.length) {
        problems.push(`count-below-minimum(need ${grp.statuses.length}, have ${matched.length})`);
      }
      const wantedCounts = new Map();
      for (const st of grp.statuses) wantedCounts.set(st, (wantedCounts.get(st) || 0) + 1);
      const observedCounts = new Map();
      const withStatus = [];
      for (const d of matched) {
        const st = recordingHttpStatus(d);
        const kind = d?.outcome?.kind;
        if (st !== null && (kind === "responded" || kind === "exception_propagated")) {
          observedCounts.set(st, (observedCounts.get(st) || 0) + 1);
          if (wantedCounts.has(st)) withStatus.push(d);
        }
      }
      if (matched.length) {
        for (const [st, need] of wantedCounts.entries()) {
          const have = observedCounts.get(st) || 0;
          if (have < need) {
            problems.push(`http-outcome-mismatch(expected ${st}x${need}, saw ${have})`);
          }
        }
      }
      const withRoot = withStatus.filter(hasRootFrame);
      if (withStatus.length && !withRoot.length) {
        problems.push("no-http-root-frame");
      }
      const withSrc = withStatus.filter(recordingHasSource);
      const srcBindingProblems = new Set();
      for (const d of matched) {
        matchedScenarioDetails.set(d.recordingId, d);
        allMatchedScenarioDetails.set(d.recordingId, d);
        for (const p of recordingSourceBindingProblems(d)) srcBindingProblems.add(p);
        for (const ev of d.events || []) {
          if (eventKindName(ev) === "frame_enter" && typeof ev.symbol === "string" && ev.symbol) {
            frameSymbols.add(ev.symbol);
          }
        }
      }
      for (const p of srcBindingProblems) problems.push(p);
      items.push({
        method: grp.method,
        route: grp.route,
        expectedStatuses: grp.statuses,
        recordingsMatchingRoute: matched.length,
        recordingsWithStatus: withStatus.length,
        recordingsWithRootFrame: withRoot.length,
        recordingsWithSource: withSrc.length,
        problems,
        passed: problems.length === 0,
      });
    }
    for (const d of matchedScenarioDetails.values()) {
      dbCount += countDbInteractions(d);
      outboundCount += countOutboundHttp(d);
    }
    const scenarioProblems = [];
    if (spec.expectDb && dbCount === 0) scenarioProblems.push("no-db-interaction");
    if (spec.expectOutbound && outboundCount === 0) scenarioProblems.push("no-outbound-http-interaction");
    if (scenarioProblems.length && items.length) {
      items[0].problems.push(...scenarioProblems);
      items[0].passed = false;
    } else if (scenarioProblems.length) {
      items.push({
        method: "*",
        route: "*",
        expectedStatuses: [],
        recordingsMatchingRoute: 0,
        recordingsWithStatus: 0,
        recordingsWithRootFrame: 0,
        recordingsWithSource: 0,
        problems: scenarioProblems,
        passed: false,
      });
    }
    verdicts[sc.id] = {
      passed: items.length > 0 && items.every((i) => i.passed),
      expectations: items,
      recordingsAttributed: matchedScenarioDetails.size,
      dbInteractions: dbCount,
      outboundHttpInteractions: outboundCount,
      frameSymbols: [...frameSymbols].sort(),
    };
  }
  const problemClasses = {};
  for (const v of Object.values(verdicts)) {
    for (const it of v.expectations) {
      for (const p of it.problems) {
        const key = p.split("(")[0];
        problemClasses[key] = (problemClasses[key] || 0) + 1;
      }
    }
  }
  const matchedList = [...allMatchedScenarioDetails.values()];
  return {
    verdicts,
    problemClasses,
    observedLimitations: collectLimitations(details),
    recordingsWithSource: matchedList.filter(recordingHasSource).length,
    recordingsWithStatus: allDetails.filter((d) => recordingHttpStatus(d) !== null).length,
  };
}

function loadBaselineFingerprints(baselineReceiptPath) {
  if (!baselineReceiptPath || !fs.existsSync(baselineReceiptPath)) return null;
  const doc = JSON.parse(fs.readFileSync(baselineReceiptPath, "utf8"));
  if (doc.status !== "passed") return null;
  let raw = null;
  if (doc.fingerprints && typeof doc.fingerprints === "object") {
    raw = doc.fingerprints;
  } else if (Array.isArray(doc.scenarios)) {
    raw = Object.fromEntries(doc.scenarios.map((s) => [s.id, s.semanticEffectFingerprint ?? null]));
  }
  if (!raw) return null;
  const valid = Object.fromEntries(
    Object.entries(raw).filter(([, fp]) => typeof fp === "string" && fp.length > 0),
  );
  return Object.keys(valid).length > 0 ? valid : null;
}

function loadRequiredCanaries(canaryFile) {
  if (!canaryFile) return null;
  if (!fs.existsSync(canaryFile)) {
    throw new Error("XCAMP_CANARY_FILE is set but does not exist");
  }
  const parsed = JSON.parse(fs.readFileSync(canaryFile, "utf8"));
  if (!parsed || typeof parsed !== "object") {
    throw new Error("XCAMP_CANARY_FILE must contain a JSON object");
  }
  const missing = Object.keys(CANARY_LOCATIONS).filter(
    (k) => typeof parsed[k] !== "string" || parsed[k].length === 0,
  );
  if (missing.length > 0) {
    throw new Error(`XCAMP_CANARY_FILE missing required canary classes: ${missing.join(", ")}`);
  }
  return parsed;
}

async function sendCanaryRequests(baseUrl, canaries, targets) {
  const results = [];
  for (const { method, path: basePath } of targets) {
    const qs = `xt_token=${encodeURIComponent(canaries["query-token"] || "")}`;
    const reqUrl = `${baseUrl}${basePath}${basePath.includes("?") ? "&" : "?"}${qs}`;
    const headers = {
      authorization: canaries["authorization-header"] || "",
      cookie: canaries["cookie-header"] || "",
      "content-type": "application/json",
    };
    const body =
      method === "GET" || method === "HEAD"
        ? undefined
        : JSON.stringify({
            email: "xt-canary@example.invalid",
            username: "xt-canary-user",
            password: canaries["json-body-password"] || "",
            note: canaries["focused-business-secret"] || "",
          });
    try {
      const r = await fetch(reqUrl, { method, headers, body, signal: AbortSignal.timeout(15000) });
      await r.text().catch(() => "");
      results.push({ method, path: basePath, status: r.status });
    } catch (e) {
      results.push({ method, path: basePath, error: e?.name || "FetchError" });
    }
  }
  return results;
}

export async function runInstrumented({
  project,
  root,
  projectDir,
  buildStack,
  scenarios,
  scenarioSpecs = {},
  canaryRequests = [],
  meta = {},
}) {
  const xtraceBin = process.env.XCAMP_XTRACE;
  const nodeAdapter = process.env.XCAMP_NODE_ADAPTER;
  const dataHome = process.env.XCAMP_DATA_HOME;
  const nodeMode = process.env.XCAMP_NODE_MODE || "auto";
  if (!xtraceBin || !fs.existsSync(xtraceBin)) throw new Error("XCAMP_XTRACE is required and must exist");
  if (!nodeAdapter || !fs.existsSync(nodeAdapter)) throw new Error("XCAMP_NODE_ADAPTER is required and must exist");
  if (!dataHome) throw new Error("XCAMP_DATA_HOME is required");
  fs.mkdirSync(dataHome, { recursive: true, mode: 0o700 });

  let n = 1;
  while (fs.existsSync(path.join(root, `instrumented-${n}`))) n += 1;
  const outDir = path.join(root, `instrumented-${n}`);
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

  const canaryFile = process.env.XCAMP_CANARY_FILE;
  const canaries = loadRequiredCanaries(canaryFile);
  const xtraceEnv = cleanLaunchEnv({ XTRACE_DATA_HOME: dataHome });

  const notes = { nodeMode };
  const initRes = spawnSync(xtraceBin, ["init", "--project-dir", projectDir, "--display-name", project], {
    env: xtraceEnv,
    encoding: "utf8",
    timeout: 120000,
  });
  notes.init = { exitCode: initRes.status };
  if (initRes.status !== 0) {
    throw new Error(`xtrace init failed with exit ${initRes.status}`);
  }
  const beforeIds = listRecordingIds(xtraceBin, projectDir, xtraceEnv);
  if (canaries) {
    notes.canaryLocations = { ...CANARY_LOCATIONS };
  }

  const launchPrefix = [
    xtraceBin,
    "run",
    "--project-dir",
    projectDir,
    "--node-adapter",
    nodeAdapter,
    "--node-mode",
    nodeMode,
    "--",
  ];
  const appExtraEnv = {
    XTRACE_DATA_HOME: dataHome,
    ...(canaries?.["env-var"] ? { XTRACE_CANARY_ENV: canaries["env-var"] } : {}),
  };

  const tag = `i${n}`;
  const names = {
    net: `${PREFIX}${project}-${tag}-net`,
    db: `${PREFIX}${project}-${tag}-db`,
    app: `${PREFIX}${project}-${tag}-app`,
    worker: `${PREFIX}${project}-${tag}-worker`,
    dep: `${PREFIX}${project}-${tag}-dep`,
  };
  const appLogPath = path.join(outDir, "application.log");
  fs.writeFileSync(appLogPath, "", { mode: 0o600 });

  const startedAt = Date.now();
  let bootMs = null;
  let ctx = null;
  let summary = null;
  let failure = null;
  let sentCount = 0;

  // Scenario hook injects only Cookie canary so no app's auth/strict-query validation alters fingerprints.
  const requestHook = canaries?.["cookie-header"]
    ? ({ headers }) => {
        const hasCookie = Object.keys(headers).some((k) => k.toLowerCase() === "cookie");
        if (!hasCookie) headers.cookie = canaries["cookie-header"];
        return { headers };
      }
    : null;

  try {
    net.create(names.net);
    const t0 = Date.now();
    ctx = await buildStack({
      names,
      outDir,
      launchPrefix,
      extraEnv: appExtraEnv,
      logFile: appLogPath,
    });
    bootMs = Date.now() - t0;
    summary = await runScenarios({
      project,
      baseUrl: ctx.baseUrl,
      outDir,
      scenarios: scenarios(ctx),
      ctxExtra: ctx.extra || {},
      requestHook,
      onCall: () => { sentCount += 1; },
      kind: "instrumented_campaign_non_release",
    });
    if (canaries && canaryRequests.length) {
      notes.canaryRequests = await sendCanaryRequests(ctx.baseUrl, canaries, canaryRequests);
      sentCount += canaryRequests.length;
    }
  } catch (e) {
    failure = String(e && e.message).slice(0, 800);
    console.error("instrumented run failed:", failure);
  } finally {
    if (ctx?.stopHost) {
      notes.launcherExitCode = await ctx.stopHost(30000);
    }
    if (ctx?.stopWorker) {
      await ctx.stopWorker(15000);
    }
    for (const extra of ["dep"]) {
      const l = container.logs(names[extra]);
      if (l.stdout || l.stderr) {
        fs.writeFileSync(path.join(outDir, `${extra}.log`), (l.stdout || "") + (l.stderr || ""), { mode: 0o600 });
      }
    }
    container.rm(names.worker);
    container.rm(names.dep);
    container.rm(names.app);
    container.rm(names.db);
    net.rm(names.net);
  }

  const stopRes = spawnSync(xtraceBin, ["stop", "--project-dir", projectDir], {
    env: xtraceEnv,
    encoding: "utf8",
    timeout: 60000,
  });
  notes.stopCommand = { exitCode: stopRes.status, notImplemented: stopRes.status === 9 };

  let api = { ok: false, reason: "viewer not started", recordings: [], details: {} };
  const viewerLogPath = path.join(outDir, "viewer.log");
  fs.writeFileSync(viewerLogPath, "", { mode: 0o600 });
  let viewer = null;
  try {
    viewer = await startViewer(xtraceBin, projectDir, xtraceEnv, viewerLogPath);
    const client = new ViewerClient(viewer.ready.origin);
    const token = bootstrapToken(viewer.ready.url);
    if (!token) throw new Error("no bootstrap token in viewer url");
    await client.exchange(token);
    api = await collectApi(client, path.join(outDir, "api"), beforeIds);
  } catch (e) {
    api = { ok: false, reason: `${e?.name || "Error"}: ${String(e?.message || e).slice(0, 200)}`, recordings: [], details: {} };
  } finally {
    if (viewer) {
      viewer.stop();
      await sleep(300);
    }
  }

  const scenarioResults = summary?.scenarios || [];
  const analysis = api.ok
    ? analyzeNodeRecordings(api.details, scenarioResults, scenarioSpecs)
    : { verdicts: {}, problemClasses: {}, observedLimitations: [], recordingsWithSource: 0, recordingsWithStatus: 0 };

  const baselineFp = loadBaselineFingerprints(process.env.XCAMP_BASELINE_RECEIPT || path.join(root, "baseline-1", "receipt.json"));
  const scenOut = scenarioResults.map((r) => {
    const v = analysis.verdicts[r.id] || null;
    const baseFp = baselineFp && typeof baselineFp[r.id] === "string" && baselineFp[r.id].length > 0 ? baselineFp[r.id] : null;
    const instrFp = typeof r.semanticEffectFingerprint === "string" && r.semanticEffectFingerprint.length > 0 ? r.semanticEffectFingerprint : null;
    return {
      id: r.id,
      scenarioChecksPassed: r.result === "passed",
      semanticEffectFingerprint: instrFp,
      baselineFingerprint: baseFp,
      fingerprintEqualsBaseline: baselineFp ? Boolean(baseFp && instrFp && baseFp === instrFp) : null,
      frameSymbols: v ? v.frameSymbols : [],
      recordingVerdict: v,
      requests: (r.requests || []).map((q) => ({ label: q.label, method: q.method, route: q.route, status: q.status, elapsedMs: q.durationMs })),
      elapsedMs: r.durationMs,
    };
  });

  const workloadsPassed = scenarioResults.length > 0 && scenarioResults.every((r) => r.result === "passed");
  const receipt = {
    schemaVersion: 1,
    kind: "instrumented_campaign_non_release",
    runtime: "node",
    project,
    releaseAcceptance: false,
    instrumented: true,
    signed: false,
    syntheticDataOnly: true,
    bootMs,
    durationSeconds: Number(((Date.now() - startedAt) / 1000).toFixed(1)),
    failure,
    notes,
    api: { ok: api.ok, reason: api.reason, recordings: api.recordings.length },
    requestsSent: sentCount,
    problemClasses: analysis.problemClasses,
    observedLimitations: analysis.observedLimitations,
    recordingsWithSource: analysis.recordingsWithSource,
    recordingsWithStatus: analysis.recordingsWithStatus,
    scenarios: scenOut,
    result: api.ok && workloadsPassed && !failure ? "recorded" : "failed",
    ...meta,
  };
  fs.writeFileSync(path.join(outDir, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
  console.log(JSON.stringify({ project, instrumented: n, result: receipt.result, recordings: api.recordings.length, scenarios: scenOut.length }));
  if (receipt.result !== "recorded") process.exitCode = 1;
  return { outDir, receipt };
}
