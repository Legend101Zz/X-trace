import fs from "node:fs";
import http from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { canonicalJson } from "../../lib/canonical.mjs";

export function requireFact(ok, code) { if (!ok) throw new Error(code); }

export function validateEvents(events) {
  let previous = -1n;
  for (const event of events) {
    requireFact(typeof event.sequence === "string" && /^[0-9]+$/.test(event.sequence), "event_sequence_schema");
    const sequence = BigInt(event.sequence);
    requireFact(sequence > previous, "event_sequence_not_increasing"); previous = sequence;
  }
  return events;
}

/** A repeated cursor or ID is a failure, never a successful truncated inventory. */
export async function pages(load, { rowsKey, cursorKey, maxPages = 20, maxRows = 400 }) {
  const rows = [], cursors = new Set();
  let cursor = null;
  for (let page = 0; page < maxPages; page++) {
    const doc = await load(cursor);
    requireFact(Array.isArray(doc[rowsKey]), "readback_page_schema");
    rows.push(...doc[rowsKey]);
    requireFact(rows.length <= maxRows, "readback_row_bound");
    cursor = doc[cursorKey];
    requireFact(cursor === null || typeof cursor === "string" && cursor.length > 0, "readback_cursor_schema");
    requireFact(cursor === null || doc[rowsKey].length > 0, "readback_empty_continuation");
    if (cursor === null) return rows;
    requireFact(!cursors.has(cursor), "readback_repeated_cursor");
    cursors.add(cursor);
  }
  throw new Error("readback_page_bound");
}

function request(origin, method, url, cookie, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(origin + url, { method, headers: {
      "Sec-Fetch-Site": "same-origin", "X-XTrace-Client": "viewer-v1", Accept: "application/json",
      ...(cookie ? { Cookie: cookie } : {}),
      ...(method === "POST" ? { Origin: origin, "Content-Type": "application/json" } : {}),
    } }, (res) => {
      const chunks = []; let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) res.destroy(new Error("viewer_response_bound"));
        else chunks.push(chunk);
      });
      res.on("error", reject);
      res.on("end", () => {
        try { requireFact(res.statusCode === 200, "viewer_http_status");
          resolve({ doc: JSON.parse(Buffer.concat(chunks).toString("utf8")), cookie: res.headers["set-cookie"]?.[0]?.split(";")[0] });
        } catch { reject(new Error("viewer_response_invalid")); }
      });
    });
    req.setTimeout(60000, () => req.destroy(new Error("viewer_request_deadline")));
    req.on("error", () => reject(new Error("viewer_transport")));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

async function stop(child) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
  const done = once(child, "exit");
  child.kill("SIGTERM");
  let forced = false;
  const timer = setTimeout(() => { forced = true; child.kill("SIGKILL"); }, 15000);
  try { await done; } finally { clearTimeout(timer); }
  requireFact(!forced, "viewer_shutdown_deadline");
}

export async function readback({ cli, project, env, call, outDir }) {
  const listing = await pages((cursor) => call("list", ["recording", "list", "--limit", "200", ...(cursor ? ["--after", cursor] : [])]),
    { rowsKey: "recordings", cursorKey: "next_after" });
  const ids = listing.map((r) => r.recording_id);
  requireFact(ids.every((id) => /^[a-f0-9-]{36}$/.test(id)) && new Set(ids).size === ids.length, "recording_id_inventory");
  const cliDetails = {};
  for (const id of ids) {
    let first;
    const events = await pages((cursor) => {
      const doc = call("show", ["recording", "show", id, "--limit", "1000", ...(cursor ? ["--cursor", cursor] : [])]);
      requireFact(doc.recording_id === id, "cli_recording_identity");
      requireFact(!first || first.completion === doc.completion && canonicalJson(first.outcome) === canonicalJson(doc.outcome), "cli_recording_changed_during_read");
      first ||= doc; return doc;
    }, { rowsKey: "events", cursorKey: "next_cursor", maxRows: 20000 });
    cliDetails[id] = { ...first, events: validateEvents(events) };
  }
  fs.writeFileSync(outDir + "/cli-readback.json", JSON.stringify(cliDetails), { mode: 0o600 });
  const err = fs.openSync(outDir + "/viewer.stderr", "wx", 0o600);
  const viewer = spawn(cli, ["open", "--project-dir", project, "--viewer", "--no-browser"], { env, stdio: ["ignore", "pipe", err] });
  fs.closeSync(err);
  let stream = "";
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("viewer_readiness_deadline")), 60000);
    viewer.once("error", () => { clearTimeout(timer); reject(new Error("viewer_spawn")); });
    viewer.once("exit", () => { clearTimeout(timer); reject(new Error("viewer_early_exit")); });
    viewer.stdout.on("data", (chunk) => {
      stream += chunk.toString("utf8");
      if (stream.length > 65536) { clearTimeout(timer); reject(new Error("viewer_readiness_bound")); return; }
      for (const line of stream.split("\n")) {
        try {
          const doc = JSON.parse(line);
          const find = (v) => v && typeof v === "object" ? v.url && v.origin ? v : Object.values(v).map(find).find(Boolean) : null;
          const found = find(doc);
          if (found) { clearTimeout(timer); resolve(found); return; }
        } catch { /* A partial JSON line is not readiness. */ }
      }
    });
  });
  try {
    const { origin, url } = await ready;
    requireFact(/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(origin), "viewer_origin");
    const token = new URL(url).hash.match(/^#(?:token=)?([A-Za-z0-9_-]{43})$/)?.[1];
    requireFact(token, "viewer_bootstrap_token");
    const exchange = await request(origin, "POST", "/api/v1/auth/exchange", null, { token });
    requireFact(exchange.cookie, "viewer_cookie");
    const get = async (url) => (await request(origin, "GET", url, exchange.cookie)).doc;
    const apiRows = await pages((cursor) => get("/api/v1/recordings?limit=200" + (cursor ? "&after=" + encodeURIComponent(cursor) : "")),
      { rowsKey: "recordings", cursorKey: "nextAfter" });
    const apiIds = apiRows.map((r) => r.recordingId);
    requireFact(new Set(apiIds).size === apiIds.length && JSON.stringify([...apiIds].sort()) === JSON.stringify([...ids].sort()), "api_cli_id_inventory");
    const api = {};
    for (const id of ids) {
      let first;
      const events = await pages(async (cursor) => {
        const doc = await get(`/api/v1/recordings/${id}?limit=1000` + (cursor ? "&cursor=" + encodeURIComponent(cursor) : ""));
        requireFact(doc.recordingId === id, "api_recording_identity");
        requireFact(!first || first.completion === doc.completion && canonicalJson(first.outcome) === canonicalJson(doc.outcome), "api_recording_changed_during_read");
        first ||= doc; return doc;
      }, { rowsKey: "events", cursorKey: "nextCursor", maxRows: 20000 });
      api[id] = { ...first, events: validateEvents(events) };
    }
    fs.writeFileSync(outDir + "/api-readback.json", JSON.stringify(api), { mode: 0o600 });
    return { cli: cliDetails, api };
  } finally { await stop(viewer); }
}
