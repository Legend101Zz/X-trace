// Passive evidence from the exact stock worker and stock server we start.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { setTimeout as pause } from "node:timers/promises";
import { signalClass } from "./installed-preflight-observation.mjs";

const alive = child => child.exitCode === null && child.signalCode === null;
const requireValue = ok => { if (!ok) throw new Error("native Vendure process observation unavailable"); };

export function launch(command, cwd, env, directory, role) {
  const file = path.join(directory, role + ".log");
  const fd = fs.openSync(file, "wx", 0o600);
  let child;
  try { child = spawn(command[0], command.slice(1), { cwd, env, stdio: ["ignore", fd, fd] }); }
  finally { fs.closeSync(fd); }
  const handle = { child, file, error: false, closed: false, node: null };
  child.once("error", () => { handle.error = true; });
  child.once("close", () => { handle.closed = true; });
  return handle;
}

function identity(pid) {
  // Field 22 is the process start tick. A recycled PID cannot satisfy this observation.
  const stat = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
  const tail = stat.slice(stat.lastIndexOf(") ") + 2).split(" ");
  requireValue(/^[0-9]+$/.test(tail[19]));
  return { pid, start: tail[19], parent: Number(tail[1]), state: tail[0] };
}

const exited = node => ["Z", "X", "x"].includes(node.state);

function expectedCommand(pid) {
  const args = fs.readFileSync('/proc/' + pid + '/cmdline').toString().split("\0");
  return fs.realpathSync('/proc/' + pid + '/exe') === fs.realpathSync(process.execPath) &&
    args.length === 3 && args[0] === process.execPath && args[1] === "./dist/index.js" && args[2] === "";
}

function recheckStockNode(handle, leg) {
  const original = handle.node;
  if (!original) return null;
  function state() {
    try {
      const current = identity(original.pid);
      if (current.start !== original.start || exited(current)) return "already-exited";
      const parentMatches = leg === "direct" ? current.pid === handle.child.pid : current.parent === handle.child.pid;
      return parentMatches ? "live-match" : "unverified";
    } catch (error) {
      return error.code === "ENOENT" ? "already-exited" : "unverified";
    }
  }
  const before = state();
  if (before !== "live-match") return before;
  let commandMatched = false;
  try { commandMatched = expectedCommand(original.pid); } catch { /* Read the same identity again below. */ }
  const after = state();
  return after === "live-match" && !commandMatched ? "unverified" : after;
}

function stockServer(launcher, argv) {
  const candidates = new Set();
  if (argv === "direct") candidates.add(launcher.pid);
  else {
    // A multithreaded launcher can spawn Node on any of its own runtime threads.
    const threads = '/proc/' + launcher.pid + '/task';
    for (const tid of fs.readdirSync(threads)) {
      if (!/^[0-9]+$/.test(tid)) continue;
      try {
        const children = fs.readFileSync(path.join(threads, tid, "children"), "utf8").trim();
        for (const id of children.split(/\s+/).filter(Boolean)) candidates.add(Number(id));
      } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  }
  const matches = [];
  for (const pid of candidates) {
    requireValue(Number.isSafeInteger(pid) && pid > 0);
    try {
      const before = identity(pid);
      if (exited(before) || !expectedCommand(pid)) continue;
      const after = identity(pid);
      if (before.start === after.start && !exited(after) &&
          (argv === "direct" || (before.parent === launcher.pid && after.parent === launcher.pid))) matches.push(after);
    } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  requireValue(matches.length === 1);
  return matches[0];
}

function banner(file, expected) {
  const size = fs.statSync(file).size;
  requireValue(size <= 16 * 1024 * 1024);
  return fs.readFileSync(file).includes(Buffer.from(expected));
}

export async function observeStartup(server, worker, leg, observed, checkpoint) {
  const end = Date.now() + 300000;
  while (Date.now() < end) {
    // Each stock marker is monotonic. Save intermediate observations even when
    // the other process fails or the job is interrupted before qualification.
    if (!observed.workerContextReady && banner(worker.file, "Vendure Worker is ready")) {
      observed.workerContextReady = true;
      checkpoint();
    }
    if (!observed.serverListenBanner &&
        banner(server.file, "Vendure server (v3.7.3) now running on port 34117")) {
      observed.serverListenBanner = true;
      checkpoint();
    }
    requireValue(!server.error && !worker.error && alive(server.child) && alive(worker.child));
    if (observed.serverListenBanner && !server.node) {
      server.node = stockServer(server.child, leg);
      observed.serverProcessMatched = true;
      checkpoint();
    }
    if (server.node && observed.workerContextReady) {
      observed.serverAtJointReady = recheckStockNode(server, leg);
      checkpoint();
      requireValue(observed.serverAtJointReady === "live-match");
      requireValue(alive(server.child) && alive(worker.child));
      return;
    }
    await pause(200);
  }
  throw new Error("native Vendure startup deadline");
}

function stockNodeGone(node) {
  if (!node) return null;
  try { return identity(node.pid).start !== node.start; }
  catch (error) { return error.code === "ENOENT" ? true : null; }
}

export function incompleteNotice(handle) {
  if (!handle.closed) return null;
  try { return banner(handle.file, "XTR-RUN-CAPTURE-INCOMPLETE"); }
  catch { return null; }
}

export async function stop(handle, leg) {
  const child = handle.child;
  const nodeBeforeStop = recheckStockNode(handle, leg);
  const live = !handle.error && child.pid !== undefined && alive(child);
  const signalled = live && child.kill("SIGTERM");
  const end = Date.now() + 25000;
  while (!handle.closed && Date.now() < end) await pause(50);
  // The runner owns final disposal on a deadline. Never target a launcher descendant.
  if (!handle.closed) child.unref();
  return { live, signalled, closed: handle.closed, code: child.exitCode, signal: signalClass(child.signalCode),
    nodeBeforeStop, nodeGone: stockNodeGone(handle.node) };
}
