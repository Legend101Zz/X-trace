// Record creation receipts before any start, observation or release. Names are creation labels only.
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { docker, dockerAttached, PLATFORM, PREFIX } from "../../lib/docker.mjs";

function readReceipt(file, maximum) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === "ENOENT") return "";
    throw new Error("Vendure fixture creation receipt unavailable");
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0 || stat.size > maximum) {
      throw new Error("Vendure fixture creation receipt invalid");
    }
    const bytes = Buffer.alloc(maximum + 1);
    const n = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (n !== stat.size) throw new Error("Vendure fixture creation receipt changed");
    return bytes.toString("utf8", 0, n).trimEnd();
  } finally {
    fs.closeSync(fd);
  }
}

export function builtImage(parent) {
  const stat = fs.lstatSync(parent);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0) {
    throw new Error("Vendure fixture image requires an owner-controlled build directory");
  }
  const id = readReceipt(path.join(parent, "vendure-image.id"), 80);
  if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error("Vendure requires its verified build image receipt");
  return id;
}

const validId = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const fixtureName = name => typeof name === "string" && name.startsWith(PREFIX + "vendure-");

export class VendureFixture {
  constructor(command = docker, logged = dockerAttached) {
    this.command = command;
    this.logged = logged;
    this.network = null;
    this.containers = new Map();
  }

  createNetwork(name) {
    if (this.network || !fixtureName(name)) throw new Error("Vendure requires a fresh fixture network");
    const result = this.command(["network", "create", name + "-" + randomUUID()], { allowFail: true });
    const id = result.stdout.trim();
    if (result.status !== 0 || !validId(id)) throw new Error("Vendure fixture network creation failed");
    this.network = id;
  }

  create(name, args, timeoutMs) {
    if (this.containers.has(name) || !fixtureName(name)) throw new Error("Vendure requires a fresh container");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-vendure-cid-"));
    const file = path.join(dir, "id");
    try {
      let result;
      try {
        result = this.command(["create", "--cidfile", file, "--name", name, "--platform", PLATFORM,
          "--label", "xtrace-campaign=node", ...args], { allowFail: true, timeoutMs });
      } finally {
        const cid = readReceipt(file, 80);
        const stdoutId = result?.status === 0 ? result.stdout.trim() : "";
        if ((cid && !validId(cid)) || (stdoutId && !validId(stdoutId)) || (cid && stdoutId && cid !== stdoutId)) {
          throw new Error("Vendure container creation receipts disagree or are invalid");
        }
        const id = cid || stdoutId;
        if (id) this.containers.set(name, id);
      }
      if (result.status !== 0 || !this.containers.has(name)) throw new Error("Vendure fixture container creation failed");
      return this.id(name);
    } finally {
      fs.rmSync(file, { force: true });
      fs.rmdirSync(dir);
    }
  }

  id(name) {
    if (!this.containers.has(name)) throw new Error("Vendure container creation was not observed");
    return this.containers.get(name);
  }

  runDetached(name, args) {
    const deadline = Date.now() + 600000;
    const id = this.create(name, args, 600000);
    if (this.command(["start", id], { allowFail: true, timeoutMs: remaining(deadline) }).status !== 0) {
      throw new Error("Vendure fixture container start failed");
    }
    return id;
  }

  async runLogged(name, args, log) {
    const deadline = Date.now() + 3600000;
    const id = this.create(name, args, Math.min(600000, remaining(deadline)));
    const code = await this.logged(["start", "--attach", id], log, { timeoutMs: remaining(deadline) });
    if (code !== 0) return code;
    const state = this.command(["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", id],
      { allowFail: true, timeoutMs: remaining(deadline) });
    const match = /^exited (0|[1-9][0-9]{0,2})$/.exec(state.stdout.trim());
    if (state.status !== 0 || !match || Number(match[1]) > 255) throw new Error("Vendure foreground exit unavailable");
    return Number(match[1]);
  }

  exec(name, args, options = {}) {
    const id = this.id(name);
    try {
      const result = this.command(["exec", id, ...args], { ...options, allowFail: true });
      if (!options.allowFail && result.status !== 0) throw new Error();
      return result;
    } catch {
      // The scenario runner retains error messages. A database diagnostic may contain private data.
      throw new Error("Vendure owned database command failed");
    }
  }

  hostPort(name, port) {
    const result = this.command(["port", this.id(name), port + "/tcp"], { allowFail: true });
    const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(result.stdout.trim());
    if (result.status !== 0 || !match || Number(match[1]) > 65535) throw new Error("Vendure loopback port unavailable");
    return Number(match[1]);
  }

  running(name) {
    const result = this.command(["inspect", "-f", "{{.State.Running}}", this.id(name)], { allowFail: true });
    return result.status === 0 && result.stdout.trim() === "true";
  }

  logs(name) {
    const result = this.command(["logs", this.id(name)], { allowFail: true });
    if (result.status !== 0) throw new Error("Vendure fixture logs unavailable");
    return result;
  }

  collect(names, outDir) {
    let missing = false;
    for (const role of ["app", "worker"]) {
      if (!this.containers.has(names[role])) continue;
      try {
        const logs = this.logs(names[role]);
        fs.writeFileSync(path.join(outDir, role + ".log"), logs.stdout + logs.stderr, { mode: 0o600, flag: "wx" });
      } catch {
        missing = true;
      }
    }
    let exit = null;
    if (this.containers.has(names.app)) {
      const result = this.command(["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", this.id(names.app)], { allowFail: true });
      const state = /^(created|running|paused|restarting|removing|dead|exited) (0|[1-9][0-9]{0,2})$/.exec(result.stdout.trim());
      if (result.status !== 0 || !state || Number(state[2]) > 255) throw new Error("Vendure app teardown status unavailable");
      if (state[1] === "exited") exit = state[2];
    }
    if (missing) throw new Error("Vendure fixture logs unavailable");
    return exit;
  }

  recordKeptHandles(outDir) {
    // A successful explicit --keep transfers the exact resources to the operator.
    const receipt = { network: this.network, containers: Object.fromEntries(this.containers) };
    const staging = fs.mkdtempSync(path.join(outDir, ".keep-"));
    const file = path.join(staging, "handles.json");
    try {
      fs.writeFileSync(file, JSON.stringify(receipt) + "\n", { mode: 0o600, flag: "wx" });
      fs.linkSync(file, path.join(outDir, "kept-fixture.json"));
    } finally {
      fs.rmSync(staging, { recursive: true, force: true });
    }
  }

  cleanup() {
    let failed = false;
    for (const [name, id] of [...this.containers].reverse()) {
      try {
        const result = this.command(["rm", "-f", "-v", id], { allowFail: true });
        const absent = ["Error response from daemon: No such container: " + id, "Error: No such container: " + id];
        if (result.status !== 0 && !absent.includes(result.stderr.trim())) throw new Error("remove");
        this.containers.delete(name);
      } catch {
        failed = true;
      }
    }
    if (this.network) {
      try {
        const result = this.command(["network", "rm", this.network], { allowFail: true });
        const absent = "Error response from daemon: network " + this.network + " not found";
        if (result.status !== 0 && result.stderr.trim() !== absent) throw new Error("remove");
        this.network = null;
      } catch {
        failed = true;
      }
    }
    if (failed) throw new Error("Vendure owned fixture cleanup failed");
  }
}

function remaining(deadline) {
  const ms = deadline - Date.now();
  if (ms <= 0) throw new Error("Vendure fixture operation reached its deadline");
  return ms;
}
