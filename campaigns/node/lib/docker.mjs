// Thin docker CLI wrapper. Every object this harness creates is prefixed
// `xtrace-camp-node-` (inside the shared `xtrace-camp-` namespace); it refuses to remove anything without that prefix.
import { spawn, spawnSync } from "node:child_process";

export const PREFIX = "xtrace-camp-node-";

function baseArgs() {
  const a = [];
  if (process.env.XTRACE_CAMP_DOCKER_CONFIG) a.push("--config", process.env.XTRACE_CAMP_DOCKER_CONFIG);
  if (process.env.XTRACE_CAMP_DOCKER_HOST) a.push("--host", process.env.XTRACE_CAMP_DOCKER_HOST);
  return a;
}

function guard(name) {
  if (!name.startsWith(PREFIX)) throw new Error(`refusing to touch non-campaign docker object: ${name}`);
}

export function docker(args, { input, timeoutMs = 600000, allowFail = false } = {}) {
  const r = spawnSync("docker", [...baseArgs(), ...args], {
    input,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (r.status !== 0 && !allowFail) {
    throw new Error(`docker ${args.slice(0, 3).join(" ")} failed (${r.status}): ${(r.stderr || "").slice(-2000)}`);
  }
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

/** Streams a long docker command (install/build) to a log file; resolves with the exit code. */
export function dockerLogged(args, logPath, { timeoutMs = 3600000 } = {}) {
  return new Promise(async (resolve) => {
    const fs = await import("node:fs");
    const out = fs.openSync(logPath, "a");
    const p = spawn("docker", [...baseArgs(), ...args], { stdio: ["ignore", out, out] });
    const t = setTimeout(() => p.kill("SIGTERM"), timeoutMs);
    p.on("close", (code) => {
      clearTimeout(t);
      fs.closeSync(out);
      resolve(code);
    });
  });
}

export const net = {
  create(name) {
    guard(name);
    docker(["network", "create", name], { allowFail: true });
  },
  rm(name) {
    guard(name);
    docker(["network", "rm", name], { allowFail: true });
  },
};

export const volume = {
  create(name) {
    guard(name);
    docker(["volume", "create", name]);
  },
  rm(name) {
    guard(name);
    docker(["volume", "rm", "-f", name], { allowFail: true });
  },
};

export const container = {
  rm(name) {
    guard(name);
    docker(["rm", "-f", "-v", name], { allowFail: true });
  },
  /** `args` are `docker run` args after the name; always detached, labelled, on the campaign platform. */
  runDetached(name, args) {
    guard(name);
    this.rm(name);
    return docker(["run", "-d", "--name", name, "--platform", "linux/arm64", "--label", "xtrace-campaign=node", ...args]).stdout.trim();
  },
  exec(name, argv, opts = {}) {
    guard(name);
    return docker(["exec", name, ...argv], opts);
  },
  hostPort(name, containerPort) {
    guard(name);
    const out = docker(["port", name, `${containerPort}/tcp`]).stdout.trim().split("\n")[0];
    return Number(out.split(":").pop());
  },
  running(name) {
    guard(name);
    return docker(["inspect", "-f", "{{.State.Running}}", name], { allowFail: true }).stdout.trim() === "true";
  },
  logs(name) {
    guard(name);
    return docker(["logs", name], { allowFail: true });
  },
  stop(name, seconds = 15) {
    guard(name);
    docker(["stop", "-t", String(seconds), name], { allowFail: true });
  },
};

export function dockerSystemDf() {
  return docker(["system", "df"]).stdout;
}
