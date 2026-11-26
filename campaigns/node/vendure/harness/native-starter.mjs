// Prepare the same ordinary Linux-hosted application for the direct and installed launchers.
import fs from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createCompileDirectory, verifyBuild, verifyOutputs, verifyStarter } from "./preparation.mjs";

// Bind the files that decide listener startup and shutdown to the reviewed registry tarballs.
const reviewedRuntime = {
  "@vendure/core/package.json": "fc35f0f951c64650e4a20658dd20f74a151f5fd15ff3e749319e9d0a982dedd4",
  "@vendure/core/dist/bootstrap.js": "671b6a69e49b5c236cce44aa7a56730dbb958dce23355bab8bf72a3d078b26b1",
  "@vendure/core/dist/version.js": "67876c778056bdc0e220eebad0c6a3c91e956ca9e00425bc540b69ba9f23eab9",
  "@vendure/core/dist/worker/vendure-worker.js": "6186e5c5144758b81ace6bdb73054b0359f08a7c8f80f3308194d901549b6335",
  "@vendure/core/dist/worker/worker-health.service.js": "341b4fc3db940008022479b95679997f871509dd67ca7936cabe1f56589326b1",
  "@vendure/core/dist/telemetry/helpers/is-telemetry-disabled.helper.js": "49af1b508262b320982800b4d460f6a86b83b4126b681091aedc9fcdc0d7020e",
  "@nestjs/core/nest-application-context.js": "3c99851d1ce809fe03ab7d681aecae8408860f5fdb4e9f163c50052d68efd28b"
};

function requireValue(ok) { if (!ok) throw new Error("native Vendure prepared input differs"); }

function loopbackConfig(text) {
  const anchor = /^( +)port: serverPort,$/gm;
  requireValue([...text.matchAll(anchor)].length === 1);
  return text.replace(anchor, '$&\n$1hostname: "127.0.0.1",');
}

function copyOrdinary(source, destination) {
  const stat = fs.lstatSync(source);
  if (stat.isDirectory()) {
    fs.mkdirSync(destination, { mode: 0o700 });
    for (const name of fs.readdirSync(source)) copyOrdinary(path.join(source, name), path.join(destination, name));
  } else {
    requireValue(stat.isFile());
    fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  }
}

export function prepareNativeStarter(prepared, app, log, env) {
  requireValue(process.versions.node === "24.21.0");
  verifyBuild(prepared, true);
  const inputs = Object.keys(verifyStarter(prepared, true));
  fs.mkdirSync(app, { mode: 0o700 });
  for (const file of inputs) {
    fs.mkdirSync(path.dirname(path.join(app, file)), { recursive: true, mode: 0o700 });
    copyOrdinary(path.join(prepared, file), path.join(app, file));
  }
  for (const item of [".env", "static"]) copyOrdinary(path.join(prepared, item), path.join(app, item));
  const fd = fs.openSync(log, "wx", 0o600);
  function npm(args) {
    execFileSync(path.join(path.dirname(process.execPath), "npm"), args,
      { cwd: app, env, stdio: ["ignore", fd, fd], timeout: 1200000, killSignal: "SIGKILL" });
  }
  try {
    npm(["ci", "--no-audit", "--no-fund"]);
    verifyStarter(app, true);
    // The binding in the exact workflow comes from reviewing the pinned core's bootstrap
    // and its use of apiOptions.hostname when listening. Never derive the expected digest from this checkout.
    const expected = process.env.VENDURE_REVIEWED_CORE_BOOTSTRAP_SHA256;
    requireValue(typeof expected === "string" && /^[0-9a-f]{64}$/.test(expected));
    requireValue(expected === reviewedRuntime["@vendure/core/dist/bootstrap.js"]);
    for (const [relative, sha256] of Object.entries(reviewedRuntime)) {
      const file = path.join(app, "node_modules", relative);
      requireValue(fs.lstatSync(file).isFile() &&
        createHash("sha256").update(fs.readFileSync(file)).digest("hex") === sha256);
    }
    createCompileDirectory(app);
    const config = path.join(app, "src/vendure-config.ts");
    fs.writeFileSync(config, loopbackConfig(fs.readFileSync(config, "utf8")));
    npm(["run", "build:server"]);
    npm(["run", "build:worker"]);
  } finally { fs.closeSync(fd); }
  verifyOutputs(app);
  verifyBuild(prepared, true);
  function same(file, adjusted = false) {
    const original = fs.readFileSync(path.join(prepared, file));
    const expected = adjusted ? Buffer.from(loopbackConfig(original.toString("utf8"))) : original;
    requireValue(expected.equals(fs.readFileSync(path.join(app, file))));
  }
  for (const file of inputs) same(file, file === "src/vendure-config.ts");
  for (const file of ["dist/index.js", "dist/index-worker.js", "dist/vendure-config.js"]) {
    same(file, file === "dist/vendure-config.js");
  }
}
