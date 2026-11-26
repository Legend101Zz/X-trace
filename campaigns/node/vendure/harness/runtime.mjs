// The same build, seed restore, runtime options and stock worker serve both legs.
import fs from "node:fs";
import path from "node:path";
import { docker } from "../../lib/docker.mjs";
import { randomSecret } from "../../lib/baseline.mjs";
import { startPostgres, sleep } from "../../lib/stack.mjs";

export function createVendureRuntime({ root, image, fixture }) {
  const appDir = path.join(root, "app");
  const PG_DB = "vendure", PG_USER = "xtrace";
  const appUser = ["--user", `${process.getuid()}:${process.getgid()}`, "-e", "HOME=/work/.xtrace-home"];
  function readEnvFile() {
    const env = {};
    for (const line of fs.readFileSync(path.join(appDir, ".env"), "utf8").split("\n")) {
      const m = /^([A-Z_]+)=(.*)$/.exec(line);
      if (m) env[m[1]] = m[2].trim();
    }
    return env;
  }

  async function buildStack({ names }, seed, capture = null) {
    const env = readEnvFile();
    const admin = { identifier: env.SUPERADMIN_USERNAME, password: env.SUPERADMIN_PASSWORD };
    const dbPassword = randomSecret();
    await seed.startAndRestore({ username: PG_USER, database: PG_DB }, async () => {
      await startPostgres({ netName: fixture.network, dbName: names.db, database: PG_DB, user: PG_USER, password: dbPassword }, fixture);
      return fixture.id(names.db);
    }, docker);
    const common = [
      ...appUser, "--network", fixture.network, "-v", `${root}:/work`, "-w", "/work/app",
      "-e", "DB_HOST=db", "-e", "DB_PORT=5432", "-e", `DB_NAME=${PG_DB}`, "-e", `DB_USERNAME=${PG_USER}`, "-e", `DB_PASSWORD=${dbPassword}`, "-e", "DB_SCHEMA=public",
      "-e", "PORT=3000", "-e", "APP_ENV=dev", "-e", "DO_NOT_TRACK=1", "-e", "VENDURE_DISABLE_TELEMETRY=1",
    ];
    // The upstream topology: stock server entry and, as a separate process/container, the stock worker entry.
    fixture.runDetached(names.worker, [...common, image, "node", "./dist/index-worker.js"]);
    if (capture) {
      fixture.runDetached(names.app, ["--init", "-p", "127.0.0.1::3000", ...common,
        ...capture.mounts, image, "/usr/local/bin/node", capture.supervisor, capture.control]);
    } else {
      fixture.runDetached(names.app, ["-p", "127.0.0.1::3000", ...common, image, "node", "./dist/index.js"]);
    }
    const port = fixture.hostPort(names.app, 3000);
    const baseUrl = `http://127.0.0.1:${port}`;
    // Readiness (necessary, never sufficient): shop-api answers and the worker logged "ready".
    let readinessResponses = 0;
    const deadline = Date.now() + 300000;
    for (;;) {
      if (!fixture.running(names.app)) throw new Error("app container exited before readiness");
      if (!fixture.running(names.worker)) throw new Error("worker container exited before readiness");
      try {
        const r = await fetch(baseUrl + "/shop-api", { method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ query: "{__typename}" }), signal: AbortSignal.timeout(3000) });
        readinessResponses++;
        await r.body?.cancel();
        const w = fixture.logs(names.worker);
        if (r.status === 200 && /Vendure Worker is ready/.test((w.stdout || "") + (w.stderr || ""))) break;
      } catch {}
      if (Date.now() > deadline) throw new Error("readiness deadline exceeded");
      await sleep(500);
    }
    // rows as objects, via PostgreSQL json_agg
    const sql = (q) => {
      const out = fixture.exec(names.db, ["psql", "-U", PG_USER, "-d", PG_DB, "-At", "-c", `select coalesce(json_agg(t),'[]'::json) from (${q}) t`]).stdout.trim();
      return JSON.parse(out);
    };
    return { baseUrl, ownedPort: port, readinessResponses, admin, sql, extra: { sql, admin },
      privacySecrets: [dbPassword, env.COOKIE_SECRET, env.SUPERADMIN_PASSWORD].filter(Boolean) };
  }

  return { buildStack };
}
