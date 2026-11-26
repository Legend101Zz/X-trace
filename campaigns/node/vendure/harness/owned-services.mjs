// Used by the paired campaign and its one seed database. A retained service stays
// with the disposable runner. The host writes a marker and observes its exact ID.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { VendureFixture } from "./fixture.mjs";
import { POSTGRES_IMAGE } from "../../lib/stack.mjs";

const supervisor = fileURLToPath(new URL("owned-service.pl", import.meta.url));

export class OwnedServicesFixture extends VendureFixture {
  constructor(directory, names, image, ...drivers) {
    super(...drivers);
    this.directory = directory;
    this.roles = new Map([[names.db, { role: "db", image: POSTGRES_IMAGE,
      command: ["/usr/local/bin/docker-entrypoint.sh", "postgres"] }]]);
    if (names.worker) this.roles.set(names.worker, { role: "worker", image, command: [] });
    this.controls = new Map();
    this.stops = {};
  }

  runDetached(name, args) {
    const service = this.roles.get(name);
    if (!service) return super.runDetached(name, args);
    const index = args.indexOf(service.image);
    if (index < 0) throw new Error("Vendure service image mismatch");
    const control = path.join(this.directory, service.role + "-control");
    fs.mkdirSync(control, { mode: 0o700 });
    this.controls.set(name, control);
    return super.runDetached(name, [
      "--init", "--entrypoint", "/usr/bin/perl", "-v", supervisor + ":/xtrace-service.pl:ro",
      "-v", control + ":/xtrace-service-control:ro", ...args.slice(0, index + 1),
      "/xtrace-service.pl", ...service.command, ...args.slice(index + 1),
    ]);
  }

  cleanup() {
    // Stop the worker while its database is still available. A failed or unknown
    // stop preserves all remaining IDs; Docker never force-removes a process.
    for (const [name, id] of [...this.containers].reverse()) {
      const control = this.controls.get(name);
      if (control) {
        const service = this.roles.get(name);
        fs.writeFileSync(path.join(control, "stop.request"), "stop\n", { flag: "wx", mode: 0o600 });
        const terminal = this.command(["wait", id], { allowFail: true, timeoutMs: 30000 });
        const code = terminal.stdout.trim();
        if (terminal.status !== 0 || (code !== "0" && !(service.role === "worker" && code === "42"))) {
          this.recordKeptHandles(this.directory);
          throw new Error("Vendure owned service terminal unavailable");
        }
        this.stops[service.role] = code === "0" ? "owned-normal-exit" : "owned-term-exit";
      }
      if (this.command(["rm", "-v", id], { allowFail: true }).status !== 0) {
        this.recordKeptHandles(this.directory);
        throw new Error("Vendure owned resource retained");
      }
      this.containers.delete(name);
    }
    // At this point only the exact created network may remain.
    super.cleanup();
  }
}
