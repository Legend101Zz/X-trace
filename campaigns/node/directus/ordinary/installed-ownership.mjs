import { requireFact } from "./installed-readback.mjs";

const ID = /^[a-f0-9]{64}$/;

/** Record an ID only after Docker positively returns it; never pre-delete by name. */
export function createOwned(docker, owned, name, args, platform) {
  let id;
  try {
    const result = docker(["create", "--name", name, "--platform", platform, "--label", "xtrace-campaign=node", ...args]);
    id = result.stdout.trim();
    requireFact(ID.test(id), "container_identity");
  } catch { owned.uncertain = true; throw new Error("container_create_unconfirmed"); }
  owned.push(id);
  docker(["start", id]);
  return id;
}

/** Removal and a successful inventory query must both confirm each owned ID absent. */
export function removeOwned(docker, kind, id) {
  if (!ID.test(id) || !["container", "network"].includes(kind)) return false;
  const remove = kind === "container" ? ["rm", "-f", "-v", id] : ["network", "rm", id];
  const list = kind === "container"
    ? ["ps", "-a", "--no-trunc", "--filter", `id=${id}`, "--format", "{{.ID}}"]
    : ["network", "ls", "--no-trunc", "--filter", `id=${id}`, "--format", "{{.ID}}"];
  try {
    const removed = docker(remove, { allowFail: true });
    const remaining = docker(list, { allowFail: true });
    return removed.status === 0 && remaining.status === 0 && remaining.stdout.trim() === "";
  } catch { return false; }
}
