import { execFile } from "node:child_process";
import { isIPv4 } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { ordinaryRequest } from "./installed-ordinary-scope.mjs";
import { requireFact } from "./installed-readback.mjs";

const fullId = (id) => typeof id === "string" && /^[a-f0-9]{64}$/.test(id);

export function admitNetwork(network, id, name) {
  requireFact(fullId(id) && network.Id === id && network.Name === name && network.Driver === "bridge"
    && network.Scope === "local" && network.Internal === true && network.EnableIPv6 === false
    && network.Options?.["com.docker.network.bridge.gateway_mode_ipv4"] === "isolated"
    && Array.isArray(network.IPAM?.Config) && network.IPAM.Config.length === 1
    && typeof network.IPAM.Config[0].Subnet === "string", "isolated_network");
}

export function admitMembers(network, containers, ids, images) {
  const members = network.Containers || {};
  requireFact(fullId(ids.db) && fullId(ids.app) && ids.db !== ids.app
    && Object.keys(members).length === 2 && containers.length === 2, "isolated_membership");
  for (const kind of ["db", "app"]) {
    const object = containers.find(c => c.Id === ids[kind]);
    const attachments = Object.values(object?.NetworkSettings?.Networks ?? {});
    const attachment = attachments[0];
    const host = object?.HostConfig;
    requireFact(object?.State?.Running && object.Image === images[kind] && members[ids[kind]]
      && [network.Id, network.Name].includes(host.NetworkMode) && host.Privileged === false && host.PublishAllPorts === false
      && !Object.keys(host.PortBindings || {}).length && JSON.stringify(host.Dns) === '["127.0.0.1"]'
      && host.Sysctls?.["net.ipv6.conf.all.disable_ipv6"] === "1" && attachments.length === 1 && attachment?.NetworkID === network.Id
      && isIPv4(attachment.IPAddress) && attachment.IPAddress === members[ids[kind]].IPv4Address.split("/")[0]
      && !attachment.GlobalIPv6Address && !attachment.IPv6Gateway, "isolated_attachment");
  }
  return members[ids.db].IPv4Address.split("/")[0];
}

// Inspect route tables without sending any packet. The kernel can show an unreachable
// IPv6 default on loopback; it has RTF_REJECT and cannot forward traffic.
export function routeInventory(ipv4, ipv6, subnet) {
  const [address, prefix] = subnet.split("/");
  requireFact(isIPv4(address) && /^(?:[1-9]|[12][0-9]|3[0-2])$/.test(prefix), "local_subnet");
  // Linux prints /proc/net/route addresses in little-endian word order on the pinned amd64 runner.
  const encode = bytes => Buffer.from(bytes).reverse().toString("hex").toUpperCase();
  const destination = encode(address.split(".").map(Number));
  const mask = encode(Array.from({ length: 4 }, (_, i) => 256 - 2 ** (8 - Math.min(8, Math.max(0, Number(prefix) - i * 8)))));
  const lines = ipv4.trim().split("\n");
  requireFact(/^Iface\s+Destination\s+Gateway\s+Flags/.test(lines.shift() || ""), "ipv4_route_header");
  const v4 = lines.map(line => line.trim().split(/\s+/));
  requireFact(v4.length > 0 && v4.every(row => row.length >= 8 && /^[0-9a-f]{8}$/i.test(row[1])
    && /^[0-9a-f]{8}$/i.test(row[2]) && /^[0-9a-f]+$/i.test(row[3]) && row[1].toUpperCase() === destination
    && row[2] === "00000000" && row[7].toUpperCase() === mask), "local_ipv4_routes");
  for (const line of ipv6.trim().split("\n").filter(Boolean)) {
    const row = line.trim().split(/\s+/);
    requireFact(row.length === 10 && /^[0-9a-f]{32}$/i.test(row[0]) && /^[0-9a-f]{2}$/i.test(row[1])
      && /^[0-9a-f]{8}$/i.test(row[8]), "ipv6_route_format");
    requireFact(row[9] === "lo" && (row[1] !== "00" || (parseInt(row[8], 16) & 0x0200) !== 0), "local_ipv6_routes");
  }
}

function exchange(id, data, signal) {
  requireFact(fullId(id), "owned_app_identity");
  return new Promise((resolve, reject) => {
    const child = execFile("docker", ["exec", "-i", id, "node", "/repo/campaigns/node/directus/ordinary/app-request.mjs"],
      { signal, encoding: "utf8", maxBuffer: 2 * 1024 * 1024 }, (error, stdout) => {
        if (error) { reject(new Error("ordinary_request_failed")); return; }
        try { resolve(JSON.parse(stdout)); } catch { reject(new Error("ordinary_response_invalid")); }
      });
    child.stdin.on("error", () => { /* Completion of the owned child supplies the transport result. */ });
    child.stdin.end(JSON.stringify(data));
  });
}

export function appTransport(id) {
  return async (route, { method, headers, body, signal }) => {
    requireFact(ordinaryRequest(method, route), "ordinary_request_not_allowed");
    const response = await exchange(id, { route, method, headers, body }, signal);
    requireFact(Number.isInteger(response.status) && response.status >= 200 && response.status <= 599
      && typeof response.text === "string" && Buffer.byteLength(response.text) <= 1024 * 1024, "ordinary_response_invalid");
    return { status: response.status, text: async () => response.text };
  };
}

export async function awaitPing(id, alive) {
  const deadline = Date.now() + 900000;
  while (Date.now() < deadline) {
    requireFact(alive(), "app_container_exited");
    try {
      const result = await exchange(id, { method: "GET", route: "/server/ping", readiness: true }, AbortSignal.timeout(3000));
      if (result.status === 200) return;
    } catch { /* Bootstrap and app startup precede availability of the owned listener. */ }
    await delay(500);
  }
  throw new Error("application_readiness_deadline");
}
