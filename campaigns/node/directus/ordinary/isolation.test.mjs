import test from "node:test";
import assert from "node:assert/strict";
import { admitNetwork, admitMembers, routeInventory } from "./isolated-runtime.mjs";

const ids = { db: "a".repeat(64), app: "b".repeat(64) };
const images = { db: "sha256:" + "c".repeat(64), app: "sha256:" + "d".repeat(64) };
const netId = "e".repeat(64);
const prefix = "10.25.0.";
const network = () => ({ Id: netId, Name: "ordinary", Driver: "bridge", Scope: "local", Internal: true,
  EnableIPv6: false, IPAM: { Config: [{ Subnet: prefix + "0/24" }] },
  Options: { "com.docker.network.bridge.gateway_mode_ipv4": "isolated" },
  Containers: { [ids.db]: { IPv4Address: prefix + "2/24" }, [ids.app]: { IPv4Address: prefix + "3/24" } } });
const objects = () => ["db", "app"].map((kind, i) => ({ Id: ids[kind], Image: images[kind], State: { Running: true },
  HostConfig: { NetworkMode: netId, Privileged: false, PublishAllPorts: false, PortBindings: {}, Dns: ["127.0.0.1"],
    Sysctls: { "net.ipv6.conf.all.disable_ipv6": "1" } },
  NetworkSettings: { Networks: { ordinary: { NetworkID: netId, IPAddress: prefix + (i + 2), GlobalIPv6Address: "", IPv6Gateway: "" } } } }));

test("ordinary runtime accepts only the separately inspected internal isolated network", () => {
  admitNetwork(network(), netId, "ordinary");
  for (const change of [{ Internal: false }, { EnableIPv6: true }, { Driver: "other" }, { Options: {} }, { Id: ids.app }]) {
    assert.throws(() => admitNetwork({ ...network(), ...change }, netId, "ordinary"));
  }
});

test("app and DB must be the two exact local service identities with all ports unpublished", () => {
  assert.equal(admitMembers(network(), objects(), ids, images), prefix + "2");
  for (const change of [set => { set[0].Id = ids.app; }, set => { set[0].Image = images.app; },
    set => { set[0].HostConfig.PortBindings = { port: [] }; }, set => { set[1].NetworkSettings.Networks.extra = {}; },
    set => { set[0].HostConfig.Sysctls = {}; }]) {
    const values = objects(); change(values);
    assert.throws(() => admitMembers(network(), values, ids, images));
  }
  const other = network(); other.Containers.extra = {};
  assert.throws(() => admitMembers(other, objects(), ids, images));
});

test("kernel route inspection permits only the owned on-link subnet and local IPv6 entries", () => {
  const header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n";
  const local = "eth0 0000190A 00000000 0001 0 0 0 00FFFFFF 0 0 0";
  const v6 = "0".repeat(32) + " 00 " + "0".repeat(32) + " 00 " + "0".repeat(32) + " ffffffff 00000000 00000000 00200200 lo";
  routeInventory(header + local, v6, prefix + "0/24");
  for (const row of ["", local.replace("0000190A", "00000000"), local.replace("00FFFFFF", "0000FFFF"),
    local.replace("00000000", "0100190A")]) {
    assert.throws(() => routeInventory(header + row, "", prefix + "0/24"));
  }
  assert.throws(() => routeInventory(header + local, v6.replace("00200200", "00000001"), prefix + "0/24"));
});
