import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, symlink, writeFile, chmod, link, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { AgentEnvelopeSchema, RecordingEventKind, RecordingEventSchema } from "@xtrace/protocol";
import {
  encodeFrame,
  readFrames,
  transcriptProof,
  validateBootstrap,
  verifyCertificatePin,
  XtraceClientError,
  openXtpSession,
} from "../index.js";
import { BoundedSendQueue } from "../send-queue.js";

function validBootstrap(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: 1,
    host: "127.0.0.1",
    port: 37001,
    certificate_sha256_pin: "1".repeat(64),
    runtime_session_id: "01900000-0000-7000-8000-000000000001",
    session_secret_base64: Buffer.alloc(32, 7).toString("base64"),
    project_id: "01900000-0000-7000-8000-000000000002",
    expected_repository_fingerprint: `b3:${"2".repeat(64)}`,
    max_protocol_major: 1,
    max_protocol_minor: 0,
    ...overrides,
  };
}

function sampleEnvelope() {
  return create(AgentEnvelopeSchema, {
    protocolMajor: 1,
    protocolMinor: 0,
    runtimeSessionId: Buffer.alloc(16, 0x33),
    sessionSeq: 2n,
    sentMonotonicNs: 9n,
    messageId: "test-event",
    payload: {
      case: "eventBatch",
      value: {
        recordingId: Buffer.alloc(16, 0x44),
        events: [create(RecordingEventSchema, {
          eventId: "event-1",
          recordingSeq: 2n,
          monotonicNs: 8n,
          kind: RecordingEventKind.FRAME_ENTER,
          symbol: "synthetic.handler",
        })],
      },
    },
  });
}

test("bootstrap validates loopback, canonical identities, and 256-bit secrets without leaking them", () => {
  const accepted = validateBootstrap(validBootstrap());
  assert.equal(accepted.session_secret.length, 32);
  accepted.session_secret.fill(0);
  const secret = Buffer.alloc(32, 9).toString("base64");
  assert.throws(
    () => validateBootstrap(validBootstrap({ host: "0.0.0.0", session_secret_base64: secret })),
    (error: unknown) => error instanceof XtraceClientError && !error.message.includes(secret),
  );
  assert.throws(() => validateBootstrap(validBootstrap({ certificate_sha256_pin: "AA".repeat(32) })));
});

test("bootstrap file refuses symlinks, hardlinks, and group-readable mode", async () => {
  const root = await mkdtemp(join(tmpdir(), "xtrace bootstrap "));
  const path = join(root, "bootstrap.json");
  const raw = JSON.stringify(validBootstrap());
  try {
    await writeFile(path, raw, { mode: 0o600 });
    await chmod(path, 0o600);
    const { readBootstrap } = await import("../bootstrap.js");
    const valid = await readBootstrap(path);
    valid.session_secret.fill(0);
    const alias = join(root, "alias.json");
    await symlink(path, alias);
    await assert.rejects(readBootstrap(alias));
    const hardlink = join(root, "hardlink.json");
    await link(path, hardlink);
    await assert.rejects(readBootstrap(path));
    await rm(hardlink);
    await chmod(path, 0o640);
    await assert.rejects(readBootstrap(path));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("bootstrap reader rejects an oversized file before parsing it", async () => {
  const root = await mkdtemp(join(tmpdir(), "xtrace bootstrap size "));
  const path = join(root, "bootstrap.json");
  try {
    await writeFile(path, Buffer.alloc(64 * 1024 + 1), { mode: 0o600 });
    await chmod(path, 0o600);
    const { readBootstrap } = await import("../bootstrap.js");
    await assert.rejects(readBootstrap(path), { code: "XTR-NODE-BOOTSTRAP" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("openXtpSession erases its secret when pre-connect setup fails", async () => {
  const missingManifest = validateBootstrap(validBootstrap());
  const missingSecret = missingManifest.session_secret;
  await assert.rejects(openXtpSession(missingManifest, "/missing/xtrace-manifest.json", {
    adapterName: "synthetic", adapterVersion: "0.1.0", language: "node", runtimeName: "node",
    runtimeVersion: process.version, pid: BigInt(process.pid), processStartMonotonicNs: 1n,
  }));
  assert.deepEqual(missingSecret, Buffer.alloc(32));

  const invalidIdentity = {
    ...validateBootstrap(validBootstrap()),
    runtime_session_id: "not-a-uuid",
  };
  const invalidSecret = invalidIdentity.session_secret;
  const manifest = resolve(process.cwd(), "fixtures/synthetic-manifest.json");
  await assert.rejects(openXtpSession(invalidIdentity, manifest, {
    adapterName: "synthetic", adapterVersion: "0.1.0", language: "node", runtimeName: "node",
    runtimeVersion: process.version, pid: BigInt(process.pid), processStartMonotonicNs: 1n,
  }));
  assert.deepEqual(invalidSecret, Buffer.alloc(32));

  const invalidHost = {
    ...validateBootstrap(validBootstrap()),
    host: "\0" as "127.0.0.1",
  };
  const hostSecret = invalidHost.session_secret;
  await assert.rejects(openXtpSession(invalidHost, manifest, {
    adapterName: "synthetic", adapterVersion: "0.1.0", language: "node", runtimeName: "node",
    runtimeVersion: process.version, pid: BigInt(process.pid), processStartMonotonicNs: 1n,
  }));
  assert.deepEqual(hostSecret, Buffer.alloc(32));
});

test("accepted concurrent sends drain in order when close stops new sends", async () => {
  const queue = new BoundedSendQueue(4);
  let nextSequence = 1n;
  let active = false;
  let accepting = true;
  const emitted: bigint[] = [];
  const send = () => {
    if (!accepting) return Promise.reject(new XtraceClientError("XTR-NODE-TRANSPORT", "session is closing"));
    return queue.enqueue(async () => {
      assert.equal(active, false, "only one send may own the session at a time");
      active = true;
      const sequence = nextSequence;
      await new Promise((resolve) => setTimeout(resolve, 5));
      emitted.push(sequence);
      nextSequence += 1n;
      active = false;
      return sequence;
    });
  };
  const accepted = [send(), send(), send()];
  accepting = false;
  const draining = queue.drain();
  await assert.rejects(send(), { code: "XTR-NODE-TRANSPORT" });
  const results = await Promise.all(accepted);
  await draining;
  assert.deepEqual(results, [1n, 2n, 3n]);
  assert.deepEqual(emitted, [1n, 2n, 3n]);
});

test("send queue rejects saturation without disturbing accepted work", async () => {
  const queue = new BoundedSendQueue(1);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const accepted = queue.enqueue(async () => { await gate; return "accepted"; });
  await assert.rejects(queue.enqueue(async () => "overflow"), { code: "XTR-NODE-TRANSPORT" });
  release();
  assert.equal(await accepted, "accepted");
  await queue.drain();
});

test("send queue poisoning prevents later accepted tasks from executing", async () => {
  const queue = new BoundedSendQueue(3);
  let laterTaskRan = false;
  const failed = queue.enqueue(async () => { throw new Error("synthetic send failed"); });
  const later = queue.enqueue(async () => { laterTaskRan = true; });
  await assert.rejects(failed, /synthetic send failed/);
  await assert.rejects(later, { code: "XTR-NODE-TRANSPORT" });
  await assert.rejects(queue.enqueue(async () => undefined), { code: "XTR-NODE-TRANSPORT" });
  assert.equal(laterTaskRan, false);
});

test("Node proof matches the shared Rust/Node transcript golden", async () => {
  const path = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../../schema/fixtures/xtp-agent/handshake-vector.json");
  const vector = JSON.parse(await readFile(path, "utf8")) as Record<string, string>;
  const proof = transcriptProof(
    Buffer.from(vector.session_secret_hex!, "hex"),
    Buffer.from(vector.tls_exporter_hex!, "hex"),
    Buffer.from(vector.runtime_session_id_hex!, "hex"),
    Buffer.from(vector.client_nonce_hex!, "hex"),
    Buffer.from(vector.server_nonce_hex!, "hex"),
    Buffer.from(vector.manifest_digest!, "utf8"),
  );
  assert.equal(proof.toString("hex"), vector.expected_hmac_hex);
});

test("certificate pin check uses the DER bytes and rejects a mismatch", () => {
  const der = Buffer.from("synthetic DER certificate");
  const pin = createHash("sha256").update(der).digest("hex");
  verifyCertificatePin(pin, der);
  assert.throws(() => verifyCertificatePin("0".repeat(64), der), { code: "XTR-NODE-TLS-PIN" });
});

test("length framing round-trips protobuf and handles fragmented/coalesced frames", async () => {
  const first = encodeFrame(sampleEnvelope(), 4096);
  const second = encodeFrame(sampleEnvelope(), 4096);
  const joined = Buffer.concat([first, second]);
  const fragments = [joined.subarray(0, 2), joined.subarray(2, 7), joined.subarray(7, first.length), joined.subarray(first.length)];
  const decoded = [];
  for await (const envelope of readFrames(Readable.from(fragments), 4096)) decoded.push(envelope);
  assert.equal(decoded.length, 2);
  assert.deepEqual(toBinary(AgentEnvelopeSchema, decoded[0]!), toBinary(AgentEnvelopeSchema, sampleEnvelope()));
  const payload = decoded[0]!.payload;
  assert.equal(payload.case, "eventBatch");
  if (payload.case === "eventBatch") assert.equal(payload.value.events[0]?.symbol, "synthetic.handler");
  assert.equal(fromBinary(AgentEnvelopeSchema, joined.subarray(4, first.length)).sessionSeq, 2n);
});

test("empty, oversize, malformed, and truncated frames fail before a decoded event", async () => {
  async function first(chunks: Uint8Array[], limit = 16): Promise<unknown> {
    const iterator = readFrames(Readable.from(chunks), limit)[Symbol.asyncIterator]();
    return iterator.next();
  }
  await assert.rejects(first([Buffer.alloc(4)]), { code: "XTR-NODE-FRAME" });
  const oversize = Buffer.alloc(4);
  oversize.writeUInt32BE(17);
  await assert.rejects(first([oversize]), { code: "XTR-NODE-FRAME" });
  await assert.rejects(first([Buffer.from([0, 0, 0, 1, 0xff])]), { code: "XTR-NODE-FRAME" });
  await assert.rejects(first([Buffer.from([0, 0, 0, 5, 1])]), { code: "XTR-NODE-FRAME" });
  assert.throws(() => encodeFrame(sampleEnvelope(), Number.NaN), { code: "XTR-NODE-FRAME" });
  assert.throws(() => encodeFrame(sampleEnvelope(), 8 * 1024 * 1024 + 1), { code: "XTR-NODE-FRAME" });
});
