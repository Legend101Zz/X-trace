import { create } from "@bufbuild/protobuf";
import { blake3 } from "hash-wasm";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import tls from "node:tls";
import { parse as parseUuid } from "uuid";
import { AgentEnvelopeSchema, AckDurability, AdapterHelloSchema, type AgentEnvelope } from "@xtrace/protocol";
import { Bootstrap } from "./bootstrap.js";
import { encodeFrame, readFrames } from "./framing.js";
import { transcriptProof, verifyTranscriptProof, ZERO_NONCE } from "./handshake.js";
import { XtraceClientError } from "./errors.js";
import { BoundedSendQueue } from "./send-queue.js";

const EXPORTER_LABEL = "xtrace-adapter-transport-v1";
const DEFAULT_MAX_ENVELOPE_BYTES = 1024 * 1024;
const MAX_ENVELOPE_BYTES = 8 * 1024 * 1024;

/** Authenticated XTP session that emits sequential post-hello envelopes and accepts only Staged ACKs. */
export interface AuthenticatedXtpSession {
  /** Negotiated protocol values and the bootstrap-bound runtime identity. */
  readonly protocolMajor: number;
  readonly protocolMinor: number;
  /** Raw 16-byte UUID bound to the daemon bootstrap. */
  readonly runtimeSessionId: Uint8Array;
  /** Negotiated maximum length of one encoded protobuf envelope. */
  readonly maxEnvelopeBytes: number;
  /**
   * Sends one envelope in invocation order and waits for its contiguous Staged acknowledgement.
   * Up to 64 send calls may be pending at once.
   * @param messageId Stable non-empty ID for the outgoing envelope.
   * @param payload Generated Protobuf payload; callers cannot supply wire bytes.
   * @param correlationToken Optional opaque correlation token.
   */
  send(messageId: string, payload: AgentEnvelope["payload"], correlationToken?: string): Promise<AgentEnvelope["payload"] & { case: "ack" }>;
  /** Sends TLS close-notify and releases the local socket. */
  close(): Promise<void>;
}

/** Runtime identity fields required by the canonical AdapterHello. */
export interface AdapterIdentity {
  /** Stable language-pack name. */
  adapterName: string;
  /** SemVer for the emitting client. */
  adapterVersion: string;
  /** Runtime language identifier, such as `node`. */
  language: string;
  /** Runtime name, such as `node`. */
  runtimeName: string;
  /** Runtime version reported by the emitter. */
  runtimeVersion: string;
  /** Process identifier reported on the authenticated connection. */
  pid: bigint;
  /** Monotonic process-start sample in nanoseconds. */
  processStartMonotonicNs: bigint;
}

/** Authenticates to the loopback daemon using the pinned TLS exporter transcript. */
export async function openXtpSession(
  bootstrap: Bootstrap,
  manifestPath: string,
  identity: AdapterIdentity,
): Promise<AuthenticatedXtpSession> {
  let socket: tls.TLSSocket | undefined;
  let authenticated = false;
  try {
    const manifestBytes = await readFile(manifestPath);
    const manifestDigest = `b3:${await blake3(manifestBytes)}`;
    const clientNonce = randomBytes(32);
    const runtimeSessionId = Buffer.from(parseUuid(bootstrap.runtime_session_id));
    socket = tls.connect({
      host: bootstrap.host,
      port: bootstrap.port,
      minVersion: "TLSv1.3",
      maxVersion: "TLSv1.3",
      rejectUnauthorized: false,
    });
    const activeSocket = socket;
    const frames = readFrames(activeSocket, DEFAULT_MAX_ENVELOPE_BYTES)[Symbol.asyncIterator]();
    await connected(activeSocket);
    verifyCertificatePin(bootstrap.certificate_sha256_pin, activeSocket.getPeerCertificate(true).raw);
    const exporter = activeSocket.exportKeyingMaterial(32, EXPORTER_LABEL, Buffer.alloc(0));
    const proof = transcriptProof(
      bootstrap.session_secret,
      exporter,
      runtimeSessionId,
      clientNonce,
      ZERO_NONCE,
      Buffer.from(manifestDigest, "utf8"),
    );
    const hello = create(AgentEnvelopeSchema, {
      protocolMajor: bootstrap.max_protocol_major,
      protocolMinor: bootstrap.max_protocol_minor,
      runtimeSessionId,
      sessionSeq: 0n,
      sentMonotonicNs: process.hrtime.bigint(),
      messageId: `${identity.adapterName}-hello`,
      correlationToken: "",
      payload: {
        case: "adapterHello",
        value: create(AdapterHelloSchema, {
          adapterName: identity.adapterName,
          adapterVersion: identity.adapterVersion,
          adapterBuildHash: "",
          signingIdentity: "",
          manifestDigest,
          language: identity.language,
          runtimeName: identity.runtimeName,
          runtimeVersion: identity.runtimeVersion,
          pid: identity.pid,
          processStartMonotonicNs: identity.processStartMonotonicNs,
          parentLaunchId: "",
          repositoryFingerprint: bootstrap.expected_repository_fingerprint,
          protocolMajorMax: bootstrap.max_protocol_major,
          protocolMinorMax: bootstrap.max_protocol_minor,
          clientNonce,
          hmac: proof,
        }),
      },
    });
    await writeEnvelope(activeSocket, hello, DEFAULT_MAX_ENVELOPE_BYTES);
    const daemonEnvelope = await nextFrame(frames);
    if (daemonEnvelope.payload.case !== "daemonHello" || daemonEnvelope.sessionSeq !== 0n ||
        !equalBytes(daemonEnvelope.runtimeSessionId, runtimeSessionId)) {
      throw new XtraceClientError("XTR-NODE-HANDSHAKE", "daemon hello identity is invalid");
    }
    const daemonHello = daemonEnvelope.payload.value;
    if (daemonHello.protocolMajor !== bootstrap.max_protocol_major ||
        daemonHello.protocolMinor > bootstrap.max_protocol_minor ||
        daemonEnvelope.protocolMajor !== daemonHello.protocolMajor ||
        daemonEnvelope.protocolMinor !== daemonHello.protocolMinor ||
        daemonHello.manifestDigest !== manifestDigest || daemonHello.serverNonce.length !== 32) {
      throw new XtraceClientError("XTR-NODE-HANDSHAKE", "daemon hello negotiation is invalid");
    }
    const expectedProof = transcriptProof(
      bootstrap.session_secret,
      exporter,
      runtimeSessionId,
      clientNonce,
      daemonHello.serverNonce,
      Buffer.from(manifestDigest, "utf8"),
    );
    verifyTranscriptProof(expectedProof, daemonHello.hmac);
    const maxBytes = daemonHello.maxEnvelopeBytes;
    if (maxBytes < 1 || maxBytes > MAX_ENVELOPE_BYTES || daemonHello.maxBatchEvents < 1) {
      throw new XtraceClientError("XTR-NODE-HANDSHAKE", "daemon limits are invalid");
    }

    authenticated = true;
    let nextSeq = 1n;
    let closing = false;
    let closed = false;
    let closePromise: Promise<void> | undefined;
    const sendQueue = new BoundedSendQueue(64);
    async function send(
      messageId: string,
      payload: AgentEnvelope["payload"],
      correlationToken = "",
    ): Promise<AgentEnvelope["payload"] & { case: "ack" }> {
      if (closing || closed) throw new XtraceClientError("XTR-NODE-TRANSPORT", "XTP session is closing or closed");
      if (messageId.length === 0) throw new XtraceClientError("XTR-NODE-ENVELOPE", "message ID must not be empty");
      return sendQueue.enqueue(async () => {
        const seq = nextSeq;
        const envelope = create(AgentEnvelopeSchema, {
          protocolMajor: daemonHello.protocolMajor,
          protocolMinor: daemonHello.protocolMinor,
          runtimeSessionId,
          sessionSeq: seq,
          sentMonotonicNs: process.hrtime.bigint(),
          messageId,
          correlationToken,
          payload,
        });
        try {
          await writeEnvelope(activeSocket, envelope, maxBytes);
          const response = await nextAck(frames);
          if (response.runtimeSessionId.length !== runtimeSessionId.length ||
              !equalBytes(response.runtimeSessionId, runtimeSessionId) ||
              response.protocolMajor !== daemonHello.protocolMajor ||
              response.protocolMinor !== daemonHello.protocolMinor ||
              response.payload.case !== "ack" ||
              response.payload.value.durability !== AckDurability.STAGED ||
              response.payload.value.highestContiguousSessionSeq !== seq ||
              response.payload.value.rejected.length !== 0) {
            throw new XtraceClientError("XTR-NODE-ACK", `daemon did not stage session sequence ${seq}`);
          }
          nextSeq += 1n;
          return response.payload as AgentEnvelope["payload"] & { case: "ack" };
        } catch (error) {
          activeSocket.destroy();
          throw error;
        }
      });
    }
    return {
      protocolMajor: daemonHello.protocolMajor,
      protocolMinor: daemonHello.protocolMinor,
      runtimeSessionId,
      maxEnvelopeBytes: maxBytes,
      send,
      async close() {
        if (closePromise) return closePromise;
        closing = true;
        closePromise = (async () => {
          await sendQueue.drain();
          closed = true;
          await new Promise<void>((resolve) => {
            const timer = setTimeout(finish, 250);
            function finish(): void {
              clearTimeout(timer);
              activeSocket.off("close", finish);
              resolve();
            }
            activeSocket.once("close", finish);
            activeSocket.end();
          });
          activeSocket.destroy();
        })();
        return closePromise;
      },
    };
  } finally {
    bootstrap.session_secret.fill(0);
    if (!authenticated) socket?.destroy();
  }
}

/** Rejects any leaf certificate that does not match the bootstrap's DER SHA-256 pin. */
export function verifyCertificatePin(expectedHex: string, certificateDer: Uint8Array): void {
  const actual = createHash("sha256").update(certificateDer).digest();
  const expected = Buffer.from(expectedHex, "hex");
  if (!/^[0-9a-f]{64}$/.test(expectedHex) || actual.length !== expected.length ||
      !timingSafeEqual(actual, expected)) {
    throw new XtraceClientError("XTR-NODE-TLS-PIN", "daemon certificate pin did not match bootstrap");
  }
}

function connected(socket: tls.TLSSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("secureConnect", onSecureConnect);
      socket.off("error", onError);
    };
    const onSecureConnect = () => { cleanup(); resolve(); };
    const onError = () => {
      cleanup();
      reject(new XtraceClientError("XTR-NODE-CONNECT", "daemon TLS connection failed"));
    };
    const timeout = setTimeout(() => {
      cleanup();
      reject(new XtraceClientError("XTR-NODE-CONNECT", "daemon TLS connection timed out"));
    }, 5000);
    socket.once("secureConnect", onSecureConnect);
    socket.once("error", onError);
  });
}

async function writeEnvelope(socket: tls.TLSSocket, envelope: AgentEnvelope, limit: number): Promise<void> {
  const frame = encodeFrame(envelope, limit);
  await new Promise<void>((resolve, reject) => {
    socket.write(frame, (error) => error ? reject(new XtraceClientError("XTR-NODE-TRANSPORT", "daemon write failed")) : resolve());
  });
}

async function nextFrame(iterator: AsyncIterator<AgentEnvelope>): Promise<AgentEnvelope> {
  let timeout: NodeJS.Timeout | undefined;
  const result = await Promise.race([
    iterator.next(),
    new Promise<never>((_, reject) => {
      timeout = setTimeout(
        () => reject(new XtraceClientError("XTR-NODE-TRANSPORT", "daemon response timed out")),
        5000,
      );
    }),
  ]).finally(() => clearTimeout(timeout));
  if (result.done) throw new XtraceClientError("XTR-NODE-TRANSPORT", "daemon closed the XTP connection");
  return result.value;
}

async function nextAck(iterator: AsyncIterator<AgentEnvelope>): Promise<AgentEnvelope> {
  for (let healthCount = 0; healthCount < 16; healthCount += 1) {
    const envelope = await nextFrame(iterator);
    if (envelope.payload.case !== "health") return envelope;
  }
  throw new XtraceClientError("XTR-NODE-TRANSPORT", "daemon sent too many unsolicited health frames");
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
