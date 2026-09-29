import { constants } from "node:fs";
import { open, lstat } from "node:fs/promises";
import { isIP } from "node:net";
import { XtraceClientError } from "./errors.js";

/** Validated one-shot daemon bootstrap data. The secret buffer is caller-owned and must be wiped. */
export interface Bootstrap {
  /** Current daemon bootstrap document version. */
  schema_version: 1;
  /** Daemon-selected IPv4 or IPv6 loopback literal. */
  host: "127.0.0.1" | "::1";
  /** OS-assigned loopback TCP port. */
  port: number;
  /** SHA-256 pin of the ephemeral TLS leaf certificate DER bytes. */
  certificate_sha256_pin: string;
  /** Canonical UUID for this authenticated runtime session. */
  runtime_session_id: string;
  /** Decoded 32-byte transcript key; erased by the client after handshake. */
  session_secret: Buffer;
  /** Canonical project UUID bound out of band by the daemon. */
  project_id: string;
  /** Repository fingerprint required in AdapterHello. */
  expected_repository_fingerprint: string;
  /** Highest XTP major protocol version supported by the daemon. */
  max_protocol_major: number;
  /** Highest XTP minor protocol version supported by the daemon. */
  max_protocol_minor: number;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINGERPRINT = /^b3:[0-9a-f]{64}$/;
const MAX_BOOTSTRAP_BYTES = 64 * 1024;

/** Reads a private daemon bootstrap file, rejecting a symlink at its final path. */
export async function readBootstrap(path: string): Promise<Bootstrap> {
  if (process.platform === "win32") {
    throw new XtraceClientError("XTR-NODE-PLATFORM", "synthetic XTP client requires a Unix daemon bootstrap");
  }
  let handle;
  try {
    const before = await lstat(path);
    if (!before.isFile() || before.nlink !== 1 || before.size > MAX_BOOTSTRAP_BYTES || (before.mode & 0o077) !== 0) {
      throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap must be an owner-only regular file");
    }
    if (typeof process.getuid === "function" && before.uid !== process.getuid()) {
      throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap owner does not match the current user");
    }
    const noFollow = constants.O_NOFOLLOW;
    if (noFollow === undefined) {
      throw new XtraceClientError("XTR-NODE-PLATFORM", "platform cannot safely open bootstrap files");
    }
    handle = await open(path, constants.O_RDONLY | noFollow);
    const after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev || after.ino !== before.ino || (after.mode & 0o077) !== 0) {
      throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap changed while being opened");
    }
    const raw = Buffer.allocUnsafe(MAX_BOOTSTRAP_BYTES + 1);
    let bytesRead = 0;
    while (bytesRead < raw.length) {
      const result = await handle.read(raw, bytesRead, raw.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    if (bytesRead > MAX_BOOTSTRAP_BYTES) {
      raw.fill(0);
      throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap exceeds the allowed file size");
    }
    let value: unknown;
    try {
      value = JSON.parse(raw.subarray(0, bytesRead).toString("utf8"));
    } catch {
      throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap JSON is invalid");
    } finally {
      raw.fill(0);
    }
    return validateBootstrap(value);
  } catch (error) {
    if (error instanceof XtraceClientError) throw error;
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap could not be read safely");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Validates fields copied from the daemon-owned bootstrap schema. */
export function validateBootstrap(value: unknown): Bootstrap {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap must be a JSON object");
  }
  const data = value as Record<string, unknown>;
  const host = data.host;
  if (data.schema_version !== 1 || (host !== "127.0.0.1" && host !== "::1") || isIP(host) === 0) {
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap version or loopback host is invalid");
  }
  if (!Number.isInteger(data.port) || (data.port as number) < 1 || (data.port as number) > 65535) {
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap port is invalid");
  }
  const pin = data.certificate_sha256_pin;
  const runtimeSession = data.runtime_session_id;
  const project = data.project_id;
  const fingerprint = data.expected_repository_fingerprint;
  const encodedSecret = data.session_secret_base64;
  if (typeof pin !== "string" || !/^[0-9a-f]{64}$/.test(pin) ||
      typeof runtimeSession !== "string" || !UUID.test(runtimeSession) ||
      typeof project !== "string" || !UUID.test(project) ||
      typeof fingerprint !== "string" || !FINGERPRINT.test(fingerprint) ||
      typeof encodedSecret !== "string" || !/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/.test(encodedSecret)) {
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap identity or credential fields are invalid");
  }
  const secret = Buffer.from(encodedSecret, "base64");
  if (secret.length !== 32 || secret.toString("base64") !== encodedSecret) {
    secret.fill(0);
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap secret encoding is invalid");
  }
  data.session_secret_base64 = "";
  const major = data.max_protocol_major;
  const minor = data.max_protocol_minor;
  if (!Number.isInteger(major) || !Number.isInteger(minor) || (major as number) < 1 || (minor as number) < 0) {
    secret.fill(0);
    throw new XtraceClientError("XTR-NODE-BOOTSTRAP", "bootstrap protocol range is invalid");
  }
  return {
    schema_version: 1,
    host,
    port: data.port as number,
    certificate_sha256_pin: pin,
    runtime_session_id: runtimeSession,
    session_secret: secret,
    project_id: project,
    expected_repository_fingerprint: fingerprint,
    max_protocol_major: major as number,
    max_protocol_minor: minor as number,
  };
}
