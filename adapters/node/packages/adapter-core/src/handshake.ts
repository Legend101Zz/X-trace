import { createHmac, timingSafeEqual } from "node:crypto";
import { XtraceClientError } from "./errors.js";

const LABEL = Buffer.from("xtrace-handshake-v1", "ascii");
export const ZERO_NONCE = Buffer.alloc(32);

/** Encodes the canonical length-prefixed XTP transcript fields and returns its HMAC-SHA256 proof. */
export function transcriptProof(
  secret: Uint8Array,
  exporter: Uint8Array,
  sessionId: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
  manifestDigest: Uint8Array,
): Buffer {
  const hmac = createHmac("sha256", secret).update(LABEL);
  for (const field of [exporter, sessionId, clientNonce, serverNonce, manifestDigest]) {
    if (field.byteLength > 0xffff_ffff) {
      throw new XtraceClientError("XTR-NODE-HANDSHAKE", "transcript field exceeds u32 length");
    }
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(field.byteLength);
    hmac.update(length).update(field);
  }
  return hmac.digest();
}

/** Constant-time proof check for the daemon's reply transcript. */
export function verifyTranscriptProof(expected: Uint8Array, actual: Uint8Array): void {
  if (expected.byteLength !== 32 || actual.byteLength !== 32 || !timingSafeEqual(expected, actual)) {
    throw new XtraceClientError("XTR-NODE-HANDSHAKE", "daemon transcript proof is invalid");
  }
}
