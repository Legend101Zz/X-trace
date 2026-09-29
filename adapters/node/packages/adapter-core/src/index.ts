export { readBootstrap, validateBootstrap, type Bootstrap } from "./bootstrap.js";
export { encodeFrame, readFrames } from "./framing.js";
export { transcriptProof, verifyTranscriptProof, ZERO_NONCE } from "./handshake.js";
export {
  openXtpSession,
  verifyCertificatePin,
  type AdapterIdentity,
  type AuthenticatedXtpSession,
} from "./session.js";
export { XtraceClientError } from "./errors.js";
