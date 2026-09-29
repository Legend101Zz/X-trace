import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { AgentEnvelopeSchema, type AgentEnvelope } from "@xtrace/protocol";
import { XtraceClientError } from "./errors.js";

const MAX_ENVELOPE_BYTES = 8 * 1024 * 1024;

/** Decodes fragmented frames while keeping only one bounded protobuf body in memory. */
export async function* readFrames(
  source: AsyncIterable<Uint8Array>,
  maxBytes: number,
): AsyncGenerator<AgentEnvelope> {
  validateLimit(maxBytes);
  let buffered = Buffer.alloc(0);
  let expected: number | undefined;
  for await (const chunk of source) {
    let offset = 0;
    while (offset < chunk.length) {
      if (expected === undefined) {
        const missingHeader = 4 - buffered.length;
        const copiedHeader = Math.min(missingHeader, chunk.length - offset);
        buffered = Buffer.concat([buffered, chunk.subarray(offset, offset + copiedHeader)]);
        offset += copiedHeader;
        if (buffered.length < 4) continue;
        expected = buffered.readUInt32BE(0);
        buffered = Buffer.alloc(0);
        if (expected === 0) throw new XtraceClientError("XTR-NODE-FRAME", "empty XTP envelope frame");
        if (expected > maxBytes) throw new XtraceClientError("XTR-NODE-FRAME", "XTP envelope exceeds negotiated limit");
      }
      const needed = expected - buffered.length;
      const copiedBody = Math.min(needed, chunk.length - offset);
      buffered = Buffer.concat([buffered, chunk.subarray(offset, offset + copiedBody)]);
      offset += copiedBody;
      if (buffered.length < expected) continue;
      const body = buffered;
      buffered = Buffer.alloc(0);
      expected = undefined;
      try {
        yield fromBinary(AgentEnvelopeSchema, body);
      } catch {
        throw new XtraceClientError("XTR-NODE-FRAME", "XTP envelope protobuf is invalid");
      }
    }
  }
  if (buffered.length > 0 || expected !== undefined) {
    throw new XtraceClientError("XTR-NODE-FRAME", "connection ended inside an XTP frame");
  }
}

/** Encodes one bounded envelope as a four-byte big-endian length and protobuf body. */
export function encodeFrame(envelope: AgentEnvelope, maxBytes: number): Buffer {
  validateLimit(maxBytes);
  const body = Buffer.from(toBinary(AgentEnvelopeSchema, envelope));
  if (body.length === 0 || body.length > maxBytes || body.length > 0xffff_ffff) {
    throw new XtraceClientError("XTR-NODE-FRAME", "encoded XTP envelope exceeds negotiated limit");
  }
  const frame = Buffer.allocUnsafe(body.length + 4);
  frame.writeUInt32BE(body.length);
  body.copy(frame, 4);
  return frame;
}

function validateLimit(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_ENVELOPE_BYTES) {
    throw new XtraceClientError("XTR-NODE-FRAME", "XTP envelope limit is invalid");
  }
}
