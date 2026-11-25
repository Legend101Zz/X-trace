/** The CLI's fixed notice is evidence of incomplete capture, not a clean-drain receipt. */
export function captureNoticeOutcome(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 32 * 1024 * 1024) return "unavailable";
  return bytes.includes("XTR-RUN-CAPTURE-INCOMPLETE") ? "present" : "absent";
}
