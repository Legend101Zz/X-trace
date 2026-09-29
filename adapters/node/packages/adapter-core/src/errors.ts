/** Safe, secret-free client failure that is suitable for CLI output. */
export class XtraceClientError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "XtraceClientError";
  }
}
