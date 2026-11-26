// Closed, finite observations only; a missing/interrupted document proves nothing.
import fs from "node:fs";

const PHASES = ["identity", "version", "init", "list", "empty", "receipt"];
export function signalClass(signal) {
  if (signal === null || signal === undefined) return null;
  if (signal === "SIGTERM" || signal === "SIGKILL") return signal;
  return typeof signal === "string" && /^SIG[A-Z0-9]{1,12}$/.test(signal) ? "other" : null;
}
export function validObservation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).join(",") !== "phase,status,code,signal") return false;
  const { phase, status, code, signal } = value;
  if (!PHASES.includes(phase) || !["running", "passed", "failed"].includes(status) ||
      !(code === null || (Number.isInteger(code) && code >= 0 && code <= 255)) ||
      ![null, "SIGTERM", "SIGKILL", "other"].includes(signal) || (code !== null && signal !== null)) return false;
  if (status === "passed" && phase !== "receipt") return false;
  if (status !== "failed" && (code !== null || signal !== null)) return false;
  return true;
}
function readCanonical(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.uid !== process.getuid() || before.nlink !== 1 ||
        (before.mode & 0o777) !== 0o600 || before.size < 1 || before.size > 1024) return null;
    const buffer = Buffer.alloc(before.size + 1), length = fs.readSync(fd, buffer, 0, buffer.length, 0);
    const after = fs.fstatSync(fd);
    if (length !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) return null;
    const text = buffer.subarray(0, length).toString("utf8"), value = JSON.parse(text);
    return text === JSON.stringify(value) + "\n" ? value : null;
  } catch { return null; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
export function preflightExitVerdict({ attachExit, processExit }, document, observation) {
  return attachExit === 0 && processExit === 0 && document?.passed === true && observation?.phase === "receipt" && observation?.status === "passed";
}

export function readPreflightObservation(file) {
  const value = readCanonical(file);
  return validObservation(value) ? value : null;
}
export function readPreflightReceipt(file) {
  const value = readCanonical(file);
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).join(",") !== "passed,projectId" || value.passed !== true ||
      typeof value.projectId !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.projectId)) return null;
  return value;
}
