// Small lifecycle decisions shared by the real runner and hosted failure regressions.
export function readbackVerdict(code, document) {
  const processSucceeded = code === 0;
  return { ...document, processSucceeded,
    status: processSucceeded && document?.status === "passed" ? "passed" : "failed" };
}

export function readbackReceipt(code, loadDocument) {
  let document;
  try { document = loadDocument(); } catch { /* The process verdict survives unreadable evidence. */ }
  return { ...readbackVerdict(code, document), processExit: Number.isInteger(code) ? code : null,
    documentStatus: ["passed", "failed"].includes(document?.status) ? document.status : null,
    documentAvailable: Boolean(document && typeof document === "object" && !Array.isArray(document)) };
}

export function installedReadbackReceipt({ attachExit, processExit }, loadDocument) {
  const receipt = readbackReceipt(processExit, loadDocument);
  return { ...receipt, attachExit, status: attachExit === 0 ? receipt.status : "failed" };
}

export function launcherObservations(liveBeforeStop, wait, terminal) {
  const normal = liveBeforeStop && wait.status === 0 && wait.stdout.trim() === "0" && terminal.normalExit === true;
  const marker = terminal.captureIncompleteNotice;
  return { shutdown: normal ? "normal" : "failed",
    captureNotice: marker === false ? "absent" : marker === true ? "present" : "unknown" };
}

export function installedCaptureDisposition(state) {
  const stopped = state.shutdown === "normal";
  return { allowReadback: stopped, eligibleForPass: stopped && state.captureNotice === "absent" };
}

export function cleanupPairFixture(fixture, names, directory) {
  // The service fixture owns its cooperating worker and database. Remove helper and app handles first.
  for (const [name, id] of [...fixture.containers]) {
    if (name === names.db || name === names.worker) continue;
    let removed = false;
    try { removed = fixture.command(["rm", "-v", id], { allowFail: true }).status === 0; } catch {}
    if (!removed) {
      fixture.recordKeptHandles(directory);
      return "retained";
    }
    fixture.containers.delete(name);
  }
  fixture.cleanup();
  return "passed";
}

const defaultWait = (promise, milliseconds) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("Vendure owned child wait deadline")), milliseconds);
  promise.then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
});
const live = child => child.exitCode === null && child.signalCode === null;

export function signalOwnedChild(child, signal) {
  return live(child) ? child.kill(signal) : false;
}

export async function stopOwnedViewer(child, closed, wait = defaultWait) {
  // ChildProcess exit fields are set before close; never signal an exited child or use its old PID.
  const liveAtStop = live(child);
  const stopSignalled = liveAtStop && signalOwnedChild(child, "SIGTERM");
  try {
    const [code, signal] = await wait(closed, 25000);
    return { status: liveAtStop && stopSignalled && code === 0 && signal === null ? "normal" : "failed",
      earlyExit: !liveAtStop, recovery: false };
  } catch {
    // The timeout can race exit. Re-read the live handle immediately before any recovery signal.
    const recoverySignalled = signalOwnedChild(child, "SIGKILL");
    try { await wait(closed, 5000); } catch {}
    return { status: "failed", earlyExit: !liveAtStop, recovery: true, recoverySignalled: Boolean(recoverySignalled) };
  }
}
