// Only a ChildProcess returned by this invocation may be stopped here.
export function waitForExit(child, milliseconds) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise(resolve => {
    const finished = () => { clearTimeout(timer); child.off('exit', finished); resolve(true); };
    const timer = setTimeout(() => { child.off('exit', finished); resolve(false); }, milliseconds);
    child.once('exit', finished);
  });
}

export async function stopViewer(child, wait = waitForExit) {
  if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
  child.kill('SIGTERM');
  if (await wait(child, 15000)) return;
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  const reaped = await wait(child, 5000);
  // Reaping after forced termination never makes a graceful shutdown pass.
  throw new Error(reaped ? 'viewer graceful shutdown timed out' : 'viewer child was not reaped');
}
