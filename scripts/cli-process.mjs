// Transport check for oracles that run the Proofkit CLI through spawnSync.
//
// A CLI that refuses its flags exits before it reads stdin, so spawnSync
// can report EPIPE for the input it could not write. As in
// internal/tools/workflowsmoke/process_streams.go, that is an ordinary early
// exit and not a transport failure. EPIPE is accepted only when the child
// exited normally with a non-zero status and no signal. Any other spawn error,
// a timeout, a signal, or EPIPE with status 0 (a success that did not consume
// its input) fails. Callers keep their own status, stdout and stderr checks.
import assert from "node:assert/strict";

export function assertCLITransport(result, label = "CLI") {
  const observed = `${label}: transport error ${result.error}, status ${result.status}, signal ${result.signal}`;
  assert.equal(result.signal, null, observed);
  if (result.error !== undefined) {
    assert.equal(result.error.code, "EPIPE", observed);
    assert.ok(Number.isInteger(result.status) && result.status !== 0, observed);
  }
  return result;
}
