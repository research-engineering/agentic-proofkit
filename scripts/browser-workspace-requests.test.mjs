import assert from "node:assert/strict";
import {createServer} from "node:http";
import test from "node:test";

import {fetchWorkspaceJSON, workspaceFailure, WorkspaceRequestError} from "../internal/command/requirementbrowser/assets/workspace-requests.js";

async function endpoint(t, respond) {
  const received = Promise.withResolvers();
  const headers = Promise.withResolvers();
  const server = createServer((request, response) => {
    respond(response);
    received.resolve(response);
  });
  server.on("clientError", (_error, socket) => socket.destroy());
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (...args) => {
    const response = await nativeFetch(...args);
    headers.resolve();
    return response;
  });
  return {url: `http://127.0.0.1:${server.address().port}/`, received: received.promise, headers: headers.promise};
}

function incompleteJSON(response) {
  response.writeHead(200, {"Content-Type": "application/json", "Content-Length": "200"});
  response.write('{"rows":');
}

test("a real body connection failure after successful headers remains retryable", async t => {
  const fixture = await endpoint(t, incompleteJSON);
  const outcome = fetchWorkspaceJSON(fixture.url, {}).catch(error => error);
  await fixture.headers;
  (await fixture.received).destroy();
  const error = await outcome;
  assert(error instanceof WorkspaceRequestError);
  assert.equal(error.status, 0);
  assert.deepEqual(workspaceFailure(error), {
    message: "The workspace could not be reached. Try this request again.",
    action: "retry", lock: false, kind: "retryable",
  });
});

test("aborting a pending response body preserves cancellation rather than Retry", async t => {
  const fixture = await endpoint(t, incompleteJSON);
  const controller = new AbortController();
  const outcome = fetchWorkspaceJSON(fixture.url, {signal: controller.signal}).catch(error => error);
  await fixture.headers;
  controller.abort();
  const error = await outcome;
  assert.equal(error.name, "AbortError");
  assert(!(error instanceof WorkspaceRequestError));
  assert.equal(workspaceFailure(error).action, "none");
});

test("a complete malformed JSON body is sanitized and non-retryable", async t => {
  const fixture = await endpoint(t, response => {
    response.writeHead(200, {"Content-Type": "application/json"});
    response.end("private malformed body");
  });
  const error = await fetchWorkspaceJSON(fixture.url, {}).catch(error => error);
  assert(error instanceof SyntaxError);
  assert.deepEqual(workspaceFailure(error), {
    message: "The admitted workspace is unavailable.", action: "none", lock: false, kind: "unavailable",
  });
});

test("a successful complete JSON body retains its admitted value", async t => {
  const fixture = await endpoint(t, response => {
    response.writeHead(200, {"Content-Type": "application/json"});
    response.end('{"requestId":"request.example","rows":[1]}');
  });
  assert.deepEqual(await fetchWorkspaceJSON(fixture.url, {}), {requestId: "request.example", rows: [1]});
});

test("HTTP status owns recovery before an unconsumed malformed body", async t => {
  const fixture = await endpoint(t, response => {
    response.writeHead(409, {"Content-Type": "application/json", "Content-Length": "200"});
    response.write("private malformed body");
  });
  const error = await fetchWorkspaceJSON(fixture.url, {}).catch(error => error);
  assert(error instanceof WorkspaceRequestError);
  assert.equal(error.status, 409);
  assert.deepEqual(workspaceFailure(error), {
    message: "The workspace snapshot has changed.", action: "reload", lock: true, kind: "stale",
  });
});
