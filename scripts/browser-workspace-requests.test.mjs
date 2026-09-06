import assert from "node:assert/strict";
import {createServer} from "node:http";
import test from "node:test";

import {fetchWorkspaceJSON, fetchWorkspaceResponse, workspaceFailure, WorkspaceRequestError} from "../internal/command/requirementbrowser/assets/workspace-requests.js";
import {workspaceScalarText} from "../internal/command/requirementbrowser/assets/workspace-json.js";

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

test("the raw response carrier preserves exact numeric and escaped JSON bytes", async t => {
  const body = '{"number":9007199254740993,"escaped":"\\u0061","text":"\\u{1F642}"}\n'.replace("\\u{1F642}", "\\ud83d\\ude42");
  let calls = 0;
  const fixture = await endpoint(t, response => {
    calls++;
    response.writeHead(200, {"Content-Type": "application/json"});
    response.end(body);
  });
  const result = await fetchWorkspaceResponse(fixture.url, {});
  assert.equal(result.text, body);
  assert.notEqual(JSON.stringify(result.value) + "\n", body);
  assert.equal(calls, 1);
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

test("HTTP numeric observations retain exact tokens and native scalar branding", async t => {
  const body = '{"start":9007199254740992,"end":9007199254740993,"safe":9007199254740991,"zero":0,"string":"9007199254740993","nested":[1.0000000000000001,1e-400,-0,1e400,-9007199254740993,0.123456789012345678901],"unbranded":{"rawJSON":"17"}}';
  const fixture = await endpoint(t, response => response.end(body));
  const {value, text} = await fetchWorkspaceResponse(fixture.url, {});
  assert.equal(text, body);
  assert.equal(JSON.stringify(value), body);
  assert.equal(workspaceScalarText(value.start), "9007199254740992");
  assert.equal(workspaceScalarText(value.end), "9007199254740993");
  assert.equal(value.safe, 9007199254740991);
  assert.equal(value.zero, 0);
  assert.equal(typeof value.string, "string");
  assert.equal(value.string, "9007199254740993");
  assert.equal(JSON.isRawJSON(value.unbranded), false);
  assert.equal(workspaceScalarText(value.unbranded), "[object Object]");
  for (const raw of [value.start, value.end, ...value.nested]) {
    assert.equal(JSON.isRawJSON(raw), true);
    assert.equal(Object.isFrozen(raw), true);
    assert.equal(Object.getPrototypeOf(raw), null);
  }
});

test("missing native numeric factories fail closed without a rounded success", async t => {
  const fixture = await endpoint(t, response => response.end("9007199254740993"));
  for (const name of ["rawJSON", "isRawJSON"]) {
    const descriptor = Object.getOwnPropertyDescriptor(JSON, name);
    assert(descriptor);
    try {
      Object.defineProperty(JSON, name, {...descriptor, value: undefined});
      const error = await fetchWorkspaceJSON(fixture.url, {}).catch(error => error);
      assert(error instanceof SyntaxError);
      assert.deepEqual(workspaceFailure(error), {message: "The admitted workspace is unavailable.", action: "none", lock: false, kind: "unavailable"});
    } finally { Object.defineProperty(JSON, name, descriptor); }
  }
});

test("missing reviver source context cannot admit rounded numeric observations", async t => {
  const nativeParse = JSON.parse;
  t.mock.method(JSON, "parse", (source, reviver) => typeof reviver === "function" ? nativeParse(source, (key, value) => reviver(key, value)) : nativeParse(source, reviver));
  assert.deepEqual(JSON.parse('{"unrelated":1}'), {unrelated: 1});
  const fixture = await endpoint(t, response => response.end("1.0000000000000001"));
  await assert.rejects(fetchWorkspaceJSON(fixture.url, {}), {name: "SyntaxError", message: "Exact numeric observation is unavailable"});
});
