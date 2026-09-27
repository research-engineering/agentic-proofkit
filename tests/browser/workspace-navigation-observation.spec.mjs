import {expect} from "@playwright/test";
import {runInNewContext} from "node:vm";
import {createServer} from "node:http";
import {once} from "node:events";
import {test} from "./workspace-test-harness.mjs";
import {navigateWorkspace, openWorkspace, reloadWorkspace} from "./workspace-navigation-harness.mjs";

const target = "http://127.0.0.1:41001/";
const rejection = "Workspace observation was not admitted";
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function protocolModel(realPage, change) {
  const state = {winner: "document", current: {location: {href: target}, readyState: "complete"}, status: 200, disposition: "", csp, nosniff: "nosniff", token: true, handles: [], phases: [], listeners: new Map(), waits: new Map()};
  change(state);
  const evaluate = (fn, arg) => runInNewContext(`(${fn.toString()})(argument)`, {document: state.current, argument: arg});
  const handle = value => {
    const result = {value, disposed: false, disposals: 0, async dispose() {
      expect(state.listeners.size).toBe(0);
      result.disposals++;
      await state.onDispose?.();
      result.disposed = true;
      if (state.disposeError) throw new Error("controlled disposal failure");
    }};
    state.handles.push(result);
    return result;
  };
  const pending = (name, signal) => {
    const deferred = Promise.withResolvers();
    const onAbort = () => {
      state.phases.push(`${name}:abort`);
      state.onAbort?.();
      deferred.reject(new Error("controlled observer cancellation", {cause: signal.reason}));
    };
    signal.addEventListener("abort", onAbort, {once: true});
    const promise = deferred.promise.finally(() => {
      signal.removeEventListener("abort", onAbort);
      state.waits.delete(name);
    });
    state.waits.set(name, deferred);
    state.phases.push(`${name}:armed`);
    return promise;
  };
  const emit = (name, value) => { state.listeners.get(name)?.(value); };
  const frame = {url: () => target, async waitForLoadState(name) {
    expect(name).toBe("domcontentloaded");
    state.phases.push("domcontentloaded");
    state.atLoad?.();
    if (state.deferredAcquisition) state.signal.addEventListener("abort", () => {
      state.phases.push("acquisition:after-abort");
      if (state.rejectAcquisition) state.acquisition.reject(state.rejectAcquisition);
      else state.acquisition.resolve();
    }, {once: true});
  }};
  const request = {isNavigationRequest: () => true, frame: () => frame, url: () => target};
  const response = {request: () => request, url: () => target, ok: () => state.status >= 200 && state.status < 300,
    headers: () => ({"content-security-policy": state.csp, "x-content-type-options": state.nosniff, "content-disposition": state.disposition})};
  const fake = {
    mainFrame: () => frame,
    on: (name, listener) => { state.listeners.set(name, listener); },
    off: name => { state.listeners.delete(name); },
    async evaluate(fn, arg) {
      if (typeof arg === "string") return evaluate(fn, arg);
      state.beforeTerminal?.();
      state.phases.push("terminal");
      if (state.terminalError) throw state.terminalError;
      return evaluate(fn, {...arg, witness: arg.witness.value});
    },
    async evaluateHandle(fn) {
      const value = evaluate(fn);
      if (state.deferredAcquisition) {
        state.acquisition = Promise.withResolvers();
        await state.acquisition.promise;
      }
      return handle(value);
    },
    getByRole: (...args) => realPage.getByRole(...args),
    waitForResponse(predicate, {signal}) { state.responsePredicate = predicate; return pending("response", signal); },
    waitForEvent(name, {predicate, signal}) { expect(name).toBe("framenavigated"); state.eventPredicate = predicate; return pending("event", signal); },
    waitForFunction(fn, arg, {signal}) { state.signal = signal; state.documentPredicate = () => evaluate(fn, arg); return pending("document", signal); },
  };
  const trigger = async token => {
    expect([...state.waits.keys()]).toEqual(["response", "event", "document"]);
    if (state.throwTrigger) throw new Error("controlled trigger failure");
    if (!state.keepOriginal) state.current = {location: {href: target}, readyState: "complete"};
    state.afterDocument?.();
    if (state.prefixRequest) emit("request", {...request});
    if (state.foreignPrefix) emit("request", {...request, url: () => `${target}foreign`});
    emit("request", request);
    emit("response", state.otherObservedResponse ? {...response} : response);
    expect(state.responsePredicate(response)).toBe(true);
    state.waits.get("response").resolve(response);
    if (state.extraRequest) emit("request", {...request});
    if (state.extraResponse) emit("response", {...response});
    if (state.foreignRequest) emit("request", {...request, url: () => `${target}foreign`});
    if (state.download) emit("download", {});
    if (state.winner !== "document") {
      expect(state.eventPredicate(frame)).toBe(true);
      state.waits.get("event").resolve(frame);
    }
    if (state.winner !== "event") {
      const value = state.documentPredicate();
      expect(value).toBe(state.current);
      state.waits.get("document").resolve(handle(value));
    }
    if (state.unexpectedObserverError) state.waits.get("event").reject(new Error("controlled observer failure"));
    state.emit = emit;
    state.request = request;
    return state.token ? token : "wrong-token";
  };
  return {state, fake, trigger};
}

test("controlled navigation protocol preserves operands, document identity and joined cleanup", async ({page}) => {
  await page.setContent("<h1>browser.fixture.workspace</h1>");
  const cases = [
    {name: "document winner", change: () => {}, passed: true},
    {name: "event winner", change: s => { s.winner = "event"; }, passed: true},
    {name: "both fulfilled handles", change: s => { s.winner = "both"; }, passed: true},
    {name: "earlier response-less prefix", change: s => { s.prefixRequest = true; }, passed: true},
    {name: "bad trigger token", change: s => { s.token = false; }, error: "trigger token"},
    {name: "trigger throws", change: s => { s.throwTrigger = true; }, error: "controlled trigger failure"},
    {name: "failed response despite ready document", change: s => { s.status = 503; }, error: rejection},
    {name: "original document", change: s => { s.winner = "event"; s.keepOriginal = true; }, error: rejection},
    {name: "actual URL mismatch", change: s => { s.winner = "event"; s.afterDocument = () => { s.current.location.href = `${target}foreign`; }; }, error: rejection},
    {name: "document replaced after readiness", change: s => { s.beforeTerminal = () => { s.current = {location: {href: target}, readyState: "complete"}; }; }, error: rejection},
    {name: "late request", change: s => { s.extraRequest = true; }, error: rejection},
    {name: "extra response", change: s => { s.extraResponse = true; }, error: rejection},
    {name: "foreign response-less prefix", change: s => { s.foreignPrefix = true; }, error: rejection},
    {name: "singleton response identity mismatch", change: s => { s.otherObservedResponse = true; }, error: rejection},
    {name: "terminal document loading", change: s => { s.beforeTerminal = () => { s.current.readyState = "loading"; }; }, error: rejection},
    {name: "attachment", change: s => { s.disposition = "attachment"; }, error: rejection},
    {name: "download", change: s => { s.download = true; }, error: rejection},
    {name: "wrong CSP", change: s => { s.csp = "default-src *"; }, error: rejection},
    {name: "missing nosniff", change: s => { s.nosniff = ""; }, error: rejection},
    {name: "unexpected losing observer error", change: s => { s.unexpectedObserverError = true; }, error: "controlled observer failure"},
    {name: "late request during observer join", change: s => { s.onAbort = () => { s.emit?.("request", {...s.request}); }; }, error: rejection},
    {name: "events after the closed interval", change: s => { s.onDispose = async () => {
      await Promise.resolve();
      for (const name of ["request", "response", "download"]) s.emit(name, {...s.request});
    }; }, passed: true},
    {name: "disposal failure", change: s => { s.winner = "both"; s.disposeError = true; }, error: "cleanup failed"},
    {name: "losing handle acquired after abort", change: s => { s.winner = "both"; s.deferredAcquisition = true; }, passed: true},
    {name: "late non-owned acquisition failure", change: s => { s.winner = "both"; s.deferredAcquisition = true; s.rejectAcquisition = new Error("late acquisition failure"); }, error: "late acquisition failure"},
    {name: "terminal context error", change: s => { s.terminalError = new Error("terminal sentinel"); }, error: rejection},
    {name: "terminal and disposal errors", change: s => { s.terminalError = new Error("terminal sentinel"); s.disposeError = true; }, error: "cleanup failed"},
  ];
  for (const item of cases) {
    try {
      const {state, fake, trigger} = protocolModel(page, item.change);
      const operation = navigateWorkspace(fake, target, trigger, rejection);
      if (item.passed) await operation;
      else {
        const error = await operation.then(() => undefined, error => error);
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toContain(item.error);
        if (state.terminalError) {
          const terminalError = state.disposeError ? error.cause : error;
          expect(terminalError.message).toBe(rejection);
          expect(terminalError.cause).toBe(state.terminalError);
          if (state.disposeError) {
            expect(error.errors[0]).toBe(terminalError);
            expect(error.errors).toHaveLength(state.handles.length + 1);
          }
        }
        if (state.rejectAcquisition) expect(error).toBe(state.rejectAcquisition);
      }
      expect(state.waits.size).toBe(0);
      expect(state.listeners.size).toBe(0);
      expect(state.handles.every(handle => handle.disposed && handle.disposals === 1)).toBe(true);
      if (item.passed) {
        expect(state.phases.filter(phase => phase === "domcontentloaded")).toHaveLength(1);
        expect(state.phases.indexOf("domcontentloaded")).toBeLessThan(state.phases.indexOf("terminal"));
        if (state.deferredAcquisition) expect(state.phases).toContain("acquisition:after-abort");
      }
    } catch (cause) {
      throw new Error(`Controlled navigation case failed: ${item.name}`, {cause});
    }
  }
});

for (const action of ["open", "reload"]) test(`actual document readiness admits ${action} without a frame-event observation`, async ({baseURL, page}) => {
  if (action === "reload") await openWorkspace(page, baseURL);
  const original = page.waitForEvent.bind(page);
  let held = 0, cancelled = 0;
  page.waitForEvent = (name, options) => {
    if (name !== "framenavigated") return original(name, options);
    held++;
    return new Promise((_resolve, reject) => options.signal.addEventListener("abort", () => {
      cancelled++;
      reject(new Error("held frame observation cancelled", {cause: options.signal.reason}));
    }, {once: true}));
  };
  try {
    await (action === "open" ? openWorkspace(page, baseURL) : reloadWorkspace(page, baseURL));
    expect(held).toBe(1);
    expect(cancelled).toBe(1);
    await expect(page.getByRole("heading", {name: "browser.fixture.workspace", exact: true})).toBeVisible();
    expect(await page.evaluate(() => document.location.href)).toBe(baseURL);
  } finally { page.waitForEvent = original; }
});

test("final navigation URL comes from the witnessed document, not a stale driver accessor", async ({baseURL, page}) => {
  const original = page.url.bind(page);
  page.url = () => "about:blank";
  try {
    await openWorkspace(page, baseURL);
    expect(await page.evaluate(() => document.location.href)).toBe(baseURL);
  } finally { page.url = original; }
});

for (const holdFrame of [false, true]) test(`navigation waits for native deferred-script completion with held frame observation ${holdFrame}`, async ({page}) => {
  const scriptRequested = Promise.withResolvers();
  const releaseScript = Promise.withResolvers();
  const enteredLoad = Promise.withResolvers();
  const server = createServer((request, response) => {
    if (request.url === "/observe.js") {
      response.writeHead(200, {"Content-Type": "text/javascript"}).end("globalThis.workspaceDCLObserved = false; document.addEventListener('DOMContentLoaded', () => { globalThis.workspaceDCLObserved = true; }, {once: true});");
      return;
    }
    if (request.url === "/held.js") {
      scriptRequested.resolve();
      void releaseScript.promise.then(() => response.writeHead(200, {"Content-Type": "text/javascript"}).end("globalThis.deferredWorkspaceScriptCompleted = true;"));
      return;
    }
    response.writeHead(200, {"Content-Type": "text/html", "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff"});
    response.end('<!doctype html><html><head><script src="/observe.js"></script><script defer src="/held.js"></script></head><body><h1>browser.fixture.workspace</h1></body></html>');
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}/`;
  const frame = page.mainFrame();
  const originalLoad = frame.waitForLoadState.bind(frame);
  const originalEvent = page.waitForEvent.bind(page);
  let completed = false, frameCancelled = 0;
  frame.waitForLoadState = (name, options) => {
    expect(name).toBe("domcontentloaded");
    enteredLoad.resolve();
    return originalLoad(name, options);
  };
  if (holdFrame) page.waitForEvent = (name, options) => {
    if (name !== "framenavigated") return originalEvent(name, options);
    return new Promise((_resolve, reject) => options.signal.addEventListener("abort", () => {
      frameCancelled++;
      reject(new Error("held frame observation cancelled", {cause: options.signal.reason}));
    }, {once: true}));
  };
  const operation = openWorkspace(page, url);
  const settled = operation.then(() => { completed = true; }, () => { completed = true; });
  try {
    await Promise.race([enteredLoad.promise, operation.then(() => { throw new Error("Navigation completed before its native DCL wait"); })]);
    await scriptRequested.promise;
    await expect(page.getByRole("heading", {name: "browser.fixture.workspace", exact: true})).toBeVisible();
    expect(await page.evaluate(() => ({state: document.readyState, script: globalThis.deferredWorkspaceScriptCompleted === true}))).toEqual({state: "interactive", script: false});
    expect(await page.evaluate(() => globalThis.workspaceDCLObserved)).toBe(false);
    expect(completed).toBe(false);
    releaseScript.resolve();
    await operation;
    expect(await page.evaluate(() => globalThis.deferredWorkspaceScriptCompleted)).toBe(true);
    expect(await page.evaluate(() => globalThis.workspaceDCLObserved)).toBe(true);
    expect(frameCancelled).toBe(holdFrame ? 1 : 0);
  } finally {
    releaseScript.resolve();
    await settled;
    frame.waitForLoadState = originalLoad;
    page.waitForEvent = originalEvent;
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
