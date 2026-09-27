import {expect} from "@playwright/test";
import {createHash, randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";

const workspaceNavigationToken = "proofkit.workspace-navigation.scheduled";
// Expected authority comes from source bytes, never a received CSP header.
const staticScriptDigest = createHash("sha256").update(readFileSync(new URL("../../internal/kernel/browserdoc/browser.js", import.meta.url))).digest("base64");
export const staticViewCSP = `default-src 'none'; script-src 'sha256-${staticScriptDigest}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
const cspBySecurityProfile = Object.freeze({
  workspace: "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "static-view": staticViewCSP,
});

export function admittedWorkspaceURL(baseURL) {
  if (typeof baseURL !== "string") throw new Error("Workspace base URL is unavailable");
  const url = new URL(baseURL);
  if (
    url.protocol !== "http:"
    || url.hostname !== "127.0.0.1"
    || url.port === ""
    || url.username !== ""
    || url.password !== ""
    || url.pathname !== "/"
    || url.search !== ""
    || url.hash !== ""
  ) throw new Error("Workspace base URL is outside the admitted local origin");
  return url.href;
}

export function isWorkspaceNavigationResponse(candidate, workspaceURL, mainFrame) {
  const request = candidate.request();
  return candidate.url() === workspaceURL
    && request.isNavigationRequest()
    && request.frame() === mainFrame;
}

export async function navigateWorkspace(page, workspaceURL, trigger, responseError, heading = "browser.fixture.workspace", securityProfile = "workspace") {
  const expectedCSP = cspBySecurityProfile[securityProfile];
  if (!expectedCSP) throw new Error("Unsupported workspace security profile");
  const controller = new AbortController();
  const observationsComplete = new Error("Workspace navigation observations are complete");
  const documents = new Set();
  const observationErrors = new Set();
  const retainDocument = (handle) => { documents.add(handle); return handle; };
  const settle = (promise) => promise.catch((error) => {
    if (error?.cause !== observationsComplete) observationErrors.add(error);
  });
  const mainFrame = page.mainFrame();
  const documentMarker = `proofkitNavigationMarker_${randomUUID()}`;
  await page.evaluate((marker) => { Object.defineProperty(document, marker, {value: true}); }, documentMarker);
  const navigationRequests = [];
  const navigationResponses = [];
  let downloadObserved = false;
  const recordNavigationRequest = (request) => {
    if (request.isNavigationRequest() && request.frame() === mainFrame) navigationRequests.push(request);
  };
  const recordDownload = () => { downloadObserved = true; };
  const recordNavigationResponse = (response) => {
    const request = response.request();
    if (request.isNavigationRequest() && request.frame() === mainFrame) navigationResponses.push(response);
  };
  page.on("request", recordNavigationRequest);
  page.on("response", recordNavigationResponse);
  page.on("download", recordDownload);
  let observing = true;
  const stopObserving = () => {
    if (!observing) return;
    observing = false;
    page.off("request", recordNavigationRequest);
    page.off("response", recordNavigationResponse);
    page.off("download", recordDownload);
  };
  const responsePromise = page.waitForResponse(
    (candidate) => isWorkspaceNavigationResponse(candidate, workspaceURL, mainFrame),
    {signal: controller.signal},
  );
  const navigationPromise = page.waitForEvent("framenavigated", {
    predicate: (frame) => frame === mainFrame && frame.url() === workspaceURL,
    signal: controller.signal,
  });
  const documentPromise = page.waitForFunction(({marker, target}) => {
    return !Object.hasOwn(document, marker) && document.location.href === target
      && document.readyState !== "loading" ? document : false;
  }, {marker: documentMarker, target: workspaceURL}, {signal: controller.signal});
  const eventDocument = navigationPromise.then(() => page.evaluateHandle(() => document)).then(retainDocument);
  const readyDocument = documentPromise.then(retainDocument);
  const settled = [responsePromise, navigationPromise, documentPromise, eventDocument, readyDocument].map(settle);
  let failed = false;
  let failure;
  const cleanupErrors = [];
  try {
    const token = await trigger(workspaceNavigationToken);
    if (token !== workspaceNavigationToken) {
      throw new Error("Workspace navigation trigger token is invalid");
    }
    const response = await responsePromise;
    if (!response.ok()) throw new Error(responseError);
    const witness = await Promise.race([eventDocument, readyDocument]);
    await mainFrame.waitForLoadState("domcontentloaded");
    await expect(
      page.getByRole("heading", {name: heading, exact: true}),
    ).toBeVisible();
    controller.abort(observationsComplete);
    await Promise.all(settled);
    if (observationErrors.size) throw observationErrors.values().next().value;
    let terminal;
    try {
      terminal = await page.evaluate(({marker, witness}) => ({
        sameDocument: witness === document,
        oldDocumentRetained: Object.hasOwn(document, marker),
        url: document.location.href,
        ready: document.readyState !== "loading",
      }), {marker: documentMarker, witness});
    } catch (cause) {
      throw new Error(responseError, {cause});
    }
    const headers = response.headers();
    const disposition = headers["content-disposition"]?.split(";", 1)[0].trim().toLowerCase();
    // A provisional request may be restarted without a response. It cannot
    // certify a document, nor may any later navigation borrow this response.
    if (
      !terminal.sameDocument || terminal.oldDocumentRetained || !terminal.ready
      || downloadObserved || disposition === "attachment"
      || navigationRequests.at(-1) !== response.request()
      || navigationRequests.some((request) => request.url() !== workspaceURL)
      || navigationResponses.length !== 1 || navigationResponses[0] !== response
      || terminal.url !== workspaceURL
      || headers["content-security-policy"] !== expectedCSP
      || headers["x-content-type-options"] !== "nosniff"
    ) {
      throw new Error(responseError);
    }
    // Close the certified observation interval before asynchronous handle cleanup.
    stopObserving();
  } catch (error) {
    failed = true;
    failure = error;
  } finally {
    controller.abort(observationsComplete);
    await Promise.all(settled);
    stopObserving();
    for (const handle of documents) {
      try { await handle.dispose(); }
      catch (error) { cleanupErrors.push(error); }
    }
  }
  if (cleanupErrors.length) throw new AggregateError(failed ? [failure, ...cleanupErrors] : cleanupErrors, "Workspace navigation cleanup failed", {cause: failure});
  if (failed) throw failure;
}

export async function openWorkspace(page, baseURL, heading, securityProfile = "workspace") {
  const workspaceURL = admittedWorkspaceURL(baseURL);
  await navigateWorkspace(
    page,
    workspaceURL,
    (token) => page.evaluate(({target, value}) => {
      window.setTimeout(() => window.location.assign(target), 0);
      return value;
    }, {target: workspaceURL, value: token}),
    "Workspace navigation did not return a successful response",
    heading,
    securityProfile,
  );
}

export async function reloadWorkspace(page, baseURL) {
  const workspaceURL = admittedWorkspaceURL(baseURL);
  await navigateWorkspace(
    page,
    workspaceURL,
    (token) => page.evaluate((value) => {
      window.setTimeout(() => window.location.reload(), 0);
      return value;
    }, token),
    "Workspace reload did not return a successful response",
  );
}
