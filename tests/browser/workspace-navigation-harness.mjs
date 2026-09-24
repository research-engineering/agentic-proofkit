import {expect} from "@playwright/test";
import {randomUUID} from "node:crypto";

const workspaceNavigationToken = "proofkit.workspace-navigation.scheduled";
const workspaceCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

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

export async function navigateWorkspace(page, workspaceURL, trigger, responseError, heading = "browser.fixture.workspace") {
  const controller = new AbortController();
  const mainFrame = page.mainFrame();
  const documentMarker = `proofkitNavigationMarker_${randomUUID()}`;
  await page.evaluate((marker) => { Object.defineProperty(document, marker, {value: true}); }, documentMarker);
  const navigationRequests = [];
  let downloadObserved = false;
  const recordNavigationRequest = (request) => {
    if (request.isNavigationRequest() && request.frame() === mainFrame) navigationRequests.push(request);
  };
  const recordDownload = () => { downloadObserved = true; };
  page.on("request", recordNavigationRequest);
  page.on("download", recordDownload);
  const responsePromise = page.waitForResponse(
    (candidate) => isWorkspaceNavigationResponse(candidate, workspaceURL, mainFrame),
    {signal: controller.signal},
  );
  const navigationPromise = page.waitForEvent("framenavigated", {
    predicate: (frame) => frame === mainFrame && frame.url() === workspaceURL,
    signal: controller.signal,
  });
  const responseSettled = responsePromise.catch(() => undefined);
  const navigationSettled = navigationPromise.catch(() => undefined);
  try {
    const token = await trigger(workspaceNavigationToken);
    if (token !== workspaceNavigationToken) {
      throw new Error("Workspace navigation trigger token is invalid");
    }
    const response = await responsePromise;
    if (!response.ok()) throw new Error(responseError);
    await navigationPromise;
    await mainFrame.waitForLoadState("domcontentloaded");
    await expect(
      page.getByRole("heading", {name: heading, exact: true}),
    ).toBeVisible();
    const oldDocumentRetained = await page.evaluate((marker) => Object.hasOwn(document, marker), documentMarker);
    const headers = response.headers();
    const disposition = headers["content-disposition"]?.split(";", 1)[0].trim().toLowerCase();
    if (oldDocumentRetained || downloadObserved || disposition === "attachment" || navigationRequests.length !== 1 || navigationRequests[0] !== response.request() || page.url() !== workspaceURL || headers["content-security-policy"] !== workspaceCSP || headers["x-content-type-options"] !== "nosniff") {
      throw new Error(responseError);
    }
  } catch (error) {
    controller.abort();
    await Promise.all([responseSettled, navigationSettled]);
    throw error;
  } finally {
    page.off("request", recordNavigationRequest);
    page.off("download", recordDownload);
  }
}

export async function openWorkspace(page, baseURL, heading) {
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
