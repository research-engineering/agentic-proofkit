import {expect} from "@playwright/test";

const workspaceNavigationToken = "proofkit.workspace-navigation.scheduled";

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

export async function navigateWorkspace(page, workspaceURL, trigger, responseError) {
  const controller = new AbortController();
  const mainFrame = page.mainFrame();
  const responsePromise = page.waitForResponse(
    (candidate) => isWorkspaceNavigationResponse(candidate, workspaceURL, mainFrame),
    {signal: controller.signal},
  );
  try {
    const token = await trigger(workspaceNavigationToken);
    if (token !== workspaceNavigationToken) {
      throw new Error("Workspace navigation trigger token is invalid");
    }
    const response = await responsePromise;
    if (!response.ok()) throw new Error(responseError);
    await expect(
      page.getByRole("heading", {name: "browser.fixture.workspace", exact: true}),
    ).toBeVisible();
  } catch (error) {
    controller.abort();
    await responsePromise.catch(() => undefined);
    throw error;
  }
}

export async function openWorkspace(page, baseURL) {
  const workspaceURL = admittedWorkspaceURL(baseURL);
  await navigateWorkspace(
    page,
    workspaceURL,
    (token) => page.evaluate(({target, value}) => {
      window.setTimeout(() => window.location.assign(target), 0);
      return value;
    }, {target: workspaceURL, value: token}),
    "Workspace navigation did not return a successful response",
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
