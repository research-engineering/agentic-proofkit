// @ts-check

import {parseWorkspaceJSON} from "./workspace-json.js";

export class WorkspaceRequestError extends Error {
  /** @param {number} status */
  constructor(status) {
    super("Workspace request failed");
    this.status = status;
  }
}

/** @param {string} path @param {RequestInit} init @returns {Promise<any>} */
export async function fetchWorkspaceJSON(path, init) {
  return (await fetchWorkspaceResponse(path, init)).value;
}

/** @param {string} path @param {RequestInit} init @returns {Promise<{text: string, value: any}>} */
export async function fetchWorkspaceResponse(path, init) {
  /** @type {string} */
  let body;
  try {
    const response = await fetch(path, init);
    if (!response.ok) throw new WorkspaceRequestError(response.status);
    body = await response.text();
  } catch (error) {
    if (init.signal?.aborted || error instanceof WorkspaceRequestError) throw error;
    throw new WorkspaceRequestError(0);
  }
  return {text: body, value: parseWorkspaceJSON(body)};
}

/** @param {unknown} error @param {boolean} optional */
export function workspaceFailure(error, optional = false) {
  const status = error instanceof WorkspaceRequestError ? error.status : -1;
  if (status === 400) return {message: "The query could not be accepted. Check its fields and submit again.", action: "none", lock: false, kind: "correction"};
  if (status === 403) return {message: "Access to this workspace was denied.", action: "none", lock: true, kind: "denied"};
  if (status === 409) return {message: "The workspace snapshot has changed.", action: "reload", lock: true, kind: "stale"};
  if (status === 0 || status === 429 || status >= 500 && status <= 599) return {message: "The workspace could not be reached. Try this request again.", action: "retry", lock: false, kind: "retryable"};
  if (status === 404 && optional) return {message: "This workspace view is unavailable.", action: "none", lock: false, kind: "optional-unavailable"};
  return {message: "The admitted workspace is unavailable.", action: "none", lock: false, kind: "unavailable"};
}
