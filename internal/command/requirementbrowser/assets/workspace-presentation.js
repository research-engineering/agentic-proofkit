// @ts-check

/** @param {string} text @param {"passed" | "failed" | "blocked" | "warning" | "info"} status */
export function statusBadge(text, status) {
  const badge = document.createElement("span");
  badge.className = "status-badge";
  badge.dataset.status = status;
  badge.textContent = text;
  return badge;
}
