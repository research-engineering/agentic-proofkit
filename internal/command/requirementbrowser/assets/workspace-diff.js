// @ts-check

/** @param {any[]} changes */
export function summarizeDiffPage(changes) {
  const entities = new Set();
  /** @type {Map<string, number>} */
  const classes = new Map();
  let riskChanges = 0;
  let lifecycleChanges = 0;
  for (const change of changes) {
    entities.add(change.entityId);
    classes.set(change.changeClass, (classes.get(change.changeClass) ?? 0) + 1);
    const entityPointer = String(change.entityId).replaceAll("~", "~0").replaceAll("/", "~1");
    if (change.entityKind === "requirement" && change.changeClass === "scalar_changed" && change.jsonPointer === `/requirements/${entityPointer}/riskClass`) riskChanges++;
    if (change.changeClass === "lifecycle_transition") lifecycleChanges++;
  }
  return {
    changeCount: changes.length, entityCount: entities.size, riskChanges, lifecycleChanges,
    byClass: [...classes].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0),
  };
}

/** @param {HTMLElement} container @param {any[]} changes */
export function renderDiffPage(container, changes) {
  const summary = summarizeDiffPage(changes);
  const heading = document.createElement("h3");
  heading.textContent = "Changes on this page";
  const counts = document.createElement("p");
  counts.className = "page-summary";
  counts.dataset.diffSummary = "";
  counts.textContent = `Changes: ${summary.changeCount}; requirements: ${summary.entityCount}; risk changes: ${summary.riskChanges}; lifecycle changes: ${summary.lifecycleChanges}.`;
  const partition = document.createElement("ul");
  partition.className = "diff-class-counts";
  partition.setAttribute("aria-label", "Change classes on this page");
  for (const [kind, count] of summary.byClass) {
    const item = document.createElement("li");
    item.textContent = `${kind}: ${count}`;
    partition.append(item);
  }
  container.append(heading, counts, partition);
  for (const change of changes) {
    const article = document.createElement("article");
    article.dataset.changeId = change.changeId;
    const title = document.createElement("h3");
    title.textContent = `${change.changeClass}: ${change.entityId}`;
    title.className = "caller-text";
    const pointer = document.createElement("p");
    pointer.className = "caller-text";
    pointer.textContent = change.jsonPointer;
    const details = document.createElement("details");
    const label = document.createElement("summary");
    label.textContent = "Before and after";
    details.append(label);
    details.addEventListener("toggle", () => {
      if (!details.open || details.querySelector("pre")) return;
      const identity = document.createElement("p");
      identity.className = "caller-text";
      identity.textContent = `Source digests: ${change.baseSourceDigest ?? "not-recorded"} -> ${change.currentSourceDigest ?? "not-recorded"}`;
      const values = document.createElement("pre");
      values.textContent = `${JSON.stringify(change.before, null, 2)}\n->\n${JSON.stringify(change.after, null, 2)}`;
      details.append(identity, values);
    });
    article.append(title, pointer, details);
    container.append(article);
  }
}
