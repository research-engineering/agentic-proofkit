// @ts-check

import {icon} from "./workspace-icons.js";

/** @param {HTMLElement} container @param {any} projection @param {(requirement: any, opener: HTMLButtonElement) => void} ask */
export function renderCoveragePage(container, projection, ask) {
  const summary = document.createElement("p");
  summary.className = "page-summary";
  summary.dataset.coverageSummary = "";
  summary.textContent = `${projection.matchingReportedRequirementCount} reported; ${projection.matchingNotReportedRequirementCount} not reported in ${projection.matchingRequirementCount} matching requirements. Mode: ${projection.proofMode}.`;
  container.append(summary);
  const list = document.createElement("ul");
  list.className = "coverage-matrix";
  list.setAttribute("aria-label", "Requirement coverage");
  for (const requirement of projection.requirements) {
    const row = requirement.coverage;
    const item = document.createElement("li");
    const article = document.createElement("article");
    article.className = "coverage-record";
    article.dataset.requirementId = requirement.requirementId;
    const identity = document.createElement("div");
    const title = document.createElement("h3");
    title.className = "caller-text";
    title.textContent = requirement.requirementId;
    const invariant = document.createElement("p");
    invariant.className = "caller-text";
    invariant.dataset.anchorId = requirement.anchor.anchorId;
    invariant.textContent = requirement.invariant;
    identity.append(title, invariant);
    const state = document.createElement("dl");
    state.className = "coverage-state";
    addField(state, "Coverage", row === null ? "Not reported" : row.coverageState);
    if (row !== null) {
      addField(state, "Evidence class", row.evidenceClass);
      addField(state, "Claim", row.claimLevel);
      addField(state, "Lifecycle", row.lifecycleState);
      addField(state, "Scenarios", String(row.scenarioCount));
      addField(state, "Tests", String(row.tests.length));
      addField(state, projection.proofMode === "compact" ? "Declared routes" : "Witness references", String(projection.proofMode === "compact" ? row.declaredWitnessRoutes.length : row.witnessRefs.length));
    }
    const actions = document.createElement("div");
    actions.className = "coverage-actions";
    const question = document.createElement("button");
    question.type = "button";
    question.dataset.protectedRequest = "";
    question.dataset.evidenceQuestion = "";
    question.append(icon("message-square"), document.createTextNode("Ask about evidence"));
    question.addEventListener("click", () => { if (!question.disabled) ask(requirement, question); });
    actions.append(question);
    const details = document.createElement("details");
    details.className = "coverage-details";
    const label = document.createElement("summary");
    label.textContent = "Declared evidence and boundaries";
    details.append(label);
    details.addEventListener("toggle", () => {
      if (!details.open || details.querySelector("[data-coverage-detail]")) return;
      const body = document.createElement("div");
      body.dataset.coverageDetail = "";
      const ownership = document.createElement("p");
      ownership.className = "caller-text";
      ownership.textContent = `Owner: ${requirement.ownerId}.`;
      body.append(ownership);
      if (row !== null) {
        const fields = document.createElement("dl");
        for (const [name, values] of [["Commands", row.commandIds], ["Environments", row.environmentClasses], ["Verify commands", row.verifyCommands], ["Failures", row.failures]]) addField(fields, name, values.length === 0 ? "None reported" : values.join("\n"));
        body.append(fields);
        if (projection.proofMode === "structured") {
          const proof = document.createElement("p");
          proof.textContent = `Proof state: ${row.proofState}.`;
          body.append(proof);
        }
        for (const [name, values] of [["Scenarios", row.scenarios], ["Tests", row.tests], [projection.proofMode === "compact" ? "Declared witness routes" : "Witness references", projection.proofMode === "compact" ? row.declaredWitnessRoutes : row.witnessRefs]]) {
          const group = document.createElement("details");
          const summary = document.createElement("summary");
          summary.textContent = `${name} (${values.length})`;
          const records = document.createElement("pre");
          // Secondary owner records retain nested oracle and falsifier fields.
          records.textContent = JSON.stringify(values, null, 2);
          group.append(summary, records);
          body.append(group);
        }
      }
      const boundaries = document.createElement("ul");
      for (const text of [...requirement.sourceNonClaims, ...requirement.nonClaims, ...(row?.nonClaims ?? [])]) {
        const entry = document.createElement("li");
        entry.className = "caller-text";
        entry.textContent = text;
        boundaries.append(entry);
      }
      body.append(boundaries);
      details.append(body);
    });
    article.append(identity, state, actions, details);
    item.append(article);
    list.append(item);
  }
  if (projection.requirements.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "No requirements matched the admitted query.";
    container.append(empty);
  }
  container.append(list);
}

/** @param {HTMLDListElement} list @param {string} label @param {string} text */
function addField(list, label, text) {
  const term = document.createElement("dt");
  term.textContent = label;
  const value = document.createElement("dd");
  value.className = "caller-text";
  value.textContent = text;
  list.append(term, value);
}
