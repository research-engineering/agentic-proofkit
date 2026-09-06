// @ts-check

import {icon} from "./workspace-icons.js";

/** @param {any} packet @param {string} requirementId */
export function resolveHandoffRequirement(packet, requirementId) {
  const sources = packet?.context?.projections?.requirementSources;
  const matches = Array.isArray(sources) ? sources.flatMap(source =>
    Array.isArray(source.requirements) ? source.requirements.filter((/** @type {any} */ requirement) => requirement.requirementId === requirementId) : []) : [];
  return {state: matches.length === 1 ? "found" : matches.length === 0 ? "unavailable" : "ambiguous", requirement: matches.length === 1 ? matches[0] : null};
}

/** @param {HTMLElement} preview @param {HTMLElement} carrier @param {HTMLElement} status */
export function initializeHandoffPreview(preview, carrier, status) {
  let generation = 0;
  /** @type {Set<string>} */
  const urls = new Set();

  function clear() {
    generation++;
    preview.replaceChildren();
    carrier.replaceChildren();
    for (const url of urls) URL.revokeObjectURL(url);
    urls.clear();
  }

  /** @param {string} text @param {any} packet */
  function show(text, packet) {
    clear();
    const currentGeneration = generation;
    const current = () => generation === currentGeneration && preview.isConnected;
    carrier.textContent = text;
    const controls = document.createElement("div");
    controls.className = "handoff-export-controls";
    const copy = document.createElement("button");
    copy.type = "button";
    copy.append(icon("copy"), document.createTextNode("Copy JSON"));
    copy.addEventListener("click", async () => {
      if (!current() || copy.disabled) return;
      copy.disabled = true;
      try {
        if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
        await navigator.clipboard.writeText(text);
        if (current()) status.textContent = "Exact handoff JSON copied.";
      } catch {
        if (current()) {
          status.textContent = "Clipboard unavailable. Exact JSON remains available below.";
          const disclosure = carrier.closest("details");
          if (disclosure) disclosure.open = true;
        }
      } finally {
        if (current()) copy.disabled = false;
      }
    });
    const download = document.createElement("button");
    download.type = "button";
    download.append(icon("download"), document.createTextNode("Download JSON"));
    download.addEventListener("click", () => {
      if (!current()) return;
      const anchor = document.createElement("a");
      let url = "";
      try {
        url = URL.createObjectURL(new Blob([text], {type: "application/json;charset=utf-8"}));
        urls.add(url);
        anchor.href = url;
        anchor.download = "proofkit-question.json";
        anchor.hidden = true;
        document.body.append(anchor);
        anchor.click();
      } catch {
        if (current()) {
          status.textContent = "Download unavailable. Exact JSON remains available below.";
          const disclosure = carrier.closest("details");
          if (disclosure) disclosure.open = true;
        }
      } finally {
        anchor.remove();
        // Release after the explicit activation's default action has run.
        if (url) setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 0);
      }
    });
    controls.append(copy, download);
    preview.append(controls);
    for (const annotation of packet.annotations ?? []) {
      const article = document.createElement("article");
      const heading = document.createElement("h4");
      heading.className = "caller-text";
      heading.textContent = annotation.anchor.requirementId;
      const question = document.createElement("p");
      question.className = "caller-text";
      question.textContent = annotation.question;
      const quote = document.createElement("blockquote");
      quote.className = "caller-text";
      quote.textContent = annotation.exactQuote;
      const coordinates = document.createElement("p");
      coordinates.textContent = `Code points ${annotation.startCodePoint}-${annotation.endCodePoint}`;
      const details = document.createElement("details");
      const label = document.createElement("summary");
      label.textContent = "Included requirement and source";
      details.append(label);
      details.addEventListener("toggle", () => {
        if (!details.open || details.querySelector("[data-handoff-detail]")) return;
        const resolved = resolveHandoffRequirement(packet, annotation.anchor.requirementId);
        const invariant = document.createElement("p");
        invariant.dataset.handoffDetail = resolved.state;
        invariant.className = "caller-text";
        invariant.textContent = resolved.state === "found" ? resolved.requirement.invariant : `Requirement detail ${resolved.state} in this packet.`;
        const identity = document.createElement("p");
        identity.className = "caller-text";
        identity.textContent = `${annotation.anchor.jsonPointer}\n${annotation.anchor.sourceDigest}`;
        details.append(invariant, identity);
      });
      article.append(heading, question, quote, coordinates, details);
      preview.append(article);
    }
    const boundary = document.createElement("details");
    const label = document.createElement("summary");
    label.textContent = "Packet identity and authority";
    const identity = document.createElement("p");
    identity.className = "caller-text";
    identity.textContent = `${packet.handoffKind}; ${packet.instructionAuthority}; source text: ${packet.sourceTextAuthority}.`;
    const refs = document.createElement("p");
    refs.className = "caller-text";
    refs.textContent = (packet.snapshotRefs ?? []).map((/** @type {any} */ ref) => `${ref.role}: ${ref.snapshotId}`).join("\n");
    const nonClaims = document.createElement("ul");
    for (const text of packet.nonClaims ?? []) {
      const item = document.createElement("li");
      item.textContent = text;
      nonClaims.append(item);
    }
    boundary.append(label, identity, refs, nonClaims);
    preview.append(boundary);
  }
  return {clear, show};
}
