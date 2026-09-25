(() => {
  const search = /** @type {HTMLInputElement} */ (document.getElementById("proofkit-search"));
  const showIds = /** @type {HTMLInputElement} */ (document.getElementById("proofkit-show-ids"));
  const openDetails = /** @type {HTMLInputElement} */ (document.getElementById("proofkit-open-details"));
  const viewMode = /** @type {HTMLSelectElement | null} */ (document.getElementById("proofkit-view-mode"));
  const count = /** @type {HTMLElement} */ (document.getElementById("proofkit-visible-count"));
  const cards = Array.from(/** @type {NodeListOf<HTMLElement>} */ (document.querySelectorAll("[data-proofkit-card]")));
  const cardGroups = Array.from(/** @type {NodeListOf<HTMLElement>} */ (document.querySelectorAll("[data-proofkit-card-group]")));
  const cardSection = /** @type {HTMLElement | null} */ (document.querySelector("[data-proofkit-card-section]"));
  const tableSection = /** @type {HTMLElement | null} */ (document.querySelector("[data-proofkit-table-section]"));
  const rows = Array.from(/** @type {NodeListOf<HTMLElement>} */ (document.querySelectorAll("[data-proofkit-table-row]")));
  const filters = Array.from(/** @type {NodeListOf<HTMLSelectElement>} */ (document.querySelectorAll("[data-proofkit-filter]")));

  // Static records and queries use the same runtime's lowercase semantics.
  const searchKeys = new Map([...cards, ...rows].map(item => [item, (item.getAttribute("data-search") || "").toLowerCase()]));

  /** @param {HTMLElement} item @param {string} query */
  function matchesFilters(item, query) {
    const matchesSearch = query === "" || (searchKeys.get(item) || "").includes(query);
    const matchesFieldFilters = filters.every(filter => {
      const value = filter.value;
      return value === "" || item.getAttribute("data-filter-" + filter.getAttribute("data-filter-key")) === value;
    });
    return matchesSearch && matchesFieldFilters;
  }

  function applyFilters() {
    const query = (search.value || "").trim().toLowerCase();
    let visible = 0;
    for (const card of cards) {
      const shown = matchesFilters(card, query);
      card.hidden = !shown;
      if (shown) visible += 1;
    }
    for (const row of rows) row.hidden = !matchesFilters(row, query);
    for (const group of cardGroups) {
      const children = /** @type {NodeListOf<HTMLElement>} */ (group.querySelectorAll("[data-proofkit-card]"));
      group.hidden = Array.from(children).every(card => card.hidden);
    }
    const mode = viewMode ? viewMode.value : "cards";
    if (cardSection) cardSection.hidden = mode === "table";
    if (tableSection) tableSection.hidden = mode !== "table";
    document.documentElement.dataset.showIds = showIds.checked ? "true" : "false";
    count.textContent = String(visible);
  }

  function applyDetails() {
    for (const detail of document.querySelectorAll("details")) detail.open = openDetails.checked;
  }

  function installDownloads() {
    for (const button of document.querySelectorAll("[data-proofkit-download]")) {
      button.addEventListener("click", () => {
        const binary = atob(button.getAttribute("data-download-content") || "");
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
        const blob = new Blob([bytes], {type: "application/octet-stream"});
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = button.getAttribute("data-download-file") || "proofkit-rendered-view";
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(link.href);
      });
    }
  }

  search.addEventListener("input", applyFilters);
  showIds.addEventListener("change", applyFilters);
  openDetails.addEventListener("change", applyDetails);
  if (viewMode) viewMode.addEventListener("change", applyFilters);
  for (const filter of filters) filter.addEventListener("change", applyFilters);
  installDownloads();
  applyFilters();
})();
