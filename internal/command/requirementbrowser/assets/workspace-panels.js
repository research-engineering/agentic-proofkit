// @ts-check

/** @param {() => void} commitSelection */
export function initializePanels(commitSelection) {
  const navigation = document.querySelector("#workspace-navigation");
  const inspector = document.querySelector("#workspace-inspector");
  if (!(navigation instanceof HTMLDialogElement) || !(inspector instanceof HTMLDialogElement)) throw new Error("Missing workspace panels");
  const panels = {navigation, inspector};
  const mobile = window.matchMedia("(max-width: 64rem)");
  /** @type {Map<HTMLDialogElement, HTMLElement>} */
  const openers = new Map();

  /** @param {HTMLElement | undefined} element */
  function visible(element) {
    return element?.isConnected === true && element.getClientRects().length > 0;
  }

  /** @param {HTMLDialogElement} panel @param {boolean} [restoreFocus] */
  function close(panel, restoreFocus = true) {
    if (panel.open) panel.close();
    synchronize();
    if (restoreFocus) focusOpener(panel);
  }

  /** @param {HTMLDialogElement} panel */
  function focusOpener(panel) {
    const opener = openers.get(panel);
    const fallback = document.querySelector("#open-inspector");
    if (visible(opener)) opener?.focus();
    else if (fallback instanceof HTMLElement && visible(fallback)) fallback.focus();
  }

  function synchronize() {
    document.body.dataset.navigationOpen = String(panels.navigation.open);
    document.body.dataset.inspectorOpen = String(panels.inspector.open);
    document.body.dataset.modalOpen = String(mobile.matches && (panels.navigation.open || panels.inspector.open));
    for (const [name, panel] of Object.entries(panels)) {
      document.querySelector(`[data-open-panel="${name}"]`)?.setAttribute("aria-expanded", String(panel.open));
    }
  }

  /** @param {"navigation" | "inspector"} name @param {HTMLElement} opener */
  function open(name, opener) {
    const panel = panels[name];
    if (name === "inspector") commitSelection();
    if (panel.open) {
      close(panel);
      return;
    }
    openers.set(panel, opener);
    if (mobile.matches) {
      for (const other of Object.values(panels)) close(other, false);
      panel.showModal();
    } else {
      panel.show();
    }
    synchronize();
    const initial = panel.querySelector(name === "inspector" ? "#annotation-question" : "#requirement-search");
    if (initial instanceof HTMLElement) initial.focus();
  }

  for (const [name, panel] of Object.entries(panels)) {
    const button = document.querySelector(`[data-open-panel="${name}"]`);
    if (!(button instanceof HTMLButtonElement)) throw new Error("Missing panel opener");
    openers.set(panel, button);
    if (name === "inspector") {
      button.addEventListener("pointerdown", commitSelection);
      button.addEventListener("focus", commitSelection);
    }
    button.addEventListener("click", () => open(/** @type {"navigation" | "inspector"} */ (name), button));
    panel.querySelector("[data-close-panel]")?.addEventListener("click", () => close(panel));
    panel.addEventListener("cancel", (event) => {
      event.preventDefault();
      close(panel);
    });
    panel.addEventListener("close", synchronize);
  }

  function changeLayout() {
    // Closing releases native modal/inert state before any desktop placement.
    const focused = document.activeElement;
    for (const panel of Object.values(panels)) close(panel, false);
    if (!mobile.matches) {
      // Layout is not user activation: show() would acquire native focus.
      panels.navigation.open = true;
      panels.inspector.open = true;
    }
    synchronize();
    if (focused instanceof HTMLElement && visible(focused)) focused.focus();
    else if (focused instanceof HTMLElement) {
      const focusedPanel = Object.values(panels).find(panel => panel.contains(focused));
      if (focusedPanel) focusOpener(focusedPanel);
    }
  }
  mobile.addEventListener("change", changeLayout);
  changeLayout();
  return {closeNavigation: () => { if (mobile.matches) close(navigation); }};
}
