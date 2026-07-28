import axeMin from "axe-core/axe.min.js";

export const axeDistributionSource = axeMin.source;
export const axeDistributionVersion = axeMin.version;
export const axeConfigureOptions = Object.freeze({
  allowedOrigins: Object.freeze(["<same_origin>"]),
  branding: Object.freeze({application: "playwright"}),
});
export const axeRunOptions = Object.freeze({
  rules: Object.freeze({
    "target-size": Object.freeze({enabled: true}),
  }),
});
const attemptedContexts = new WeakSet();
const initializedContexts = new WeakSet();
const attemptedPages = new WeakSet();
const completedPages = new WeakSet();

export async function initializeAxe(page) {
  const context = page.context();
  if (attemptedContexts.has(context)) {
    throw new Error("axe was already initialized for this browser context");
  }
  attemptedContexts.add(context);
  try {
    await context.addInitScript({content: axeDistributionSource});
  } catch (error) {
    attemptedContexts.delete(context);
    throw error;
  }
  initializedContexts.add(context);
}

export async function analyzeAxe(page) {
  if (attemptedPages.has(page)) {
    throw new Error("axe already analyzed this page");
  }
  attemptedPages.add(page);
  const frames = page.frames();
  if (frames.length !== 1 || frames[0] !== page.mainFrame()) {
    throw new Error("axe analysis requires exactly the main frame");
  }
  const result = await page.evaluate(
    async ({configureOptions, expectedVersion, runOptions}) => {
      const axe = globalThis.axe;
      if (axe?.version !== expectedVersion) {
        throw new Error("the pinned axe distribution was not initialized");
      }
      if (typeof axe.configure !== "function" || typeof axe.run !== "function") {
        throw new Error("the pinned axe distribution is incomplete");
      }
      axe.configure(configureOptions);
      return axe.run(globalThis.document, runOptions);
    },
    {
      configureOptions: axeConfigureOptions,
      expectedVersion: axeDistributionVersion,
      runOptions: axeRunOptions,
    },
  );
  if (
    result?.testEngine?.name !== "axe-core" ||
    result.testEngine.version !== axeDistributionVersion
  ) {
    throw new Error("axe returned an unexpected test engine");
  }
  completedPages.add(page);
  return result;
}

export function assertAxeTestComplete(page) {
  if (!initializedContexts.has(page.context()) || !completedPages.has(page)) {
    throw new Error("axe test did not initialize and analyze exactly once");
  }
}
