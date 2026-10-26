import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {chmodSync, constants, copyFileSync, existsSync, readdirSync, rmSync, writeFileSync} from "node:fs";
import {join, resolve} from "node:path";

import {captureInventory} from "../tests/visual/capture-inventory.mjs";
import {comparedEnvironmentFields, environmentDivergence, observeEnvironment} from "../tests/visual/environment-probe.mjs";
import {executeBrowserProof} from "./browser-proof-execution.mjs";
import {isSafeRepoPath, loadBrowserProofInputResolution, readBrowserProofFile, snapshotInputAssets} from "./browser-proof-inputs.mjs";
import {runDiagnosticEntrypoint} from "./diagnostic.mjs";
import {decodeUTF8Strict, stableJSONStringify} from "./stable-json.mjs";

const manifestPath = "scripts/browser-visual-proof-inputs.v1.json";
const testRoot = "tests/visual";
const testCommand = ["node_modules/@playwright/test/cli.js", "test", "--config", "playwright.visual.config.mjs"];

await runDiagnosticEntrypoint(async () => {
  const resolution = loadBrowserProofInputResolution();
  const inputPaths = resolution.inputPaths;
  const runDirectory = requiredSafePath("PROOFKIT_BROWSER_RUN_DIRECTORY");
  const proofCandidatePath = requiredSafePath("PROOFKIT_BROWSER_PROOF_CANDIDATE_PATH");
  if (proofCandidatePath !== `${runDirectory}/browser-visual-proof.candidate.json`) {
    throw new Error("browser visual proof candidate path must belong to the admitted run directory");
  }
  const environment = JSON.parse(decodeUTF8Strict(readBrowserProofFile(`${testRoot}/environment.json`).content, "visual environment"));
  const environmentId = `sha256:${createHash("sha256").update(stableJSONStringify(environment)).digest("hex")}`;
  const referencesBytes = readBrowserProofFile(`${testRoot}/references.json`).content;
  const references = JSON.parse(decodeUTF8Strict(referencesBytes, "visual references"));
  // The font configuration is copied into the run directory and set before the
  // environment is observed and recorded and before any browser launches, so
  // the hashed bytes are the bytes that fc-match and every browser read; the
  // working-tree file is never read again.
  const fontConfigPath = resolve(runDirectory, "fonts.conf");
  copyFileSync(`${testRoot}/fonts.conf`, fontConfigPath, constants.COPYFILE_EXCL);
  chmodSync(fontConfigPath, 0o444);
  process.env.FONTCONFIG_FILE = fontConfigPath;
  const observedEnvironment = observeEnvironment();
  const divergentFields = environmentDivergence(environment.observed, observedEnvironment);
  const observedRecord = {
    ...Object.fromEntries(["cpu", ...comparedEnvironmentFields].map((field) => [field, observedEnvironment[field]])),
    divergentFields,
  };
  writeFileSync(join(runDirectory, "observed-environment.json"), `${JSON.stringify(observedRecord, null, 2)}\n`, {flag: "wx", mode: 0o644});
  const {cpu} = observedEnvironment;
  process.stdout.write(`browser visual environment: cpu vendor=${cpu.vendor} model=${cpu.model} features=${cpu.features}; divergent fields: ${divergentFields.length === 0 ? "none" : divergentFields.join(", ")}\n`);
  let assets;
  let command = null;
  let engines = [];
  let projects = [];
  if (divergentFields.length === 0) {
    let execution;
    try {
      execution = await executeBrowserProof({
        admissionArguments: ["--manifest", manifestPath],
        environment: process.env,
        execFile: execFileSync,
        inputPaths,
        nodeExecutable: process.execPath,
        resolution,
        runDirectory,
        spawnProcess: spawnSync,
        testCommand,
      });
    } finally {
      // Passing or failing, the run keeps its captures and a candidate
      // inventory derived from them for review and owner admission.
      writeCandidateInventory(runDirectory, environmentId);
    }
    assertNoUnlistedTestFiles(execution.sourceDirectory, inputPaths);
    for (const generated of [execution.sourceDirectory, join(runDirectory, "server"), join(runDirectory, "visual-fixture-server")]) {
      rmSync(generated, {force: true, recursive: true});
    }
    ({assets, projects} = execution);
    command = {argv: testCommand, exitCode: execution.testResult.status, inputMode: "materialized_snapshot", runner: "node"};
    engines = projects.map(({browserName, browserVersion}) => ({name: browserName, version: browserVersion}));
  } else {
    assets = snapshotInputAssets(inputPaths);
  }
  const inputResolution = {serverTarget: resolution.serverTarget, writerPath: resolution.writerPath};
  const inputDigest = createHash("sha256").update(stableJSONStringify({assets, inputResolution})).digest("hex");
  const sourceRevision = decodeUTF8Strict(execFileSync("git", ["rev-parse", "HEAD"]), "git source revision output").trim();
  const sourceTreeState = decodeUTF8Strict(
    execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"]),
    "git source tree status output",
  ).trim() === "" ? "clean" : "dirty";
  const record = {
    assets,
    command,
    divergentFields,
    engines,
    inputDigest: `sha256:${inputDigest}`,
    inputResolution,
    nonClaims: [
      "A passed record proves only that every listed reference view produced, in two byte-equal captures, its admitted canonical RGBA digest and dimensions in the recorded reference environment before record creation.",
      "Only the first 2400 CSS pixels of each view are compared; content below that height is not covered by a reference.",
      "An unverified record makes no pixel claim; it lists the compared environment fields that differ from the recorded reference environment.",
      "The CPU vendor, model and features are recorded but are not part of the compared environment identity; pixel identity is calibrated only on Apple M1 (implementer 0x61) and Arm Neoverse N2 (implementer 0x41, part 0xd49).",
      "Admitted images are not stored in the repository; they are reproducible from the admitting commit in the recorded environment on a calibrated CPU model while the pinned image and the pinned toolchain and dependency downloads remain available, and an uploaded capture gallery is derived, retention-limited evidence.",
      "This record does not identify who reviewed or admitted a reference.",
      "Playwright WebKit is not branded Safari compatibility proof.",
      "A dirty-tree record is content-bound only to its listed assets; sourceRevision is contextual.",
      "This record does not independently authenticate or sandbox the same-user proof runner, the container image beyond its observed tuple, external toolchain packages, or browser binaries.",
    ],
    observedEnvironment: Object.fromEntries(["cpu", ...comparedEnvironmentFields].map((field) => [field, observedEnvironment[field]])),
    projects,
    proofKind: "proofkit.browser-visual-proof",
    referenceEnvironment: {
      environmentId: references.environmentId,
      referenceCount: Array.isArray(references.references) ? references.references.length : 0,
      referencesDigest: `sha256:${createHash("sha256").update(referencesBytes).digest("hex")}`,
    },
    schemaVersion: 1,
    sourceRevision,
    sourceTreeState,
    state: divergentFields.length === 0 ? "passed" : "unverified",
  };
  writeFileSync(proofCandidatePath, `${JSON.stringify(record, null, 2)}\n`, {flag: "wx", mode: 0o600});
});

function writeCandidateInventory(runDirectory, environmentId) {
  const captures = join(runDirectory, "captures");
  const entries = existsSync(captures) ? captureInventory(captures) : [];
  const candidate = {clipHeight: 2400, environmentId, kind: "proofkit.browser-visual-references", references: entries, schemaVersion: 1};
  writeFileSync(join(runDirectory, "candidate-references.json"), `${JSON.stringify(candidate, null, 2)}\n`, {flag: "wx", mode: 0o644});
}

// The materialized test directory must hold exactly its content-bound input
// files after the run: no capture, reference or other file may appear in it.
function assertNoUnlistedTestFiles(sourceDirectory, inputPaths) {
  const listed = new Set(inputPaths.filter((path) => path.startsWith(`${testRoot}/`)));
  const present = [];
  const walk = (relativeDirectory) => {
    for (const entry of readdirSync(join(sourceDirectory, relativeDirectory), {withFileTypes: true})) {
      const path = `${relativeDirectory}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else present.push(path);
    }
  };
  walk(testRoot);
  const unlisted = present.filter((path) => !listed.has(path));
  if (unlisted.length > 0 || present.length !== listed.size) {
    throw new Error("the visual test directory gained or lost files during the run");
  }
}

function requiredSafePath(name) {
  const value = process.env[name];
  if (!value || !isSafeRepoPath(value)) throw new Error(`${name} must be a safe repository-relative path`);
  return value;
}
