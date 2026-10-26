import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {chmodSync, constants, copyFileSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {join, resolve} from "node:path";

import {comparedEnvironmentFields, environmentDivergence, observeEnvironment} from "../tests/visual/environment-probe.mjs";
import {executeBrowserProof} from "./browser-proof-execution.mjs";
import {isSafeRepoPath, loadBrowserProofInputResolution} from "./browser-proof-inputs.mjs";
import {runDiagnosticEntrypoint} from "./diagnostic.mjs";
import {decodeUTF8Strict, stableJSONStringify} from "./stable-json.mjs";

// The accessibility-matrix writer of both families. Its family is the one
// whose input manifest is in its content-bound input set.
const families = Object.freeze({
  static: "scripts/browser-matrix-static-proof-inputs.v1.json",
  workspace: "scripts/browser-matrix-workspace-proof-inputs.v1.json",
});
const testCommand = ["node_modules/@playwright/test/cli.js", "test", "--config", "playwright.matrix.config.mjs"];

await runDiagnosticEntrypoint(async () => {
  const resolution = loadBrowserProofInputResolution();
  const inputPaths = resolution.inputPaths;
  const named = Object.entries(families).filter(([, manifest]) => inputPaths.includes(manifest));
  if (named.length !== 1) throw new Error("the browser matrix input set must name exactly one family manifest");
  const [[family, manifestPath]] = named;
  const runDirectory = requiredSafePath("PROOFKIT_BROWSER_RUN_DIRECTORY");
  const proofCandidatePath = requiredSafePath("PROOFKIT_BROWSER_PROOF_CANDIDATE_PATH");
  if (proofCandidatePath !== `${runDirectory}/browser-matrix-${family}-proof.candidate.json`) {
    throw new Error("browser matrix proof candidate path must belong to the admitted run directory");
  }
  const environment = JSON.parse(readFileSync("tests/visual/environment.json", "utf8"));
  const environmentId = `sha256:${createHash("sha256").update(stableJSONStringify(environment)).digest("hex")}`;
  // The recorded font mapping is copied into the run directory and set before
  // the environment is observed and before any browser launches.
  const fontConfigPath = resolve(runDirectory, "fonts.conf");
  copyFileSync("tests/visual/fonts.conf", fontConfigPath, constants.COPYFILE_EXCL);
  chmodSync(fontConfigPath, 0o444);
  process.env.FONTCONFIG_FILE = fontConfigPath;
  const observedEnvironment = observeEnvironment();
  const divergentFields = environmentDivergence(environment.observed, observedEnvironment);
  const {cpu} = observedEnvironment;
  process.stdout.write(`browser matrix ${family}: cpu vendor=${cpu.vendor} model=${cpu.model}; divergent fields: ${divergentFields.length === 0 ? "none" : divergentFields.join(", ")}\n`);
  if (divergentFields.length > 0 && process.env.PROOFKIT_BROWSER_REQUIRE_REFERENCE_ENVIRONMENT === "true") {
    throw new Error(`browser matrix ${family} requires the reference environment; the observed environment differs in ${divergentFields.join(", ")}`);
  }
  const execution = await executeBrowserProof({
    admissionArguments: ["--manifest", manifestPath],
    environment: {...process.env, PROOFKIT_BROWSER_MATRIX_FAMILY: family},
    execFile: execFileSync,
    inputPaths,
    nodeExecutable: process.execPath,
    resolution,
    runDirectory,
    spawnProcess: spawnSync,
    testCommand,
  });
  for (const generated of [execution.sourceDirectory, join(runDirectory, "server"), join(runDirectory, "matrix-fixture-server")]) {
    rmSync(generated, {force: true, recursive: true});
  }
  const {assets, projects, testResult} = execution;
  const inputResolution = {serverTarget: resolution.serverTarget, writerPath: resolution.writerPath};
  const inputDigest = createHash("sha256").update(stableJSONStringify({assets, inputResolution})).digest("hex");
  const sourceRevision = decodeUTF8Strict(execFileSync("git", ["rev-parse", "HEAD"]), "git source revision output").trim();
  const sourceTreeState = decodeUTF8Strict(
    execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"]),
    "git source tree status output",
  ).trim() === "" ? "clean" : "dirty";
  const record = {
    assets,
    command: {argv: testCommand, exitCode: testResult.status, inputMode: "materialized_snapshot", runner: "node"},
    divergentFields,
    engines: projects.map(({browserName, browserVersion}) => ({name: browserName, version: browserVersion})),
    family,
    inputDigest: `sha256:${inputDigest}`,
    inputResolution,
    nonClaims: [
      "A passed record proves only that every expected accessibility-matrix cell, negative control and reader task of its family passed with zero retries in each recorded engine, in the observed environment, before record creation.",
      "A record whose divergentFields is not empty was produced outside the recorded reference environment and claims its outcomes only for the observed environment.",
      "This record does not prove WCAG conformance certification, a human usability study, complete screen-reader interoperability, 400-percent zoom behavior or pixel identity.",
      "Playwright WebKit is not branded Safari compatibility proof.",
      "A dirty-tree record is content-bound only to its listed assets; sourceRevision is contextual.",
      "This record does not independently authenticate or sandbox the same-user proof runner, the container image beyond its observed tuple, external toolchain packages, or browser binaries.",
    ],
    observedEnvironment: Object.fromEntries(["cpu", ...comparedEnvironmentFields].map((field) => [field, observedEnvironment[field]])),
    projects,
    proofKind: "proofkit.browser-matrix-proof",
    referenceEnvironment: {environmentId},
    schemaVersion: 1,
    sourceRevision,
    sourceTreeState,
    state: "passed",
  };
  writeFileSync(proofCandidatePath, `${JSON.stringify(record, null, 2)}\n`, {flag: "wx", mode: 0o600});
});

function requiredSafePath(name) {
  const value = process.env[name];
  if (!value || !isSafeRepoPath(value)) throw new Error(`${name} must be a safe repository-relative path`);
  return value;
}
