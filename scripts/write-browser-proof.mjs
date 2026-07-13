import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {writeFileSync} from "node:fs";

import {executeBrowserProof} from "./browser-proof-execution.mjs";
import {isSafeRepoPath, loadBrowserProofInputResolution} from "./browser-proof-inputs.mjs";

const testCommand = ["node_modules/@playwright/test/cli.js", "test"];
const resolution = loadBrowserProofInputResolution();
const inputPaths = resolution.inputPaths;
const runDirectory = requiredSafePath("PROOFKIT_BROWSER_RUN_DIRECTORY");
const proofCandidatePath = requiredSafePath("PROOFKIT_BROWSER_PROOF_CANDIDATE_PATH");
if (proofCandidatePath !== `${runDirectory}/browser-runtime-proof.candidate.json`) {
  throw new Error("browser proof candidate path must belong to the admitted run directory");
}
const execution = await executeBrowserProof({
  environment: process.env,
  execFile: execFileSync,
  inputPaths,
  nodeExecutable: process.execPath,
  resolution,
  runDirectory,
  spawnProcess: spawnSync,
  testCommand,
});
const {assets, projects, testResult} = execution;
const inputResolution = {serverTarget: resolution.serverTarget, writerPath: resolution.writerPath};
const inputDigest = createHash("sha256").update(JSON.stringify({assets, inputResolution})).digest("hex");
const engines = projects.map(({browserName, browserVersion}) => ({name: browserName, version: browserVersion}));
const sourceRevision = execFileSync("git", ["rev-parse", "HEAD"], {encoding: "utf8"}).trim();
const sourceTreeState = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {encoding: "utf8"}).trim() === "" ? "clean" : "dirty";
const record = {
  assets,
  command: {argv: testCommand, exitCode: testResult.status, inputMode: "materialized_snapshot", runner: "node"},
  engines,
  inputDigest: `sha256:${inputDigest}`,
  inputResolution,
  nonClaims: [
    "This record proves only that the listed content-bound Playwright tests passed in each recorded project before record creation.",
    "Playwright WebKit is not branded Safari compatibility proof.",
    "This record does not prove registry publication, rollout, or production readiness.",
    "A dirty-tree record is content-bound only to its listed assets; sourceRevision is contextual.",
    "This record does not independently authenticate or sandbox the same-user proof runner, external toolchain packages, or browser binaries.",
  ],
  projects,
  proofKind: "proofkit.browser-runtime-proof",
  schemaVersion: 2,
  sourceRevision,
  sourceTreeState,
  state: "passed",
};
writeFileSync(proofCandidatePath, `${JSON.stringify(record, null, 2)}\n`, {flag: "wx", mode: 0o600});

function requiredSafePath(name) {
  const value = process.env[name];
  if (!value || !isSafeRepoPath(value)) throw new Error(`${name} must be a safe repository-relative path`);
  return value;
}
