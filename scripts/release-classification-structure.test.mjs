import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url), release = "release-authority", readiness = "readiness-closeout";
const baseline = JSON.parse(readFileSync(new URL("internal/app/testdata/release-classification-native-observations.json", root)));
assert.equal(baseline.head, "264f256daa4516e41ddf9b6dfcd89dee6580431d");
assert.equal(baseline.tree, "2329c6e31810f9a8b2ec7741bb2ddd5378f1deeb");
assert.equal(baseline.observations.length, 74);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_RELEASE_CLASSIFICATION_CONTRACT || new URL("proofkit/cli-contract.v2.json", root)));
const ajv = new Ajv2020({strict: false, validateFormats: false});
const validators = Object.fromEntries([release, readiness].map(command => [command, Object.fromEntries(["input", "output"].map(direction => {
  const id = `proofkit.${command}.${direction}.v1.json-schema`, record = contract.commands.find(x => x.command === command);
  assert.equal(record[direction + "Contract"].contractId, `proofkit.${command}.${direction}.v1`);
  assert.equal(record[direction + "Contract"].rootDefinitionRef, id);
  const variants = contract.contractDefinitions.find(x => x.definitionId === id).fieldTree.variants;
  return [direction, ajv.compile({oneOf: variants.map(x => x.schema)})];
}))]));
const builtin = {
  [release]: ["Release authority does not publish packages, authenticate registry credentials, execute consumer installs, approve rollout, or prove registry freshness.",
    "Release authority validates caller-owned release-channel declarations only."],
  [readiness]: ["Readiness closeout reports classify caller-owned backlog text only.",
    "Readiness closeout reports do not execute gates, authenticate receipts, publish artifacts, approve merge, or prove deployment readiness.",
    "Readiness closeout reports cannot convert blocked, open, missing, or failed owner rows into passed readiness evidence."],
};
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-release-classification-")); binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off"},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const order = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
const trim = text => text.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
const mergedClaims = (command, values) => [...new Set([...builtin[command], ...values.map(trim)])].sort(order);
function invoke(row) {
  const result = spawnSync(binary, row.argv, {input: row.input, encoding: "utf8", timeout: 10000, maxBuffer: 2 << 20});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return result;
}
function expectedHelp(row) {
  const summaries = contract.commands.find(x => x.command === row.command).inputContract.compatibilitySummary;
  const before = `Input schema summary:\n  schemaVersion=1\n  root-shape-only definition proofkit.${row.command}.input.v1.root-shape; nested fields, types, and cardinalities are non-claims`;
  assert.ok(row.predecessorHelp.includes(before));
  const navigation = row.command === release ? ["01-legacy-registry", "02-source-registry", "03-dry-run-registry"].map((variant, i) =>
    `root fields (${variant}): artifactProof{}, channel, consumerContract{}, nonClaims[], package{}, registryAuthority, releaseId, rollback{}, rolloutClaim, schemaVersion=${i + 1}`)
    : ["root fields: environmentPreconditions[], exactCommand, frontier{}, inputDefinitions[], markdownText, negatedNonClaimPhrases[], nonClaims[], phraseRules[], readinessRowPrefixes[], readinessSections[], reportId, runIdentity"];
  return row.predecessorHelp.replace(before, "Input schema summary:\n  " + [...summaries, ...navigation].join("\n  "));
}
function meanings(command, input, output, exitCode) {
  assert.equal(output.schemaVersion, 1); assert.equal(output.reportKind, `proofkit.${command}`);
  assert.equal(output.reportId, command === release ? input.releaseId : input.reportId);
  assert.equal(output.state, exitCode ? "failed" : "passed");
  assert.deepEqual(output.nonClaims, mergedClaims(command, input.nonClaims));
  if (command === release) {
    assert.deepEqual(output.summary, {channel: input.channel, dependencyPinType: input.consumerContract.dependencyPinType,
      manifestPrivate: input.package.manifestPrivate, packageName: trim(input.package.name), packageVersion: trim(input.package.version),
      registryAuthorityDeclared: input.registryAuthority !== null, rolloutClaim: input.rolloutClaim});
    const proof = output.diagnostics[0].value;
    assert.deepEqual(proof, input.artifactProof);
    assert.deepEqual(output.diagnostics[1].value, {dependencyPinType: input.consumerContract.dependencyPinType,
      inputBinarySmokeOnly: input.consumerContract.binarySmokeOnly, inputLockfileRequired: input.consumerContract.lockfileRequired,
      inputSiblingSourceCheckoutAllowed: input.consumerContract.siblingSourceCheckoutAllowed});
    assert.deepEqual(output.diagnostics[2].value, {artifactPath: trim(input.package.artifactPath),
      packageManagerLockfile: trim(input.package.packageManagerLockfile), packManifestPath: trim(input.package.packManifestPath)});
    assert.deepEqual(output.diagnostics[4].value, Object.fromEntries(Object.entries(input.rollback).map(([key, value]) => [key, trim(value)])));
    if (!exitCode) assert.deepEqual(output.ruleResults, [{diagnostics: [], message: "release authority is explicit and bounded to the selected channel",
      ruleId: "proofkit.release-authority.accepted", status: "passed"}]);
    else output.ruleResults.forEach((rule, i) => {assert.equal(rule.ruleId, `proofkit.release-authority.failure.${String(i + 1).padStart(3, "0")}`);
      assert.equal(rule.status, "failed"); assert.deepEqual(rule.diagnostics, []);});
  } else {
    assert.equal(output.summary.readinessClaim, "classification_honesty_only"); assert.equal(output.summary.runIdentity, input.runIdentity);
    assert.equal(output.ruleResults.length, input.inputDefinitions.length + 3);
    for (const rule of output.ruleResults) {
      assert.equal(rule.diagnostics.find(x => x.key === "exactCommand").value, trim(input.exactCommand));
      assert.deepEqual(rule.diagnostics.find(x => x.key === "environmentPreconditions").value, input.environmentPreconditions.map(trim).sort(order));
      assert.equal(rule.diagnostics.find(x => x.key === "runIdentity").value, input.runIdentity);
    }
  }
}

test("release classifications conserve74predecessor streams and independent public meanings", () => {
  for (const row of baseline.observations) {
    const result = invoke(row); assert.equal(result.status, row.exitCode, row.name);
    assert.equal(hash(result.stderr), row.stderrSHA256, `${row.name}/stderr`);
    assert.equal(hash(result.stdout), row.help ? hash(expectedHelp(row)) : row.stdoutSHA256, `${row.name}/stdout`);
    if (!row.report) continue;
    const input = row.name === "pointer" ? JSON.parse(row.input).payload : JSON.parse(row.input), output = JSON.parse(result.stdout);
    assert.equal(validators[row.command].input(input), true, `${row.command}/${row.name}/input`);
    assert.equal(validators[row.command].output(output), true, `${row.command}/${row.name}/output`);
    meanings(row.command, input, output, row.exitCode);
  }
});

const at = (value, path) => path.reduce((current, key) => current[key], value);
function paths(value, path = [], rows = []) {
  rows.push({path, value});
  if (value && typeof value === "object") for (const [key, child] of Object.entries(value)) paths(child, [...path, Array.isArray(value) ? Number(key) : key], rows);
  return rows;
}
function replace(value, path, replacement) {
  const copy = structuredClone(value); at(copy, path.slice(0, -1))[path.at(-1)] = replacement; return copy;
}
const rawIDs = new Set(["releaseId", "reportId", "runIdentity", "evidenceClass", "ruleId", "binarySmokeProofId", "cliSmokeProofId", "deepImportRejectionProofId", "outsideConsumerInstallProofId", "packageArtifactCommandId", "packDryRunCommandId", "registryPublishDryRunProofId"]);
function optional(command, direction, key) {
  return command === release ? key === "registryPublishDryRunProofId" || (direction === "input" && key === "publishConfigRegistry")
    : direction === "input" && ["forbiddenText", "directClaimPhrases"].includes(key);
}
function nullable(command, direction, path) {
  return command === release && (direction === "input" ? path.join(".") === "registryAuthority" || path.join(".") === "package.publishConfigRegistry" : path.at(-1) === "sourceRepository");
}
test("release classification nested predicates cover optional null and populated rule branches", () => {
  for (const row of baseline.observations.filter(x => x.report && x.name !== "pointer")) {
    const input = JSON.parse(row.input), output = JSON.parse(invoke(row).stdout);
    for (const [direction, specimen] of [["input", input], ["output", output]]) {
      const valid = validators[row.command][direction]; assert.equal(valid(specimen), true);
      for (const {path, value} of paths(specimen)) {
        if (value && !Array.isArray(value) && typeof value === "object") {
          const unknown = structuredClone(specimen); at(unknown, path).foreign = true;
          assert.equal(valid(unknown), false, `${row.command}/${direction}/${path}/unknown`);
          for (const key of Object.keys(value)) {
            const missing = structuredClone(specimen); delete at(missing, path)[key];
            assert.equal(valid(missing), optional(row.command, direction, key), `${row.command}/${direction}/${path}/${key}/missing`);
          }
        }
        if (!path.length) continue;
        assert.equal(valid(replace(specimen, path, null)), nullable(row.command, direction, path), `${row.command}/${direction}/${path}/null`);
        const wrong = typeof value === "string" || value === null ? 0 : "wrong-type";
        assert.equal(valid(replace(specimen, path, wrong)), false, `${row.command}/${direction}/${path}/type`);
        if (typeof value === "string" && !["markdownText", "packageScope"].includes(path.at(-1))) assert.equal(valid(replace(specimen, path, "")), false, `${row.command}/${direction}/${path}/blank`);
        const bounded = rawIDs.has(path.at(-1)) && (direction === "input" || path.at(-1) !== "ruleId");
        if (typeof value === "string" && bounded) {
          assert.equal(valid(replace(specimen, path, "a".repeat(256))), true, `${row.command}/${direction}/${path}/accepted-id-bound`);
          for (const invalid of ["foreign/id", "a".repeat(257)]) assert.equal(valid(replace(specimen, path, invalid)), false, `${row.command}/${direction}/${path}/raw-id-domain`);
        }
        if (typeof value === "number") for (const wrongNumber of [-1, 0.5]) assert.equal(valid(replace(specimen, path, wrongNumber)), false, `${row.command}/${direction}/${path}/integer`);
      }
      if (direction === "output") {
        for (const bad of [[], specimen.diagnostics.slice(1), [...specimen.diagnostics].reverse()]) assert.equal(valid({...specimen, diagnostics: bad}), false);
        assert.equal(valid({...specimen, ruleResults: []}), false, `${row.command}/ruleResults/empty`);
        if (row.command === readiness) assert.equal(valid({...specimen, ruleResults: specimen.ruleResults.slice(0, 2)}), false, "readiness/ruleResults/short");
        for (const claim of builtin[row.command]) assert.equal(valid({...specimen, nonClaims: specimen.nonClaims.filter(x => x !== claim)}), false);
        assert.equal(valid({...specimen, nonClaims: [...specimen.nonClaims, specimen.nonClaims[0]]}), false);
      }
    }
  }
});

test("mixed readiness classifications distinguish caller labels from validation failures", () => {
  for (const failed of [false, true]) {
    const row = baseline.observations.find(x => x.name === `mixed-classifications-${failed}`);
    const result = invoke(row); assert.equal(result.status, failed ? 1 : 0); assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout);
    assert.deepEqual(output.summary, {blocked: 1, failed: failed ? 1 : 0, outOfScope: 1, passed: 1,
      readinessClaim: "classification_honesty_only", rowCount: 4, runIdentity: "run.example"});
    assert.deepEqual(output.diagnostics, [{key: "blockedRowIds", value: ["PROD-02"]},
      {key: "outOfScopeRowIds", value: ["PROD-03"]}, {key: "passedRowIds", value: ["PROD-01"]}]);
    assert.equal(output.ruleResults.length, 7);
    assert.equal(output.ruleResults.filter(x => x.status === "failed").length, failed ? 1 : 0);
  }
});

test("accepted identifier limits and native normalization close the real CLI chain", () => {
  for (const command of [release, readiness]) {
    const row = baseline.observations.find(x => x.command === command && x.name === "valid"), input = JSON.parse(row.input);
    if (command === readiness) input.phraseRules = [{ruleId: "claim.bound", subjectPhrases: ["Unrelated subject"], evidencePhrases: ["Unrelated evidence"],
      predicatePhrases: ["Unrelated predicate"], directClaimPhrases: ["Unrelated claim"], failureMessage: "Synthetic boundary rule."}];
    const locations = paths(input).filter(x => typeof x.value === "string" && rawIDs.has(x.path.at(-1))).map(x => x.path);
    for (const path of locations) at(input, path.slice(0, -1))[path.at(-1)] = "a".repeat(256);
    assert.equal(validators[command].input(input), true, `${command}/all-accepted-id-boundaries`);
    const result = invoke({...row, input: JSON.stringify(input)}); assert.equal(result.status, 0); assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout); assert.equal(validators[command].output(output), true);
    meanings(command, input, output, 0);
    for (const path of locations) {
      const invalid = replace(input, path, "a".repeat(257));
      assert.equal(validators[command].input(invalid), false, `${command}/${path}/outside-id-boundary`);
      const rejected = invoke({...row, input: JSON.stringify(invalid)});
      assert.equal(rejected.status, 1); assert.equal(rejected.stdout, ""); assert.notEqual(rejected.stderr, "");
    }
  }
  const row = baseline.observations.find(x => x.command === readiness && x.name === "valid"), input = JSON.parse(row.input);
  input.inputDefinitions[0].rowId = "\u0085PROD-01\u0085";
  input.inputDefinitions[0].expectedStatus = "\u0085DONE\u0085";
  assert.equal(validators[readiness].input(input), true);
  const result = invoke({...row, input: JSON.stringify(input)}); assert.equal(result.status, 0); assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout); assert.equal(validators[readiness].output(output), true);
  assert.deepEqual(output.diagnostics[2], {key: "passedRowIds", value: ["PROD-01"]});
  for (const path of [["frontier", "rowId"], ["frontier", "closedStatus"], ["inputDefinitions", 0, "rowId"], ["inputDefinitions", 0, "expectedStatus"]]) {
    assert.equal(validators[readiness].input(replace(input, path, "foreign/id")), false, `readiness/${path}/normalized-domain`);
  }
});

test("Markdown-derived row and status admission prevents report egress without rejecting analysis", () => {
  const row = baseline.observations.find(x => x.command === readiness && x.name === "valid");
  const base = JSON.parse(row.input), id = "GL" + "PAT" + "-EXAMPLE-01", status = "GL" + "PAT" + "-EXAMPLE";
  const baseResult = invoke(row); assert.equal(baseResult.status, 0); assert.equal(baseResult.stderr, "");
  const cases = [
    ["unclassified-id", base.markdownText + `\n| DONE | ${id} | Note | Synthetic text |`],
    ["duplicate-id", base.markdownText + `\n| DONE | ${id} | Note | Synthetic text |`.repeat(2)],
    ["definition-status", base.markdownText.replace("| DONE | PROD-01", `| ${status} | PROD-01`)],
    ["frontier-status", base.markdownText.replace("| DONE | PROD-09", `| ${status} | PROD-09`)],
    ["unrelated-id", base.markdownText + `\n### Unrelated\n| DONE | ${id} | Note | Synthetic text |`],
  ];
  for (const [name, markdownText] of cases) {
    const result = invoke({...row, input: JSON.stringify({...base, markdownText})});
    assert.equal(result.status, 1, `derived/${name}/exit`);
    assert.equal(result.stdout, "", `derived/${name}/stdout`);
    assert.match(result.stderr, /secret-like values/, `derived/${name}/admission`);
    assert.equal(result.stderr.includes(id) || result.stderr.includes(status), false, `derived/${name}/nondisclosure`);
  }
  for (const markdownText of [base.markdownText + `\nSynthetic analysis: ${id}`,
    base.markdownText.replace("Alpha phrase", `Alpha phrase ${id}`),
    base.markdownText + `\n| mixed-case | ${id} | Note | Synthetic text |`]) {
    const result = invoke({...row, input: JSON.stringify({...base, markdownText})});
    assert.equal(result.status, 0); assert.equal(result.stderr, "");
    assert.equal(result.stdout.includes(id), false);
    assert.equal(validators[readiness].output(JSON.parse(result.stdout)), true);
  }
});
