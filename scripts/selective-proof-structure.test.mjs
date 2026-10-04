import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, relative, isAbsolute} from "node:path";
import {fileURLToPath} from "node:url";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {planInput, populatedPlanInput, evidenceInput, projectionInput, boundProjectionInput, decisionInput, decisionStates} from "./selective-proof-fixtures.mjs";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_SELECTIVE_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const ajv = new Ajv2020({strict: false, validateFormats: false});
const names = ["selective-gate-plan", "selective-gate-evidence", "selective-gate-obligation-decision-input", "obligation-decision"];
const validators = new Map();
for (const name of names) for (const direction of ["input", "output"]) {
  const ref = contract.commands.find(row => row.command === name)[`${direction}Contract`].rootDefinitionRef;
  const definition = contract.contractDefinitions.find(row => row.definitionId === ref);
  assert.equal(definition.fieldTree.kind, "structural_json_schema");
  validators.set(`${name}/${direction}`, ajv.compile({oneOf: definition.fieldTree.variants.map(row => row.schema)}));
}
let directory, binary, executionSubjects;
const fileDigest = path => createHash("sha256").update(readFileSync(path)).digest("hex");
function binaryIdentity(path) {
  const metadata = execFileSync("go", ["version", "-m", path], {encoding: "utf8", timeout: 10000, maxBuffer: 1 << 20});
  const revision = /^\s*build\tvcs\.revision=([0-9a-f]{40})$/m.exec(metadata)?.[1];
  const modified = /^\s*build\tvcs\.modified=(true|false)$/m.exec(metadata)?.[1];
  assert.ok(revision && modified);
  return {sha256: fileDigest(path), revision, modified: modified === "true"};
}
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-selective-")); binary = join(directory, "proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"],
    {cwd: root, timeout: 120000, maxBuffer: 2 << 20, env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"}});
  if (process.env.PROOFKIT_SELECTIVE_BASELINE) {
    executionSubjects = {kind: "proofkit.selective-comparison-subjects", baseline: binaryIdentity(process.env.PROOFKIT_SELECTIVE_BASELINE),
      candidate: binaryIdentity(binary), testSourceSHA256: fileDigest(new URL(import.meta.url)), fixtureSHA256: fileDigest(new URL("selective-proof-fixtures.mjs", import.meta.url))};
    console.log(JSON.stringify(executionSubjects));
  }
});
after(() => {
  try {
    if (executionSubjects) {
      assert.equal(fileDigest(binary), executionSubjects.candidate.sha256);
      assert.equal(fileDigest(process.env.PROOFKIT_SELECTIVE_BASELINE), executionSubjects.baseline.sha256);
    }
  } finally { if (directory) rmSync(directory, {recursive: true, force: true}); }
});
function validates(name, direction, value, expected = true, label = "") {
  const check = validators.get(`${name}/${direction}`);
  assert.equal(check(value), expected, `${name}/${direction}/${label}: ${ajv.errorsText(check.errors)}`);
}
function native(name, value, {exit = 0, report = true, extra = [], carrier = "stdin", expectedStderr} = {}) {
  let args = [name, "--input", "-", ...extra], input = typeof value === "string" ? value : JSON.stringify(value);
  if (carrier === "pointer") {
    const path = join(directory, "input.json"); writeFileSync(path, JSON.stringify({payload: value}));
    args = [name, "--input", path, "--input-pointer", "/payload", ...extra]; input = "";
  } else if (carrier === "compact") args.unshift("--json-layout", "compact");
  const invoke = file => spawnSync(file, args, {input, encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
  const result = invoke(binary);
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, exit, `${name}: ${result.stderr}`);
  if (expectedStderr !== undefined) assert.equal(result.stderr, expectedStderr);
  if (process.env.PROOFKIT_SELECTIVE_BASELINE) {
    const previous = invoke(process.env.PROOFKIT_SELECTIVE_BASELINE);
    assert.equal(previous.error, undefined);
    assert.deepEqual([result.status, result.signal, result.stdout, result.stderr], [previous.status, previous.signal, previous.stdout, previous.stderr], "native predecessor observation changed");
  }
  if (!report) { assert.equal(result.stdout, ""); assert.notEqual(result.stderr, ""); return; }
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout); validates(name, "output", output); return output;
}
const seeds = {"selective-gate-plan": planInput, "selective-gate-evidence": evidenceInput, "selective-gate-obligation-decision-input": projectionInput, "obligation-decision": decisionInput};
const at = (value, path) => path.reduce((node, key) => node[key], value);
function entries(value, path = []) {
  if (!value || typeof value !== "object") return [];
  return [[path, value], ...Object.entries(value).flatMap(([key, child]) => entries(child, [...path, key]))];
}
const diagnostic = (report, key) => report.diagnostics.find(row => row.key === key).value;
function* outputCases() {
  for (const name of names) yield [name, native(name, seeds[name]())];
  yield [names[0], native(names[0], populatedPlanInput())];
  const plan = planInput(); plan.preexistingFailures = ["Synthetic blocked plan."];
  yield [names[0], native(names[0], plan, {exit: 1})];
  const uncovered = populatedPlanInput(); uncovered.fallbackCoverage = [];
  yield [names[0], native(names[0], uncovered, {exit: 1})];
  for (const status of ["failed", "blocked", "not_run"]) {
    const input = evidenceInput(); Object.assign(input.receipts[0], {status, exitCode: status === "failed" ? 1 : null});
    yield [names[1], native(names[1], input, {exit: 1})];
    yield [names[1], native(names[1], input, {exit: 1, extra: ["--agent-envelope"]})];
  }
  for (const kind of ["missing", "duplicate", "unexpected", "producer"]) {
    const input = evidenceInput();
    if (kind === "missing") input.receipts = [];
    if (kind === "duplicate") input.receipts.push(structuredClone(input.receipts[0]));
    if (kind === "unexpected") input.receipts[0].id = "unknown.command";
    if (kind === "producer") input.evidenceClass = "merge_satisfying";
    yield [names[1], native(names[1], input, {exit: 1})];
    yield [names[1], native(names[1], input, {exit: 1, extra: ["--agent-envelope"]})];
  }
  const bound = boundProjectionInput(); bound.evidence.producerAdmission.receipts[0].producerId = "unknown.producer";
  yield [names[1], native(names[1], bound.evidence, {exit: 1})];
  yield [names[1], native(names[1], bound.evidence, {exit: 1, extra: ["--agent-envelope"]})];
  for (const name of [names[0], names[1], names[3]]) {
    yield [name, native(name, seeds[name](), {extra: ["--agent-envelope"]})];
    yield [name, native(name, {}, {exit: 1, extra: ["--agent-envelope"]})];
  }
  const decision = decisionInput(); decision.obligations[0].candidateStates = ["missing_receipt"];
  yield [names[3], native(names[3], decision, {exit: 1})];
  yield [names[3], native(names[3], decision, {exit: 1, extra: ["--agent-envelope"]})];
  decision.obligations[0].candidateStates = ["unknown_scope"];
  yield [names[3], native(names[3], decision, {exit: 1, extra: ["--agent-envelope"]})];
}

test("four whole CLI routes preserve stdin pointer compact and owner identity", () => {
  for (const name of names) {
    const input = seeds[name](); validates(name, "input", input);
    const output = native(name, input);
    for (const carrier of ["pointer", "compact"]) assert.deepEqual(native(name, input, {carrier}), output);
    if (name === "selective-gate-plan") assert.equal(output.planState, "ok");
    if (name === "selective-gate-evidence") assert.equal(output.reportKind, "proofkit.selective-gate-evidence");
    if (name === "selective-gate-obligation-decision-input") assert.deepEqual(output.obligations[0].candidateStates, ["invalid_producer", "unknown_scope", "satisfied"]);
    if (name === "obligation-decision") assert.deepEqual([output.reportKind, output.state, output.summary.obligationCount], ["proofkit.obligation-decision", "passed", 1]);
  }
});

test("populated plan traverses evidence projector and decision without hidden adapters", () => {
  const source = populatedPlanInput(); validates(names[0], "input", source);
  const plan = native(names[0], source);
  assert.equal(plan.generatedArtifacts.length, 1); assert.equal(plan.artifactIntegrity.length, 1);
  assert.equal(plan.unknownEdges[0].coverageState, "covered_by_declared_fallback");
  const evidence = evidenceInput(); evidence.plan = plan;
  evidence.receipts = plan.requiredCommands.map(row => ({artifactRefs: [], command: row.command, evidenceRef: "evidence/run.json", exitCode: 0, id: row.id, status: "passed", ...(row.sourcePath ? {sourcePath: row.sourcePath} : {})}));
  validates(names[1], "input", evidence);
  assert.equal(native(names[1], evidence).summary.receiptCount, plan.requiredCommands.length);
  const projection = projectionInput(); projection.evidence = evidence;
  projection.commandRoutes = plan.requiredCommands.map((row, index) => ({...projectionInput().commandRoutes[0], command: row.command, commandId: row.id,
    obligationId: `obligation.${index}`, sourcePath: row.sourcePath ?? null}));
  validates(names[2], "input", projection);
  const decision = native(names[2], projection); validates(names[3], "input", decision);
  const result = native(names[3], decision, {exit: 1});
  assert.equal(result.summary.blockingUnsatisfiedCount, plan.requiredCommands.length);
  assert.ok(diagnostic(result, "decisions").every(row => row.decisionState === "invalid_producer"));
});

test("complete child evidence supports a satisfied decision without implying execution", () => {
  const input = boundProjectionInput(); validates(names[2], "input", input);
  assert.equal(native(names[1], input.evidence).summary.producerAdmissionState, "passed");
  const decision = native(names[2], input);
  assert.deepEqual(decision.obligations[0].candidateStates, ["satisfied"]);
  assert.equal(native(names[3], decision).state, "passed");
  for (const child of ["receiptCurrentnessScopeAdmission", "receiptTrustClassAdmission"]) {
    const bad = structuredClone(input); bad[child].obligationReceipts[0].receiptId = "receipt.other";
    validates(names[2], "input", bad); native(names[2], bad, {exit: 1, report: false});
  }
});

test("optional null partitions preserve the consuming owner domain", () => {
  const nullCommand = planInput(); nullCommand.dependencyFreshness.command = null;
  validates(names[0], "input", nullCommand, false, "dependencyFreshness/command/null");
  native(names[0], nullCommand, {exit: 1, report: false});
  for (const key of ["fallbackCoverage", "pathTriggeredCommands", "unknownEdges"]) {
    const input = planInput(); input[key] = null; validates(names[0], "input", input); native(names[0], input);
  }
  const bad = planInput(); bad.fullWorkspaceCommand = null; validates(names[0], "input", bad, false); native(names[0], bad, {exit: 1, report: false});
  for (const key of ["producerAdmission"]) {
    const input = evidenceInput(); input[key] = null; validates(names[1], "input", input); native(names[1], input);
  }
  for (const key of ["sourcePath", "producerReceiptId"]) {
    const input = evidenceInput(); input.receipts[0][key] = null; validates(names[1], "input", input, false); native(names[1], input, {exit: 1, report: false});
  }
  const projection = projectionInput(); projection.commandRoutes[0].sourcePath = null;
  projection.receiptCurrentnessScopeAdmission = null; projection.receiptTrustClassAdmission = null;
  validates(names[2], "input", projection); native(names[2], projection);
  const broader = evidenceInput(); broader.plan.nonClaims = [];
  broader.plan.touchedRequirementWitnesses = [{commands: [], path: "tests/one.go", requirementIds: []}];
  validates(names[1], "input", broader); native(names[1], broader);
});

test("projected nonClaims retain the downstream native admission boundary", () => {
  const input = boundProjectionInput();
  input.nonClaims = ["Obligation decision reports do not execute proofs."];
  validates(names[2], "input", input);
  const projected = native(names[2], input);
  validates(names[3], "input", projected);
  assert.ok(projected.nonClaims.includes(input.nonClaims[0]));
  native(names[3], projected, {exit: 1, report: false, expectedStderr: "obligation decision nonClaims must be unique\n"});
});

test("evidence failure rules sort together with the fixed rules", () => {
  const input = evidenceInput(); input.receipts = [];
  const output = native(names[1], input, {exit: 1});
  assert.deepEqual(output.ruleResults.map(row => row.ruleId), [
    "coverage", "duplicates", "failure.001", "plan", "producer-admission", "status", "unexpected",
  ].map(suffix => `proofkit.selective-gate-evidence.${suffix}`));
});

test("receipt statuses own exit-code presence and report partitions", () => {
  for (const [status, code, state] of [["passed", 0, "passed"], ["failed", 1, "failed"], ["blocked", null, "blocked"], ["not_run", null, "failed"]]) {
    const input = evidenceInput(); Object.assign(input.receipts[0], {status, exitCode: code});
    validates(names[1], "input", input); assert.equal(native(names[1], input, {exit: state === "passed" ? 0 : 1}).state, state);
    if (code === null) { delete input.receipts[0].exitCode; validates(names[1], "input", input); native(names[1], input, {exit: 1}); }
    for (const bad of [0.5, -1, "0", {}, ...(status === "passed" ? [1, null] : status === "failed" ? [0, null] : [0])]) {
      const copy = structuredClone(input); copy.receipts[0].exitCode = bad;
      validates(names[1], "input", copy, false); native(names[1], copy, {exit: 1, report: false});
    }
  }
});

test("all decision states and classes retain rank counts and blocking semantics", () => {
  for (const obligationClass of ["blocking", "advisory", "deferred"]) for (const [rank, state] of decisionStates.entries()) {
    const input = decisionInput(); Object.assign(input.obligations[0], {obligationClass, candidateStates: [state]});
    validates(names[3], "input", input);
    const blocking = obligationClass === "blocking" && !["satisfied", "not_applicable"].includes(state);
    const output = native(names[3], input, {exit: blocking ? 1 : 0});
    assert.deepEqual([diagnostic(output, "decisions")[0].decisionState, diagnostic(output, "decisions")[0].decisionRank, output.summary.stateCounts[state]], [state, rank, 1]);
    assert.equal(output.summary.blockingUnsatisfiedCount, blocking ? 1 : 0);
    native(names[3], input, {exit: blocking ? 1 : 0, extra: ["--agent-envelope"]});
  }
  for (const [field, bad] of [["candidateStates", ["unsupported"]], ["obligationClass", "unsupported"]]) {
    const input = decisionInput(); input.obligations[0][field] = bad;
    validates(names[3], "input", input, false, field); native(names[3], input, {exit: 1, report: false});
  }
});

test("every envelope mode includes invalid-input and bounded failure carriers", () => {
  for (const name of [names[0], names[1], names[3]]) {
    const normal = native(name, seeds[name](), {extra: ["--agent-envelope"]});
    assert.equal(normal.envelopeId, `proofkit.${name}.agent-envelope`);
    for (const bad of [{}, {schemaVersion: 1}]) {
      const output = native(name, bad, {exit: 1, extra: ["--agent-envelope"]});
      assert.equal(output.envelopeId, "proofkit.agent-envelope.invalid-input");
      assert.equal(output.sourceReport.state, "failed");
    }
    native(name, '{"schemaVersion":1,"schemaVersion":1}', {exit: 1, report: false, extra: ["--agent-envelope"]});
  }
  const failures = planInput(); failures.preexistingFailures = Array.from({length: 30}, (_, i) => `Failure ${i}.`);
  const output = native(names[0], failures, {exit: 1, extra: ["--agent-envelope"]});
  assert.equal(output.blockedPreconditions.length, 12); assert.equal(output.clarificationQuestions.length, 12);
  assert.equal(output.bounds.truncated, true); assert.ok(output.omitted.length);
  const crowded = decisionInput(); crowded.obligations = Array.from({length: 30}, (_, i) => ({...decisionInput().obligations[0], obligationId: `obligation.${String(i).padStart(2, "0")}`, candidateStates: ["missing_receipt"]}));
  const large = native(names[3], crowded, {exit: 1, extra: ["--agent-envelope"]});
  assert.equal(large.actionPlan.length, 20); assert.equal(large.contextRefs.length, 48); assert.ok(large.bounds.maxContextRefs > 48);
  assert.equal(large.omitted.length, 1); assert.equal(large.bounds.truncated, true);
  native(names[2], projectionInput(), {exit: 1, report: false, extra: ["--agent-envelope"]});
});

test("closed nested input objects and populated list items reject malformed neighbors", () => {
  for (const [name, input] of [[names[0], populatedPlanInput()], [names[1], evidenceInput()], [names[2], boundProjectionInput()], [names[3], decisionInput()]]) {
    validates(name, "input", input); native(name, input);
    for (const [path, value] of entries(input)) {
      if (Array.isArray(value)) {
        for (const bad of [null, false, 0, [], "", {}]) {
          const copy = structuredClone(input); at(copy, path).push(bad);
          validates(name, "input", copy, false, path.join("/")); native(name, copy, {exit: 1, report: false});
        }
      } else {
        const copy = structuredClone(input); at(copy, path).unknownField = true;
        validates(name, "input", copy, false, path.join("/")); native(name, copy, {exit: 1, report: false});
      }
    }
  }
});

test("nested output records reject field removal unknown members and item corruption", () => {
  for (const [name, output] of outputCases()) for (const [path, value] of entries(output)) {
    if (Array.isArray(value)) {
      const copy = structuredClone(output); at(copy, path).push(false); validates(name, "output", copy, false, path.join("/"));
    } else {
      const copy = structuredClone(output); at(copy, path).unknownField = true; validates(name, "output", copy, false, path.join("/"));
      for (const key of Object.keys(value)) {
        const optionalSourcePath = key === "sourcePath" && name === names[0] &&
          (path.length === 2 && path[0] === "requiredCommands" || path.length === 3 && path[0] === "fallbackCoverage" && path[2] === "command");
        if (optionalSourcePath || ["truncated", "prunedLocalReferenceCount", "referenceClosurePreserved", "boundsViolationCount", "boundsViolations"].includes(key) || key === "commandOwnership" && path.at(-1) !== "scanObligation") continue;
        const missing = structuredClone(output); delete at(missing, path)[key]; validates(name, "output", missing, false, [...path, key].join("/"));
      }
    }
  }
});

test("coverage sourcePath is required nullable across receipt and command-key records", () => {
  for (const key of ["failedReceipts", "blockedReceipts", "notRunReceipts", "missingReceipts", "duplicateReceipts", "unexpectedReceipts"]) {
    for (const sourcePath of [null, "src/check.go"]) {
      const input = evidenceInput();
      const receipt = {artifactRefs: [], command: "go test ./...", evidenceRef: "evidence/check.json", exitCode: 0, id: "check.one", status: "passed"};
      const command = {command: receipt.command, id: receipt.id, reason: "Synthetic check."};
      if (sourcePath !== null) {
        command.sourcePath = sourcePath;
        receipt.sourcePath = sourcePath;
      }
      input.plan.requiredCommands.push(command);
      input.receipts.push(receipt);
      native(names[1], input);
      const status = {failedReceipts: "failed", blockedReceipts: "blocked", notRunReceipts: "not_run"}[key];
      if (status) Object.assign(receipt, {status, exitCode: status === "failed" ? 1 : null});
      if (key === "missingReceipts") input.receipts.pop();
      if (key === "duplicateReceipts") input.receipts.push(structuredClone(receipt));
      if (key === "unexpectedReceipts") receipt.id = "unknown.command";
      const output = native(names[1], input, {exit: 1});
      const records = diagnostic(output, "coverage")[key];
      assert.ok(records.length > 0, key);
      assert.equal(records[0].sourcePath, sourcePath, key);
      const missing = structuredClone(output);
      delete diagnostic(missing, "coverage")[key][0].sourcePath;
      validates(names[1], "output", missing, false, `${key}/sourcePath/absent`);
    }
  }
});

test("delimiter-bearing duplicate keys retain command text and only repair the declared legacy fields", () => {
  const invoke = (file, input) => {
    const result = spawnSync(file, [names[1], "--input", "-"], {input: JSON.stringify(input), encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
    assert.equal(result.error, undefined); assert.equal(result.signal, null);
    assert.equal(result.status, 1); assert.equal(result.stderr, "");
    return result;
  };
  for (const command of ["\u0000", "go\u0000test", "\u0000go\u0000test\u0000"]) {
    for (const sourcePath of [null, "src/check.go"]) {
      const input = evidenceInput(); input.receipts[0].command = command;
      if (sourcePath !== null) input.receipts[0].sourcePath = sourcePath;
      input.receipts.push(structuredClone(input.receipts[0]));
      validates(names[1], "input", input);
      const current = invoke(binary, input), output = JSON.parse(current.stdout);
      validates(names[1], "output", output);
      const expected = {command, id: "scan.one", sourcePath};
      assert.deepEqual(diagnostic(output, "coverage").duplicateReceipts, [expected]);
      const message = `duplicate receipt for required command: scan.one :: ${command}` + (sourcePath === null ? "" : ` :: ${sourcePath}`);
      const ruleId = "proofkit.selective-gate-evidence.failure.001";
      assert.equal(output.ruleResults.find(row => row.ruleId === ruleId).message, message);
      if (process.env.PROOFKIT_SELECTIVE_BASELINE) {
        const previous = invoke(process.env.PROOFKIT_SELECTIVE_BASELINE, input);
        const corrected = JSON.parse(previous.stdout);
        assert.notDeepEqual(diagnostic(corrected, "coverage").duplicateReceipts, [expected]);
        diagnostic(corrected, "coverage").duplicateReceipts = [expected];
        const failure = corrected.ruleResults.find(row => row.ruleId === ruleId);
        assert.ok(failure.message.startsWith("duplicate receipt for required command: scan.one :: "));
        failure.message = message;
        assert.deepEqual(output, corrected);
        assert.equal(current.stdout, JSON.stringify(corrected, null, 2) + "\n");
      }
    }
  }
  const input = evidenceInput(), receipt = input.receipts[0];
  const expected = [{command: "go", id: "scan.one", sourcePath: "test"}, {command: "go\u0000test", id: "scan.one", sourcePath: null}];
  input.receipts = expected.flatMap(key => {
    const value = {...receipt, command: key.command};
    if (key.sourcePath !== null) value.sourcePath = key.sourcePath;
    return [value, structuredClone(value)];
  });
  const current = invoke(binary, input), output = JSON.parse(current.stdout);
  validates(names[1], "output", output);
  assert.deepEqual(diagnostic(output, "coverage").duplicateReceipts, expected);
  assert.equal(output.summary.duplicateReceiptCount, 2);
  if (process.env.PROOFKIT_SELECTIVE_BASELINE) {
    const previous = invoke(process.env.PROOFKIT_SELECTIVE_BASELINE, input);
    const corrected = JSON.parse(previous.stdout);
    assert.deepEqual(diagnostic(corrected, "coverage").duplicateReceipts, [expected[0], expected[0]]);
    diagnostic(corrected, "coverage").duplicateReceipts = expected;
    const messages = ["duplicate receipt for required command: scan.one :: go\u0000test", "duplicate receipt for required command: scan.one :: go :: test"];
    for (const [index, message] of messages.entries()) {
      corrected.ruleResults.find(row => row.ruleId === `proofkit.selective-gate-evidence.failure.00${index + 1}`).message = message;
    }
    assert.deepEqual(output, corrected);
    assert.equal(current.stdout, JSON.stringify(corrected, null, 2) + "\n");
  }
});

test("repaired report hashes bind both envelope references across layouts and omissions", () => {
  const sourceRefId = "proofkit.agent.context.selective-evidence.001";
  const invoke = (file, input, layout) => {
    const args = layout ? ["--json-layout", layout, names[1], "--input", "-", "--agent-envelope"] : [names[1], "--input", "-"];
    const result = spawnSync(file, args,
      {input: JSON.stringify(input), encoding: "utf8", timeout: 10000, maxBuffer: 4 << 20});
    assert.equal(result.error, undefined); assert.equal(result.signal, null);
    assert.equal(result.status, 1); assert.equal(result.stderr, "");
    return {wire: result.stdout, value: JSON.parse(result.stdout)};
  };
  for (const crowded of [false, true]) {
    const input = evidenceInput(); input.receipts[0].command = "go\u0000test";
    input.receipts.push(structuredClone(input.receipts[0]));
    if (crowded) for (let index = 0; index < 30; index++) {
      input.plan.requiredCommands.push({command: "go test ./extra", id: `extra.${index}`, reason: "Synthetic missing receipt."});
    }
    validates(names[1], "input", input);
    const report = invoke(binary, input);
    validates(names[1], "output", report.value);
    const digest = wire => "sha256:" + createHash("sha256").update(wire).digest("hex");
    const currentHash = digest(report.wire);
    const predecessor = process.env.PROOFKIT_SELECTIVE_BASELINE;
    const previousHash = predecessor ? digest(invoke(predecessor, input).wire) : null;
    if (predecessor) assert.notEqual(currentHash, previousHash);
    for (const layout of ["pretty", "compact"]) {
      const current = invoke(binary, input, layout);
      validates(names[1], "output", current.value);
      assert.equal(current.value.sourceReport.stableHash, currentHash);
      assert.equal(current.value.contextRefs.find(row => row.refId === sourceRefId).ref, currentHash);
      assert.equal(current.value.bounds.omittedCount > 0, crowded);
      if (predecessor) {
        const previous = invoke(predecessor, input, layout).value;
        assert.equal(previous.sourceReport.stableHash, previousHash);
        const sourceRef = previous.contextRefs.find(row => row.refId === sourceRefId);
        assert.equal(sourceRef.ref, previousHash);
        previous.sourceReport.stableHash = currentHash; sourceRef.ref = currentHash;
        assert.deepEqual(current.value, previous);
        assert.equal(current.wire, JSON.stringify(previous, null, layout === "pretty" ? 2 : 0) + "\n");
      }
    }
  }
});

test("every required input member has an isolated missing-member counterexample", () => {
  for (const [name, input] of [[names[0], populatedPlanInput()], [names[1], evidenceInput()], [names[2], boundProjectionInput()], [names[3], decisionInput()]]) {
    for (const [path, value] of entries(input)) {
      if (Array.isArray(value)) continue;
      for (const key of Object.keys(value)) {
        const optional = ["fullWorkspaceCommand", "fallbackCoverage", "pathTriggeredCommands", "unknownEdges", "sourcePath", "producerReceiptId", "producerAdmission", "receiptCurrentnessScopeAdmission", "receiptTrustClassAdmission"].includes(key);
        // Plan children require these lists; producer provenance alone is optional.
        if (optional && !(["fallbackCoverage", "unknownEdges"].includes(key) && path.at(-1) === "plan")) continue;
        if (key === "provenanceRef" && path.includes("producerAdmission")) continue;
        if (key === "commandOwnership" && path.at(-1) !== "scanObligation") continue;
        const copy = structuredClone(input); delete at(copy, path)[key];
        validates(name, "input", copy, false, [...path, key].join("/")); native(name, copy, {exit: 1, report: false});
      }
    }
  }
});

test("input scalar types and boolean nullability reject independent wrong-type neighbors", () => {
  for (const [name, input] of [[names[0], populatedPlanInput()], [names[1], evidenceInput()], [names[2], boundProjectionInput()], [names[3], decisionInput()]]) {
    validates(name, "input", input); native(name, input);
    for (const [path, record] of entries(input)) for (const [key, value] of Object.entries(record)) {
      const badValues = typeof value === "boolean" ? [null, "false", 0] : ["number", "string"].includes(typeof value) ? [false, true, {}] : [];
      for (const badValue of badValues) {
        const bad = structuredClone(input); at(bad, path)[key] = badValue;
        validates(name, "input", bad, false, [...path, key].join("/"));
        native(name, bad, {exit: 1, report: false});
      }
    }
  }
});

test("scalar domains reject wrong types empty strings and numeric boundary neighbors", () => {
  const enumFields = new Set(["decisionState", "obligationClass", "status", "state", "planState", "mode", "commandOwnership", "coverageState", "phase", "kind", "role", "expectedAnswerKind", "producerAdmission", "receiptClass", "selectedState", "fanout", "stopReason", "reportKind", "ruleId", "envelopeId", "evidenceClass", "producerAdmissionState"]);
  for (const [name, output] of outputCases()) for (const [path, value] of entries(output)) {
    if (Array.isArray(value)) continue;
    for (const [key, child] of Object.entries(value)) {
      if (child !== null && typeof child === "object") continue;
      const badValues = child === null ? [false, 0, "", {}] : typeof child === "string" ? [false, 0, null, ""] : typeof child === "number" ? ["0", null, -1, child + 0.5, 2 ** 64] : ["false", 0, null];
      for (const bad of badValues) {
        const copy = structuredClone(output); at(copy, path)[key] = bad;
        validates(name, "output", copy, false, [...path, key].join("/"));
      }
      if (enumFields.has(key) && typeof child === "string") {
        const copy = structuredClone(output); at(copy, path)[key] = "unsupported";
        validates(name, "output", copy, false, [...path, key].join("/"));
      }
      if (["consumerObligationDecisionRequired", "omittedEdgesCounted", "truncated", "required"].includes(key) || key === "referenceClosurePreserved" && path.at(-1) === "bounds") {
        const copy = structuredClone(output); at(copy, path)[key] = !child;
        validates(name, "output", copy, false, [...path, key].join("/"));
      }
    }
  }
  const input = evidenceInput(); input.receipts[0].exitCode = -0; validates(names[1], "input", input); native(names[1], input);
  for (const token of ["-0", "0.0", "0e0"]) {
    const bytes = JSON.stringify(evidenceInput()).replace('"exitCode":0', `"exitCode":${token}`);
    native(names[1], bytes, token === "-0" ? {} : {exit: 1, report: false});
  }
  const decision = decisionInput(); decision.decisionId = "a".repeat(256);
  validates(names[3], "input", decision); native(names[3], decision);
  decision.decisionId += "a"; validates(names[3], "input", decision, false); native(names[3], decision, {exit: 1, report: false});
});

test("all scan owners and edge classes retain positive native routes", () => {
  for (const [commandOwnership, commandId, reason] of [["caller_owned_external", "scan.one", "external_secret_scan"], ["proofkit_text_policy", "text-policy", "text_policy"], ["proofkit_secret_scan", "secret-scan", "secret_scan"]]) {
    const input = planInput(); Object.assign(input.scanObligation, {commandOwnership, commandId, reason});
    validates(names[0], "input", input); assert.equal(native(names[0], input).scanObligation.commandOwnership, commandOwnership);
  }
  for (const edgeClass of ["command_environment_registry", "dynamic_or_unknown", "generated_source", "package_reverse_dependency", "public_export_api", "requirement_binding", "source_owner_mapping", "witness_selector", "workspace_script"]) {
    const input = populatedPlanInput(); input.unknownEdges[0].edgeClass = edgeClass; input.fallbackCoverage[0].edgeClasses = [edgeClass];
    validates(names[0], "input", input); assert.equal(native(names[0], input).unknownEdges[0].edgeClass, edgeClass);
  }
  const generated = populatedPlanInput(); generated.changedPaths = ["generated/item.go"];
  const output = native(names[0], generated, {exit: 1}); assert.equal(output.generatedArtifacts[0].reason, "generated_artifact_changed");
  for (const [key, bad] of [["commandOwnership", "unknown"], ["mode", "full"], ["reason", "unknown"], ["required", false]]) {
    const input = planInput(); input.scanObligation[key] = bad;
    validates(names[0], "input", input, false, key); native(names[0], input, {exit: 1, report: false});
  }
  for (const field of ["unknownEdges", "fallbackCoverage"]) {
    const input = populatedPlanInput();
    if (field === "unknownEdges") input.unknownEdges[0].edgeClass = "unsupported";
    else input.fallbackCoverage[0].edgeClasses = ["unsupported"];
    validates(names[0], "input", input, false, field); native(names[0], input, {exit: 1, report: false});
  }
});

test("ambiguous local identities preserve omission and reference-pruning carriers", () => {
  const input = planInput(); input.baseCommands = [{command: "go test ./other", id: "scan.one", reason: "other"}];
  const output = native(names[0], input, {extra: ["--agent-envelope"]});
  assert.equal(output.commands.length, 0); assert.equal(output.costContract.referenceClosurePreserved, false);
  assert.equal(output.bounds.referenceClosurePreserved, false); assert.ok(output.costContract.prunedLocalReferenceCount > 0);
  assert.ok(output.omitted.some(row => row.omittedCount > 0));
});

test("nonempty collections and bounded envelope arrays have boundary falsifiers", () => {
  for (const [name, seed, paths] of [
    [names[0], populatedPlanInput, [["nonClaims"], ["touchedRequirementWitnesses", "0", "commands"], ["touchedRequirementWitnesses", "0", "requirementIds"], ["pathTriggeredCommands", "0", "pathPatterns"], ["fallbackCoverage", "0", "edgeClasses"]]],
    [names[1], evidenceInput, [["nonClaims"]]],
    [names[2], projectionInput, [["nonClaims"], ["commandRoutes", "0", "nonClaims"], ["commandRoutes", "0", "evidenceRefs"]]],
    [names[3], decisionInput, [["nonClaims"], ["obligations"], ["obligations", "0", "candidateStates"], ["obligations", "0", "evidenceRefs"], ["obligations", "0", "nonClaims"]]],
  ]) for (const path of paths) {
    const input = seed(); at(input, path.slice(0, -1))[path.at(-1)] = [];
    validates(name, "input", input, false, path.join("/")); native(name, input, {exit: 1, report: false});
  }
  const input = decisionInput(); input.obligations[0].candidateStates = ["missing_receipt"];
  const output = native(names[3], input, {exit: 1});
  diagnostic(output, "decisions")[0].decisionRank = 12; validates(names[3], "output", output, false);
  const envelope = native(names[3], input, {exit: 1, extra: ["--agent-envelope"]});
  for (const [field, size] of [["actionPlan", 21], ["blockedPreconditions", 13], ["contextRefs", 49], ["receiptRefs", 21], ["routeQuestions", 4]]) {
    assert.ok(envelope[field].length); const bad = structuredClone(envelope);
    bad[field] = Array.from({length: size}, () => structuredClone(envelope[field][0])); validates(names[3], "output", bad, false, field);
  }
  const fixed = native(names[0], planInput(), {extra: ["--agent-envelope"]});
  for (const field of ["actionPlan", "routeQuestions"]) {
    const bad = structuredClone(fixed); bad[field].pop(); validates(names[0], "output", bad, false, field);
  }
  const withCommands = structuredClone(envelope); withCommands.commands = [fixed.commands[0]];
  validates(names[3], "output", withCommands, false);
});

test("boundary witness inputs include build fixture and local import operands", () => {
  const manifest = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));
  const argv = manifest.scripts["boundary-contract:check"].split(" ");
  assert.deepEqual(argv.slice(0, 2), ["node", "--test"]);
  assert.ok(argv.length > 2);
  for (const path of argv.slice(2)) assert.match(path, /^scripts\/[a-z0-9.-]+\.test\.mjs$/);
  // Static imports and authored non-import operands have different owners.
  // The latter includes native build inputs, fixture roots and this read plan;
  // neither inventory claims arbitrary runtime filesystem discovery.
  const listing = execFileSync(process.execPath, ["node_modules/typescript/bin/tsc", "--allowJs", "--noEmit", "--listFilesOnly", ...argv.slice(2)],
    {cwd: root, encoding: "utf8", timeout: 30000, maxBuffer: 4 << 20});
  const sources = new Set();
  for (const file of listing.trim().split(/\r?\n/)) {
    const path = relative(fileURLToPath(root), file).replaceAll("\\", "/");
    assert.ok(!isAbsolute(path) && !path.startsWith("../"));
    if (path.startsWith("node_modules/")) continue;
    assert.match(path, /^scripts\/[a-z0-9.-]+\.mjs$/); sources.add(path);
  }
  for (const path of argv.slice(2)) assert.ok(sources.has(path));
  for (const path of ["cmd", "go.mod", "go.sum", "internal", "package-lock.json", "package.json",
    "proofkit/cli-contract.v2.json", "proofkit/witness-plan.json"]) sources.add(path);
  const plan = JSON.parse(readFileSync(new URL("proofkit/witness-plan.json", root), "utf8"));
  const selectors = plan.policies.find(row => row.commandId === "proofkit.boundary-contract-check").inputSelectors;
  const missing = input => [...sources].filter(path => !input.includes(path));
  assert.deepEqual(missing(selectors), []);
  for (const path of sources) assert.deepEqual(missing(selectors.filter(item => item !== path)), [path]);
});

test("native-only relations remain fail closed while metadata stays structurally valid", () => {
  const plan = planInput(); plan.scanObligation.commandOwnership = "proofkit_text_policy";
  validates(names[0], "input", plan); native(names[0], plan, {exit: 1, report: false});
  const projection = projectionInput(); projection.commandRoutes[0].commandId = "unknown.command";
  validates(names[2], "input", projection); native(names[2], projection, {exit: 1, report: false});
  const decision = decisionInput(); decision.obligations[0].candidateStates = ["satisfied", "satisfied"];
  validates(names[3], "input", decision); native(names[3], decision, {exit: 1, report: false});
  const unavailable = evidenceInput(); unavailable.evidenceClass = "merge_satisfying";
  validates(names[1], "input", unavailable); assert.equal(native(names[1], unavailable, {exit: 1}).summary.producerAdmissionFailureCount, 1);
});
