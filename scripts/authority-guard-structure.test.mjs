import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url), producer = "producer-policy-self-proof", migration = "migration-parity-admission";
const baseline = JSON.parse(readFileSync(new URL("internal/app/testdata/authority-guard-native-observations.json", root)));
assert.equal(baseline.head, "ebdd943e0740998e5051e98a87be0288f271f69a");
assert.equal(baseline.tree, "1f62667dcb9de501fbb66672be1f91d27b502e0a");
assert.equal(baseline.observations.length, 75);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_AUTHORITY_GUARD_CONTRACT || new URL("proofkit/cli-contract.v2.json", root)));
const ajv = new Ajv2020({strict: false, validateFormats: false});
const validators = Object.fromEntries([producer, migration].map(command => [command, Object.fromEntries(["input", "output"].map(direction => {
  const id = `proofkit.${command}.${direction}.v1.json-schema`, binding = contract.commands.find(x => x.command === command)[direction + "Contract"];
  assert.equal(binding.contractId, `proofkit.${command}.${direction}.v1`); assert.equal(binding.rootDefinitionRef, id);
  const definition = contract.contractDefinitions.find(x => x.definitionId === id);
  assert.ok(definition); return [direction, ajv.compile(definition.fieldTree.variants[0].schema)];
}))]));
const builtin = {
  [producer]: ["Producer policy self-proof guard does not approve merge, release, rollout, or migration exceptions.",
    "Producer policy self-proof guard does not authenticate producers.", "Producer policy self-proof guard does not compute receipt freshness.",
    "Producer policy self-proof guard does not execute commands or inspect CI state.", "Producer policy self-proof guard does not verify policy digest provenance."],
  [migration]: ["Migration parity admission does not approve old-owner deletion, migration exceptions, merge, release, rollout, or production readiness.",
    "Migration parity admission does not authenticate parity evidence.", "Migration parity admission does not compute digest values or proof freshness.",
    "Migration parity statuses and status-derived parity claim counters are caller declarations, while structural and failure counts are Proofkit-computed admission facts; none are native verification results.",
    "Migration parity admission does not execute native commands or prove command result correctness.",
    "Migration parity admission does not prove semantic correctness of either legacy or Proofkit-owned infrastructure."],
};
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-authority-guard-")); binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120000, env: {...process.env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off"},
  });
});
after(() => {if (directory) rmSync(directory, {recursive: true, force: true});});
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
function invoke(command, input, argv = [command, "--input", "-"]) {
  const result = spawnSync(binary, argv, {input, encoding: "utf8", timeout: 10000, maxBuffer: 2 << 20});
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return result;
}
const utf8Order = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
const normalizedText = text => text.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
const sortedText = values => values.map(normalizedText).sort(utf8Order);
const tuple = (x, level) => [x.producerId, x.producerClass, x.proofClass, x.receiptKind, x.environmentClass, normalizedText(x.provenanceRuleRef), normalizedText(x.artifactRetentionRuleRef), level];
function producerSemantics(input, output) {
  const changes = [...input.admissionChanges].sort((a, b) => utf8Order(a.changeId, b.changeId));
  const receipts = [...input.mergeObligationReceiptRefs].sort((a, b) => utf8Order(a.receiptId, b.receiptId));
  const newTuples = new Set(changes.filter(x => x.toAdmissionLevel === "merge_satisfying").map(x => JSON.stringify(tuple(x, x.toAdmissionLevel))));
  const self = receipts.filter(x => x.satisfiesMergeObligation && newTuples.has(JSON.stringify(tuple(x, x.producerAdmissionClass))));
  const failures = [];
  if (input.baselinePolicyDigest === input.proposedPolicyDigest && changes.length) failures.push("unchanged producer policy declares admission changes");
  for (const x of changes) {
    if (x.changeKind === "add_producer" && x.fromAdmissionLevel !== null) failures.push(`admission change ${x.changeId} add_producer must start without an admission level`);
    if (x.changeKind === "promote_to_merge_satisfying" && x.toAdmissionLevel !== "merge_satisfying") failures.push(`admission change ${x.changeId} promotion does not target merge_satisfying`);
    if (x.changeKind === "promote_to_merge_satisfying" && x.fromAdmissionLevel !== null && x.fromAdmissionLevel === x.toAdmissionLevel) failures.push(`admission change ${x.changeId} does not change admission level`);
  }
  for (const x of receipts.filter(x => x.satisfiesMergeObligation)) {
    if (x.receiptStatus !== "passed") failures.push(`merge-obligation receipt ${x.receiptId} is not passed`);
    if (x.producerAdmissionClass !== "merge_satisfying") failures.push(`merge-obligation receipt ${x.receiptId} does not use a merge_satisfying producer class`);
    if (self.includes(x)) failures.push(`merge-obligation receipt ${x.receiptId} uses newly admitted producer tuple: ${tuple(x, x.producerAdmissionClass).join("|")}`);
  }
  failures.sort(utf8Order);
  assert.equal(output.reportId, input.guardId); assert.equal(output.state, failures.length ? "failed" : "passed");
  assert.deepEqual(output.summary, {admissionChangeCount: changes.length, declaredMergeObligationReceiptCount: receipts.filter(x => x.satisfiesMergeObligation).length,
    failureCount: failures.length, newlyMergeSatisfyingTupleCount: newTuples.size, policyChanged: input.baselinePolicyDigest !== input.proposedPolicyDigest, selfProofReceiptCount: self.length});
  const policy = {baselinePolicyDigest: input.baselinePolicyDigest, nonClaimRefs: input.nonClaimRefs, policyChangeDigest: input.policyChangeDigest,
    policyChangeId: input.policyChangeId, policyId: input.policyId, policyOwner: normalizedText(input.policyOwner), policySurfaceRefs: sortedText(input.policySurfaceRefs), proposedPolicyDigest: input.proposedPolicyDigest};
  const projected = self.map(x => Object.fromEntries(["artifactRetentionRuleRef", "environmentClass", "nonClaimRefs", "producerClass", "producerId", "proofClass", "proofReceiptDigest", "proofReceiptRef", "provenanceRuleRef", "receiptId", "receiptKind"].map(key => [key, typeof x[key] === "string" ? normalizedText(x[key]) : x[key]])));
  assert.deepEqual(output.diagnostics, [{key: "failures", value: failures}, {key: "policy", value: policy}, {key: "selfProofReceipts", value: projected}]);
  assert.deepEqual(output.ruleResults, [
    {ruleId: "proofkit.producer-policy-self-proof.boundary", status: "passed", message: "proofkit validates caller-provided producer-policy self-proof facts without authenticating producers or approving merge", diagnostics: []},
    {ruleId: "proofkit.producer-policy-self-proof.receipts", status: failures.length ? "failed" : "passed", message: "merge-obligation receipt refs must not use producer tuples newly admitted by the same producer-policy change",
      diagnostics: failures.map((value, i) => ({key: `failure.${String(i + 1).padStart(3, "0")}`, value}))},
  ]);
}
function migrationSemantics(input, output) {
  const owners = new Set(input.sourceProofOwners.map(x => x.ownerId)), targets = new Set(input.targetProofkitRefs.map(x => x.targetId));
  const records = [...input.parityRecords].sort((a, b) => utf8Order(a.evidenceId, b.evidenceId)).map(x => {
    const findings = [];
    if (!owners.has(x.sourceOwnerId)) findings.push(`migration parity record ${x.evidenceId} references unknown source owner: ${x.sourceOwnerId}`);
    if (!targets.has(x.targetId)) findings.push(`migration parity record ${x.evidenceId} references unknown target: ${x.targetId}`);
    if (x.status === "caller_declared_match" && x.legacyDigest !== x.proofkitDigest) findings.push(`migration parity record ${x.evidenceId} declares a match but digests differ`);
    if (x.status === "caller_declared_mismatch" && x.legacyDigest === x.proofkitDigest) findings.push(`migration parity record ${x.evidenceId} declares a mismatch but digests are equal`);
    if (x.status !== "caller_declared_match") findings.push(`migration parity record ${x.evidenceId} is not admitted: ${x.status}`);
    return {...x, evidenceRefs: sortedText(x.evidenceRefs), receiptRefs: [...x.receiptRefs].sort(utf8Order), nonClaims: sortedText(x.nonClaims),
      legacySubjectRef: normalizedText(x.legacySubjectRef), proofkitSubjectRef: normalizedText(x.proofkitSubjectRef), reason: normalizedText(x.reason), findings: findings.sort(utf8Order)};
  });
  const failures = records.flatMap(x => x.findings), admitted = records.filter(x => !x.findings.length);
  assert.equal(output.reportId, input.paritySetId); assert.equal(output.state, failures.length ? "failed" : "passed");
  assert.deepEqual(output.summary, {admittedParityClaimCount: admitted.length, failureCount: failures.length, parityRecordCount: records.length,
    sourceProofOwnerCount: owners.size, targetProofkitRefCount: targets.size,
    ...Object.fromEntries([["caller_declared_match", "callerDeclaredMatchCount"], ["caller_declared_mismatch", "callerDeclaredMismatchCount"],
      ["caller_declared_not_comparable", "callerDeclaredNotComparableCount"], ["caller_declared_not_run", "callerDeclaredNotRunCount"]].map(([status, key]) => [key, records.filter(x => x.status === status).length]))});
  assert.deepEqual(output.diagnostics, [{key: "admittedParityClaimRefs", value: admitted.map(x => Object.fromEntries(["equivalenceKind", "evidenceId", "evidenceRefs", "receiptRefs", "sourceOwnerId", "targetId"].map(key => [key, x[key]])))},
    {key: "failures", value: failures}, {key: "migrationParity", value: records}]);
  assert.deepEqual(output.ruleResults, records.map(x => ({ruleId: "proofkit.migration-parity-admission.record." + x.evidenceId,
    status: x.findings.length ? "failed" : "passed", message: x.findings.length ? "caller-declared migration parity claim is not admitted" : "caller-declared migration parity claim is admitted",
    diagnostics: x.findings.length ? [{key: "findings", value: x.findings}] : []})));
}
function semantics(command, input, output) {
  assert.equal(output.schemaVersion, 1); assert.equal(output.reportKind, "proofkit." + command);
  (command === producer ? producerSemantics : migrationSemantics)(input, output);
  assert.deepEqual(output.nonClaims, [...builtin[command], ...sortedText(input.nonClaims)].sort(utf8Order));
}

test("authority guards conserve75predecessor streams and independently check native report meanings", () => {
  for (const row of baseline.observations) {
    const result = invoke(row.command, row.input, row.argv);
    assert.equal(result.status, row.exitCode, row.name); assert.equal(hash(result.stderr), row.stderrSHA256, row.name + "/stderr");
    if (row.help) {
      assert.equal(hash(row.predecessorHelp), row.stdoutSHA256);
      const id = `proofkit.${row.command}.input.v1`;
      let expected = row.predecessorHelp.replace(`root-shape-only definition ${id}.root-shape; nested fields, types, and cardinalities are non-claims`,
        `structural JSON Schema definition ${id}.json-schema; canonicalization and semantic validity remain native admission obligations`);
      if (row.command === migration) expected = expected.replace("  paritySetId\n  sourceProofOwners[]\n  targetProofkitRefs[]\n  parityRecords[]\n  nonClaims[]\n", "");
      const keys = row.command === producer ? "admissionChanges[], baselinePolicyDigest, guardId, mergeObligationReceiptRefs[], nonClaimRefs[], nonClaims[], policyChangeDigest, policyChangeId, policyId, policyOwner, policySurfaceRefs[], proposedPolicyDigest" : "nonClaims[], parityRecords[], paritySetId, sourceProofOwners[], targetProofkitRefs[]";
      assert.equal(result.stdout, expected.replace("\n\nPublic contract:", "\n  root fields: " + keys + "\n\nPublic contract:"));
    } else assert.equal(hash(result.stdout), row.stdoutSHA256, row.name + "/stdout");
    if (!row.report) continue;
    const input = row.name === "pointer" ? JSON.parse(row.input).payload : JSON.parse(row.input), output = JSON.parse(result.stdout);
    assert.equal(validators[row.command].input(input), true, row.name + "/input");
    assert.equal(validators[row.command].output(output), true, row.name + "/output"); semantics(row.command, input, output);
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
const validInput = command => JSON.parse(baseline.observations.find(x => x.command === command && x.name === "valid").input);
test("authority guard nested predicates have populated positive and negative specimens", () => {
  for (const command of [producer, migration]) {
    const rows = baseline.observations.filter(x => x.command === command && x.report);
    const outputs = rows.map(row => JSON.parse(invoke(command, row.input, row.argv).stdout));
    const inputs = rows.map(row => row.name === "pointer" ? JSON.parse(row.input).payload : JSON.parse(row.input));
    // Include empty collections, nullable input and populated failure records, not just happy-path output.
    for (const [direction, specimens] of [["input", inputs], ["output", outputs]]) for (const specimen of specimens) {
      const valid = validators[command][direction]; assert.equal(valid(specimen), true);
      for (const {path, value} of paths(specimen)) {
        if (value && !Array.isArray(value) && typeof value === "object") {
          const unknown = structuredClone(specimen); at(unknown, path).foreign = true;
          assert.equal(valid(unknown), false, `${command}/${direction}/${path}/unknown`);
          for (const key of Object.keys(value)) {
            const missing = structuredClone(specimen); delete at(missing, path)[key];
            assert.equal(valid(missing), false, `${command}/${direction}/${path}/${key}/missing`);
          }
        }
        if (!path.length) continue;
        const nullable = direction === "input" && command === producer && path.at(-1) === "fromAdmissionLevel";
        assert.equal(valid(replace(specimen, path, null)), nullable, `${command}/${direction}/${path}/null`);
        const wrongType = typeof value === "string" ? 0 : "wrong-type";
        assert.equal(valid(replace(specimen, path, wrongType)), false, `${command}/${direction}/${path}/type`);
        if (typeof value === "string") assert.equal(valid(replace(specimen, path, "")), false, `${command}/${direction}/${path}/blank`);
        if (typeof value === "number") for (const wrong of [-1, 1.5]) assert.equal(valid(replace(specimen, path, wrong)), false, `${command}/${direction}/${path}/integer`);
      }
    }
    const output = outputs[0];
    for (const wrong of [output.diagnostics.slice(1), [...output.diagnostics, output.diagnostics[0]], [...output.diagnostics].reverse()]) assert.equal(validators[command].output({...output, diagnostics: wrong}), false);
    assert.equal(validators[command].output({...output, nonClaims: output.nonClaims.filter(x => x !== builtin[command][0])}), false);
    const overlap = outputs[rows.findIndex(x => x.name === "builtin-overlap")];
    assert.equal(overlap.nonClaims.filter(x => x === builtin[command][1]).length, 2);
    const input = inputs[0];
    const idKey = command === producer ? "guardId" : "paritySetId";
    for (const wrong of ["a".repeat(257), "foreign/id", " id "]) assert.equal(validators[command].input({...input, [idKey]: wrong}), false);
  }
  const p = validInput(producer), m = validInput(migration);
  for (const path of [["admissionChanges"], ["mergeObligationReceiptRefs"], ["nonClaimRefs"], ["nonClaims"]]) assert.equal(validators[producer].input(replace(p, path, [])), true);
  for (const path of [["policySurfaceRefs"], ["admissionChanges", 0, "evidenceRefs"]]) assert.equal(validators[producer].input(replace(p, path, [])), false);
  for (const path of [["sourceProofOwners"], ["targetProofkitRefs"], ["parityRecords"], ["parityRecords", 0, "nonClaims"], ["parityRecords", 0, "evidenceRefs"]]) assert.equal(validators[migration].input(replace(m, path, [])), false);
  for (const path of [["nonClaims"], ["parityRecords", 0, "receiptRefs"]]) assert.equal(validators[migration].input(replace(m, path, [])), true);
  for (const [command, value, path] of [[producer, p, ["admissionChanges", 0, "changeKind"]], [producer, p, ["mergeObligationReceiptRefs", 0, "receiptStatus"]],
    [producer, p, ["admissionChanges", 0, "toAdmissionLevel"]], [migration, m, ["parityRecords", 0, "status"]], [migration, m, ["parityRecords", 0, "equivalenceKind"]],
    [migration, m, ["sourceProofOwners", 0, "ownerKind"]], [migration, m, ["targetProofkitRefs", 0, "targetKind"]]]) {
    for (const wrong of ["foreign", " " + at(value, path) + " "]) assert.equal(validators[command].input(replace(value, path, wrong)), false, `${command}/${path}/domain`);
  }
  for (const [command, value, path] of [[producer, p, ["baselinePolicyDigest"]], [migration, m, ["parityRecords", 0, "legacyDigest"]]]) {
    for (const wrong of ["sha256:" + "A".repeat(64), "sha256:" + "a".repeat(63), "sha256:" + "a".repeat(64) + "\n"]) assert.equal(validators[command].input(replace(value, path, wrong)), false);
  }
});

test("producer tuple identity is injective despite admitted path delimiter collisions", () => {
  const input = validInput(producer), change = input.admissionChanges[0], receipt = input.mergeObligationReceiptRefs[0];
  receipt.producerId = change.producerId;
  change.provenanceRuleRef = "docs/a|b"; change.artifactRetentionRuleRef = "docs/c";
  receipt.provenanceRuleRef = "docs/a"; receipt.artifactRetentionRuleRef = "b|docs/c";
  assert.notDeepEqual(tuple(change, change.toAdmissionLevel), tuple(receipt, receipt.producerAdmissionClass));
  assert.equal(tuple(change, change.toAdmissionLevel).join("|"), tuple(receipt, receipt.producerAdmissionClass).join("|"));
  function check(expectedCode, count) {
    assert.equal(validators[producer].input(input), true);
    const result = invoke(producer, JSON.stringify(input)); assert.equal(result.status, expectedCode); assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout); assert.equal(validators[producer].output(output), true); producerSemantics(input, output);
    assert.equal(output.summary.newlyMergeSatisfyingTupleCount, count);
  }
  check(0, 1);
  receipt.provenanceRuleRef = change.provenanceRuleRef; receipt.artifactRetentionRuleRef = change.artifactRetentionRuleRef; check(1, 1);
  input.admissionChanges.push({...structuredClone(change), changeId: "change.other", provenanceRuleRef: "docs/a", artifactRetentionRuleRef: "b|docs/c"}); check(1, 2);
});

test("mixed raw IDs preserve native ordinal record order", () => {
  for (const command of [producer, migration]) {
    const input = validInput(command);
    if (command === producer) {
      const base = input.mergeObligationReceiptRefs[0]; base.producerId = input.admissionChanges[0].producerId;
      input.mergeObligationReceiptRefs = ["receipt.a", "receipt._", "receipt.A"].map(receiptId => ({...structuredClone(base), receiptId}));
    } else {
      const base = input.parityRecords[0];
      input.parityRecords = ["evidence.a", "evidence._", "evidence.A"].map(evidenceId => ({...structuredClone(base), evidenceId}));
    }
    assert.equal(validators[command].input(input), true);
    const result = invoke(command, JSON.stringify(input));
    assert.equal(result.status, command === producer ? 1 : 0); assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout); assert.equal(validators[command].output(output), true);
    const key = command === producer ? "selfProofReceipts" : "migrationParity", id = command === producer ? "receiptId" : "evidenceId";
    assert.deepEqual(output.diagnostics.find(x => x.key === key).value.map(x => x[id]), command === producer ? ["receipt.A", "receipt._", "receipt.a"] : ["evidence.A", "evidence._", "evidence.a"]);
    semantics(command, input, output);
  }
});

test("Unicode caller text preserves native trim and UTF8 order", () => {
  for (const command of [producer, migration]) {
    const input = validInput(command);
    input.nonClaims = command === producer ? ["\u0085Alpha\u0085", "\uE000 text", "\uFEFFBeta\uFEFF", "\u{10000} text"] : ["\u{10000} text", "\u0085Alpha\u0085", "\uFEFFBeta\uFEFF", "\uE000 text"];
    if (command === producer) input.policyOwner = "\u0085owner\u0085";
    else {
      input.parityRecords[0].reason = "\u0085Reason\u0085";
      input.parityRecords[0].legacySubjectRef = "\uFEFFSubject\uFEFF";
      input.parityRecords[0].nonClaims = ["\u{10000} inner", "\uE000 inner"];
    }
    assert.equal(validators[command].input(input), true);
    const result = invoke(command, JSON.stringify(input));
    assert.equal(result.status, 0); assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout); assert.equal(validators[command].output(output), true);
    assert.ok(output.nonClaims.includes("Alpha")); assert.ok(output.nonClaims.includes("\uFEFFBeta\uFEFF"));
    assert.deepEqual(output.nonClaims.filter(x => x.endsWith(" text")), ["\uE000 text", "\u{10000} text"]);
    semantics(command, input, output);
  }
});
