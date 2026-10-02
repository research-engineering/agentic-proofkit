import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import test, {before, after} from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const contract = JSON.parse(readFileSync(process.env.PROOFKIT_REPORT_ADMISSION_CONTRACT || new URL("proofkit/cli-contract.v2.json", root), "utf8"));
const corpus = JSON.parse(readFileSync(new URL("internal/app/testdata/report-admission-native-observations.json", root), "utf8"));
assert.equal(corpus.sourceCommit, "ae15909a7c211d0abf31e83ba82acf21f52a2911");
assert.equal(corpus.observations.length, 111);
const ajv = new Ajv2020({strict: false, allErrors: false, validateFormats: false});
const commands = ["adoption-checklist", "binding-partition", "completion-criteria", "package-runtime-dependency-admission", "proof-obligation-algebra", "text-policy"];
const families = Object.fromEntries(commands.map(command => [command, {
  command, rows: corpus.observations.filter(row => row.command === command),
  ...Object.fromEntries(["input", "output"].map(direction => {
    const definition = contract.contractDefinitions.find(row => row.definitionId === `proofkit.${command}.${direction}.v1.json-schema`);
    assert.ok(definition, `${command}/${direction}`);
    return [direction, ajv.compile(definition.fieldTree.variants[0].schema)];
  })),
}]));
let directory, binary;
before(() => {
  directory = mkdtempSync(join(tmpdir(), "proofkit-report-admission-"));
  binary = join(directory, "agentic-proofkit");
  execFileSync("go", ["build", "-mod=readonly", "-o", binary, "./cmd/agentic-proofkit"], {
    cwd: root, timeout: 120_000, maxBuffer: 2 << 20,
    env: {...process.env, GOPROXY: "off", GOSUMDB: "off", GOTOOLCHAIN: "local"},
  });
});
after(() => { if (directory) rmSync(directory, {recursive: true, force: true}); });
const sha256 = value => createHash("sha256").update(value).digest("hex");
const seed = command => structuredClone(families[command].rows.find(row => row.name === "positive").input);
const at = (value, path) => path.reduce((record, key) => record[key], value);
function paths(value, predicate, path = []) {
  if (value === null || typeof value !== "object") return [];
  return [...(predicate(value) ? [path] : []), ...Object.entries(value).flatMap(([key, child]) => paths(child, predicate, [...path, key]))];
}
const objects = value => paths(value, value => !Array.isArray(value));
const arrays = value => paths(value, Array.isArray);
const wrongType = value => typeof value === "string" ? 0 : typeof value === "number" || typeof value === "boolean" ? "wrong-type" : value === null ? false : Array.isArray(value) ? {} : [];
function native(family, input, expected, label, extra = []) {
  const result = spawnSync(binary, [family.command, "--input", "-", ...extra], {
    input: typeof input === "string" ? input : JSON.stringify(input), encoding: "utf8", timeout: 10_000, maxBuffer: 8 << 20,
  });
  assert.equal(result.error, undefined, `${label}/transport-error`);
  assert.equal(result.signal, null, `${label}/transport-signal`);
  if (expected === "rejected") {
    assert.equal(result.status, 1, label);
    assert.equal(result.stdout, "", label);
    assert.notEqual(result.stderr, "", label);
    return result;
  }
  assert.ok(result.status === 0 || result.status === 1, label);
  assert.equal(result.stderr, "", `${label}/stderr`);
  const output = JSON.parse(result.stdout);
  assert.equal(output.reportKind, `proofkit.${family.command}${family.command === "binding-partition" ? "-admission" : ""}`, label);
  assert.equal(output.state, result.status === 0 ? "passed" : "failed", label);
  if (expected) assert.equal(output.state, expected, label);
  assert.equal(family.output(output), true, `${label}: ${ajv.errorsText(family.output.errors)}`);
  return {...result, output};
}
function pair(command, input, expected, label) {
  const family = families[command];
  assert.equal(family.input(input), expected !== "rejected", `${label}: ${ajv.errorsText(family.input.errors)}`);
  return native(family, input, expected, label);
}
const nullableInput = (command, path) => {
  const key = path.at(-1);
  return (command === "adoption-checklist" || command === "completion-criteria") && key === "blocker"
    || command === "binding-partition" && (key === "reviewConditionRef" || path[0] === "surfaceThresholds" && key !== "surfaceId")
    || command === "package-runtime-dependency-admission" && (key === "dependencySpec" || path[0] === "admissibleLocations")
    || command === "proof-obligation-algebra" && ["expiryRef", "reviewConditionRef"].includes(key);
};

test("positive native predecessors remain admitted under isolated schema controls", () => {
  for (const family of Object.values(families)) {
    const row = family.rows.find(row => row.name === "positive");
    const result = pair(family.command, row.input, "passed", family.command);
    assert.equal(sha256(result.stdout), row.stdoutSHA256, family.command);
  }
});

test("all predecessor wire observations survive exact whole-CLI execution", () => {
  for (const row of corpus.observations) {
    const family = families[row.command], label = `${row.command}/${row.name}`;
    // Whitespace canonicalization is a native-only constraint, not a schema claim.
    assert.equal(family.input(row.input), row.expected !== "rejected" || row.name === "caller-denial-whitespace", label);
    const result = native(family, row.input, row.expected, label);
    assert.equal(result.status, row.exitCode, label);
    assert.equal(result.stderr, row.stderr, label);
    assert.equal(sha256(result.stdout), row.stdoutSHA256, `${label}/predecessor-bytes`);
  }
});

test("input objects reject unknown members and preserve required/nullable/type partitions", () => {
  for (const family of Object.values(families)) {
    const samples = family.rows.filter(row => row.name === "positive" || row.name === "crossing-with-delegation" || row.name.startsWith("single-max"));
    const visited = new Set();
    for (const row of samples) for (const path of objects(row.input)) {
      const signature = path.join("/");
      if (visited.has(signature)) continue;
      visited.add(signature);
      const unknown = structuredClone(row.input);
      at(unknown, path).unexpected = true;
      pair(family.command, unknown, "rejected", `${family.command}/${path}/unknown`);
      for (const [key, value] of Object.entries(at(row.input, path))) {
        const nullable = nullableInput(family.command, [...path, key]);
        const optional = nullable || family.command === "text-policy" && key === "contentBase64";
        for (const mode of ["wrong-type", ...(!optional ? ["missing"] : []), ...(!nullable ? ["null"] : [])]) {
          const input = structuredClone(row.input), object = at(input, path);
          if (mode === "missing") delete object[key];
          if (mode === "null") object[key] = null;
          if (mode === "wrong-type") object[key] = wrongType(value);
          pair(family.command, input, "rejected", `${family.command}/${path}/${key}/${mode}`);
        }
      }
    }
  }
});

test("array items are typed independently of list cardinality", () => {
  for (const family of Object.values(families)) {
    for (const row of family.rows.filter(row => ["positive", "crossing-with-delegation", "single-maxCohesionGroupCount"].includes(row.name))) {
      for (const path of arrays(row.input)) for (const item of [null, false, 0, [], "", {}]) {
        const input = structuredClone(row.input);
        at(input, path).push(item);
        pair(family.command, input, "rejected", `${family.command}/${path}/item/${JSON.stringify(item)}`);
      }
    }
  }
});

test("optional members and conditional evidence guards match native admission", () => {
  for (const command of ["adoption-checklist", "completion-criteria"]) {
    const list = command === "adoption-checklist" ? "items" : "criteria";
    for (const blocker of [undefined, null]) {
      const input = seed(command);
      if (blocker === undefined) delete input[list][0].blocker; else input[list][0].blocker = blocker;
      pair(command, input, "passed", `${command}/optional-blocker`);
    }
    const missingEvidence = seed(command);
    missingEvidence[list][0].evidenceRefs = [];
    pair(command, missingEvidence, "rejected", `${command}/satisfied-needs-evidence`);
    const unexpectedBlocker = seed(command);
    unexpectedBlocker[list][0].blocker = "An actual precondition is missing.";
    pair(command, unexpectedBlocker, "rejected", `${command}/nonblocked-forbids-blocker`);
    const blocked = seed(command);
    blocked[list][0].status = command === "adoption-checklist" ? "blocked" : "blocked_missing_precondition";
    for (const blocker of [undefined, null, ""]) {
      if (blocker === undefined) delete blocked[list][0].blocker; else blocked[list][0].blocker = blocker;
      pair(command, blocked, "rejected", `${command}/blocked-needs-blocker`);
    }
  }
  const completion = seed("completion-criteria");
  completion.criteria[0].proofRefs = [];
  completion.criteria[0].validatorRefs = [];
  pair("completion-criteria", completion, "rejected", "criterion-needs-proof-or-validator");
  for (const field of ["proofRefs", "validatorRefs"]) {
    const input = structuredClone(completion);
    input.criteria[0][field] = ["proof.executable"];
    pair("completion-criteria", input, "passed", `criterion-${field}-alone`);
  }
  for (const field of ["maxCohesionGroupCount", "maxOwnedProofRouteCount", "maxOwnedSelectorCount"]) {
    for (const value of [0, -1, 1.5, "1", {}, []]) {
      const input = seed("binding-partition");
      input.surfaceThresholds = [{surfaceId: input.bindingSurfaces[0].surfaceId, [field]: value}];
      pair("binding-partition", input, "rejected", `threshold/${field}/${JSON.stringify(value)}`);
    }
  }
});

test("finite vocabularies, ID bounds and required list minima have isolated controls", () => {
  const requiredLists = {
    "adoption-checklist": [["items"], ["requiredItemIds"], ["nonClaims"], ["items", 0, "nonClaims"]],
    "binding-partition": [["bindingSurfaces"], ["routeOwners"], ["proofRouteRefs"], ["nonClaims"], ["bindingSurfaces", 0, "selectorRefs"], ["routeOwners", 0, "selectorRefs"]],
    "completion-criteria": [["criteria"], ["nonClaims"], ["criteria", 0, "failsWhen"], ["criteria", 0, "nonClaims"]],
    "package-runtime-dependency-admission": [],
    "proof-obligation-algebra": [["obligations"], ["nonClaims"], ["obligations", 0, "nonClaims"]],
    "text-policy": [],
  };
  const enumPaths = {
    "adoption-checklist": [["scenario"], ["items", 0, "status"]],
    "binding-partition": [], "package-runtime-dependency-admission": [],
    "completion-criteria": [["criteria", 0, "criterionClass"], ["criteria", 0, "status"]],
    "proof-obligation-algebra": [["obligations", 0, "obligationKind"]], "text-policy": [["files", 0, "state"]],
  };
  for (const family of Object.values(families)) {
    const input = seed(family.command), identity = Object.keys(input).find(key => key.endsWith("Id"));
    assert.ok(identity);
    input[identity] = "x".repeat(256);
    pair(family.command, input, "passed", `${family.command}/max-root-id`);
    for (const id of ["", "x".repeat(257), "invalid id", "invalid/segment"]) {
      input[identity] = id;
      pair(family.command, input, "rejected", `${family.command}/invalid-root-id/${id.length}`);
    }
    for (const path of requiredLists[family.command]) {
      const changed = seed(family.command);
      at(changed, path).length = 0;
      pair(family.command, changed, "rejected", `${family.command}/${path}/minimum`);
    }
    for (const path of enumPaths[family.command]) {
      const changed = seed(family.command);
      at(changed, path.slice(0,-1))[path.at(-1)] = "unsupported-value";
      pair(family.command, changed, "rejected", `${family.command}/${path}/enum`);
    }
  }
  const binding = structuredClone(families["binding-partition"].rows.find(row => row.name === "crossing-with-delegation").input);
  for (const key of ["evidenceRefs", "nonClaims", "proofRouteRefs"]) {
    const changed = structuredClone(binding);
    changed.delegations[0][key] = [];
    pair("binding-partition", changed, "rejected", `delegation/${key}/minimum`);
  }
});

test("report builtin denials, identity, booleans and derived rule IDs remain bounded", () => {
  for (const family of Object.values(families)) {
    const output = native(family, seed(family.command), "passed", family.command).output;
    const rootId = structuredClone(output);
    rootId.reportId = "x".repeat(256);
    assert.equal(family.output(rootId), true);
    for (const invalid of ["", "x".repeat(257), "invalid id"]) {
      rootId.reportId = invalid;
      assert.equal(family.output(rootId), false, `${family.command}/reportId`);
    }
    const caller = seed(family.command).nonClaims;
    const duplicated = structuredClone(output);
    duplicated.nonClaims.push(duplicated.nonClaims[0]);
    assert.equal(family.output(duplicated), ["package-runtime-dependency-admission", "text-policy"].includes(family.command), `${family.command}/output-claim-uniqueness`);
    for (const claim of output.nonClaims.filter(value => !caller.includes(value))) {
      const changed = structuredClone(output);
      changed.nonClaims = changed.nonClaims.map(value => value === claim ? "A different non-authoritative statement." : value);
      assert.equal(family.output(changed), false, `${family.command}/required-builtin`);
    }
    for (const path of objects(output)) for (const [key, value] of Object.entries(at(output, path))) {
      if (typeof value === "boolean") for (const boolean of [false, true]) {
        const changed = structuredClone(output);
        at(changed, path)[key] = boolean;
        assert.equal(family.output(changed), true, `${family.command}/${path}/${key}/boolean`);
      }
      if (typeof value === "number") {
        const changed = structuredClone(output);
        at(changed, path)[key] = 1e20;
        assert.equal(family.output(changed), false, `${family.command}/${path}/${key}/above-int64`);
      }
    }
    for (let index = 0; index < output.ruleResults.length; index++) {
      const changed = structuredClone(output);
      changed.ruleResults[index].ruleId = "invalid rule";
      assert.equal(family.output(changed), false, `${family.command}/rule-id`);
    }
  }
});

test("output vocabularies and prefixed identities reject unsupported values and overflow", () => {
  const prefixed = {
    "binding-partition": ["proofkit.binding-partition.route-owner.", "proofkit.binding-partition.route-reference.", "proofkit.binding-partition.surface."],
    "completion-criteria": ["proofkit.completion-criteria."],
    "proof-obligation-algebra": ["proofkit.proof-obligation-algebra."],
  };
  for (const family of Object.values(families)) {
    const input = family.command === "binding-partition" ? family.rows.find(row => row.name === "crossing-with-delegation").input : seed(family.command);
    const output = native(family, input, "passed", family.command).output;
    for (const version of [0, 2]) {
      const changed = structuredClone(output);
      changed.schemaVersion = version;
      assert.equal(family.output(changed), false, `${family.command}/output-version`);
    }
    for (const path of objects(output)) for (const key of Object.keys(at(output, path))) {
      if (["state", "status", "scenario", "criterionClass", "obligationKind", "mode"].includes(key)) {
        const changed = structuredClone(output);
        at(changed, path)[key] = "unsupported-value";
        assert.equal(family.output(changed), false, `${family.command}/${path}/${key}/enum`);
      }
    }
    for (const prefix of prefixed[family.command] || []) {
      const index = output.ruleResults.findIndex(row => row.ruleId.startsWith(prefix));
      assert.notEqual(index, -1, `${family.command}/${prefix}/positive-rule`);
      const changed = structuredClone(output);
      changed.ruleResults[index].ruleId = prefix + "x".repeat(256);
      assert.equal(family.output(changed), true, `${family.command}/${prefix}/maximum`);
      changed.ruleResults[index].ruleId += "x";
      assert.equal(family.output(changed), false, `${family.command}/${prefix}/overflow`);
    }
  }
});

test("positive report counts reject zero independently of schema declarations", () => {
  const positiveCounts = {
    "adoption-checklist": ["itemCount", "requiredItemCount"],
    "binding-partition": ["proofRouteCount", "surfaceCount"],
    "completion-criteria": ["criterionCount"],
    "proof-obligation-algebra": ["obligationCount"],
  };
  for (const [command, keys] of Object.entries(positiveCounts)) {
    const family = families[command], output = native(family, seed(command), "passed", command).output;
    for (const key of keys) {
      const changed = structuredClone(output);
      changed.summary[key] = 1;
      assert.equal(family.output(changed), true, `${command}/${key}/at-minimum`);
      changed.summary[key] = 0;
      assert.equal(family.output(changed), false, `${command}/${key}/below-minimum`);
    }
  }
});

test("all report members, array elements and integer counts reject structural counterexamples", () => {
  const nullable = new Set(["blocker", "expiryRef", "reviewConditionRef", "graphDepth", "canonicalOwnerId", "canonicalSurfaceId"]);
  for (const family of Object.values(families)) {
    const visited = new Set();
    for (const row of family.rows.filter(row => row.expected !== "rejected")) {
      const output = native(family, row.input, row.expected, row.name).output;
      for (const path of objects(output)) {
        const signature = JSON.stringify([path, Object.entries(at(output, path)).map(([key, value]) => [key, value === null ? "null" : Array.isArray(value) ? "array" : typeof value])]);
        if (visited.has(signature)) continue;
        visited.add(signature);
        const unknown = structuredClone(output);
        at(unknown, path).unexpected = true;
        assert.equal(family.output(unknown), false, `${family.command}/${path}/unknown`);
        for (const [key, value] of Object.entries(at(output, path))) {
          for (const mode of ["missing", "wrong-type", ...(!nullable.has(key) ? ["null"] : [])]) {
            const changed = structuredClone(output), object = at(changed, path);
            if (mode === "missing") delete object[key];
            if (mode === "wrong-type") object[key] = wrongType(value);
            if (mode === "null") object[key] = null;
            assert.equal(family.output(changed), false, `${family.command}/${path}/${key}/${mode}`);
          }
          if (typeof value === "number") for (const invalid of [-1, 0.5]) {
            const changed = structuredClone(output);
            at(changed, path)[key] = invalid;
            assert.equal(family.output(changed), false, `${family.command}/${path}/${key}/${invalid}`);
          }
        }
      }
      for (const path of arrays(output)) {
        const signature = `array/${path}`;
        if (visited.has(signature)) continue;
        visited.add(signature);
        for (const index of at(output, path).length ? at(output, path).map((_, index) => index) : [0]) {
          for (const item of [null, false, 0, [], "", {}]) {
            const changed = structuredClone(output);
            at(changed, path)[index] = item;
            assert.equal(family.output(changed), false, `${family.command}/${path}/${index}/item`);
          }
        }
      }
    }
  }
});

test("finite report count maxima preserve exact declared neighbors", () => {
  const command = "package-runtime-dependency-admission", family = families[command], input = seed(command);
  Object.assign(input.packageResolution, {
    packageName: "different-package", packageVersion: "0.2.0", dependencySpec: null,
    lockfileEntryPresent: false, lockfileIntegrity: "sha512-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  });
  input.admissibleLocations = {};
  const failed = pair(command, input, "failed", "six-independent-package-failures").output;
  assert.equal(failed.summary.failureCount, 6);
  failed.summary.failureCount = 7;
  assert.equal(family.output(failed), false, "package/failureCount/over-maximum");

  const algebra = families["proof-obligation-algebra"];
  const output = native(algebra, seed(algebra.command), "passed", "algebra-count-seed").output;
  const targets = [
    ...["failedObligationCount", "nonRouteBearingObligationCount", "obligationCount", "routeBearingObligationCount", "rootObligationCount"].map(key => ["summary", key]),
    ...["all_of", "any_of", "atomic", "conditional", "deferred", "waived_until"].map(key => ["summary", "kindCounts", key]),
    ...objects(output).filter(path => Object.hasOwn(at(output, path), "graphDepth")).map(path => [...path, "graphDepth"]),
  ];
  for (const path of targets) {
    const changed = structuredClone(output), object = at(changed, path.slice(0, -1)), key = path.at(-1);
    object[key] = 2048;
    assert.equal(algebra.output(changed), true, `algebra/${path}/at-maximum`);
    object[key] = 2049;
    assert.equal(algebra.output(changed), false, `algebra/${path}/over-maximum`);
  }
});

test("nested text and identifier domains reject empty, malformed and oversized values", () => {
  const ids = {
    "adoption-checklist": new Set(["reportId", "checklistId", "itemId", "requiredItemIds", "blockedRequiredItemIds", "missingRequiredItemIds", "notApplicableRequiredItemIds"]),
    "binding-partition": new Set(["reportId", "partitionId", "ownerId", "surfaceId", "selectorRefs", "cohesionGroupId", "proofRouteRef", "proofRouteRefs", "referenceId", "referenceIds", "referrerOwnerId", "referrerSurfaceId", "delegationRef", "delegationRefs", "reviewConditionRef", "fromOwnerId", "fromSurfaceId", "toOwnerId", "toSurfaceId", "canonicalOwnerId", "canonicalSurfaceId", "matchedDelegationRefs", "cohesionGroupIds", "ownedProofRouteRefs", "ownedSelectorRefs", "failedProofRouteRefs", "failedSurfaceIds"]),
    "completion-criteria": new Set(["reportId", "completionId", "criterionId", "blockingUnsatisfiedCriterionIds"]),
    "package-runtime-dependency-admission": new Set(["reportId"]),
    "proof-obligation-algebra": new Set(["reportId", "algebraId", "obligationId", "requirementId", "childObligationIds", "conditionRefs", "delegationRefs", "proofRouteRefs", "transitiveChildObligationIds", "failedObligationIds", "nonRouteBearingObligationIds", "rootObligationIds"]),
    "text-policy": new Set(["reportId"]),
  };
  for (const family of Object.values(families)) {
    const visited = new Set();
    for (const row of family.rows.filter(row => row.expected !== "rejected")) {
      const output = native(family, row.input, row.expected, row.name).output;
      for (const [direction, original] of [["input", row.input], ["output", output]]) {
        const targets = [];
        for (const path of objects(original)) for (const [key, value] of Object.entries(at(original, path))) {
          const nullableText = value === null && ["blocker", "expiryRef", "reviewConditionRef", "canonicalOwnerId", "canonicalSurfaceId", "dependencySpec", "expectedPackageRoot", "localWorkspaceRoot", "nodeModulesRoot"].includes(key);
          if ((typeof value === "string" || nullableText) && key !== "contentBase64") targets.push({path: [...path, key], id: ids[family.command].has(key)});
        }
        for (const path of arrays(original)) {
          const parent = at(original, path.slice(0,-1));
          const name = path.at(-1) === "value" && typeof parent.key === "string" ? parent.key : path.at(-1);
          // Empty ID arrays still need an element-grammar counterexample.
          if (ids[family.command].has(name)) targets.push({path: [...path, 0], id: true});
          else for (let index = 0; index < at(original, path).length; index++) if (typeof at(original, path)[index] === "string") targets.push({path: [...path, index], id: false});
        }
        for (const target of targets) for (const value of ["", ...(target.id ? ["invalid id", "x".repeat(257), "valid\n"] : [])]) {
          const key = JSON.stringify([direction, target.path, value.length, value.includes(" "), value.includes("\n")]);
          if (visited.has(key)) continue;
          visited.add(key);
          const changed = structuredClone(original);
          at(changed, target.path.slice(0,-1))[target.path.at(-1)] = value;
          assert.equal(family[direction](changed), false, `${family.command}/${direction}/${target.path}/lexical`);
          if (direction === "input") native(family, changed, "rejected", `${family.command}/${target.path}/native-lexical`);
        }
      }
    }
  }
  for (const path of [["expectedPackageName"], ["packageResolution", "packageName"], ["expectedLockfileIntegrity"], ["packageResolution", "lockfileIntegrity"], ["expectedDependencySpec"], ["packageResolution", "dependencySpec"]]) {
    const input = seed("package-runtime-dependency-admission"), key = path.at(-1);
    at(input, path.slice(0,-1))[key] = /name/i.test(key) ? "UPPERCASE" : /integrity/i.test(key) ? "not-integrity" : "value\n";
    pair("package-runtime-dependency-admission", input, "rejected", `${path}/grammar`);
  }
});

test("output array minima and fixed tuple lengths are independently enforced", () => {
  const diagnosticCounts = {"adoption-checklist": 1, "binding-partition": 5, "completion-criteria": 2, "package-runtime-dependency-admission": 11, "proof-obligation-algebra": 4, "text-policy": 1};
  const ruleMinima = {"adoption-checklist": 1, "binding-partition": 2, "completion-criteria": 1, "package-runtime-dependency-admission": 4, "proof-obligation-algebra": 1, "text-policy": 1};
  const nonemptyFields = {
    "adoption-checklist": new Set(["items", "requiredItemIds", "nonClaims"]),
    "binding-partition": new Set(["selectorRefs", "ownedSelectorRefs"]),
    "completion-criteria": new Set(["failsWhen", "nonClaims"]),
    "package-runtime-dependency-admission": new Set(),
    "proof-obligation-algebra": new Set(["nonClaims"]), "text-policy": new Set(),
  };
  for (const family of Object.values(families)) {
    const input = seed(family.command), output = native(family, input, "passed", family.command).output;
    const minima = [[['diagnostics'], diagnosticCounts[family.command]], [['ruleResults'], ruleMinima[family.command]]];
    for (const path of arrays(output)) {
      if (path[0] === "ruleResults" && path.at(-1) === "diagnostics") minima.push([path, at(output, path).length]);
      if (path.length > 1 && nonemptyFields[family.command].has(path.at(-1))) {
        // The missing-owner placeholder alone permits empty selectorRefs.
        if (family.command === "binding-partition" && path.at(-1) === "selectorRefs" && at(output, path.slice(0,-1)).proofRouteRef) continue;
        minima.push([path, 1]);
      }
      if (path.length === 3 && path[0] === "diagnostics" && path[2] === "value" && ["routeOwnership", "surfaceDiagnostics", "criteria", "obligations"].includes(output.diagnostics[path[1]].key)) minima.push([path, 1]);
    }
    for (const [path, minimum] of minima.filter(([,minimum]) => minimum > 0)) {
      // NonClaims have a separate precursor below, keeping all builtin guards.
      if (path.at(-1) === "nonClaims") continue;
      const atMinimum = structuredClone(output);
      at(atMinimum, path).length = minimum;
      assert.equal(family.output(atMinimum), true, `${family.command}/${path}/at-minimum`);
      at(atMinimum, path).length = minimum - 1;
      assert.equal(family.output(atMinimum), false, `${family.command}/${path}/below-minimum`);
    }
    for (const path of arrays(output).filter(path => path.at(-1) === "nonClaims")) {
      const changed = structuredClone(output), values = at(changed, path);
      if (path.length === 1 || family.command === "adoption-checklist" && path.join('/') === 'diagnostics/0/value/nonClaims') {
        if (["package-runtime-dependency-admission", "text-policy"].includes(family.command)) continue;
        const index = values.indexOf(input.nonClaims[0]);
        assert.notEqual(index, -1);
        values.splice(index, 1);
      } else values.length = 0;
      assert.equal(family.output(changed), false, `${family.command}/${path}/claim-minimum`);
    }
    const extra = structuredClone(output);
    extra.diagnostics.push(structuredClone(extra.diagnostics[0]));
    assert.equal(family.output(extra), false, `${family.command}/diagnostic-tuple-maximum`);
  }
});

test("native ordering and terminal nondisclosure survive complete CLI boundaries", () => {
  const input = seed("proof-obligation-algebra");
  input.obligations[0].evidenceRefs = [" z.txt", " a.txt"];
  const result = pair("proof-obligation-algebra", input, "passed", "native-path-normalization").output;
  assert.deepEqual(result.diagnostics.find(row => row.key === "obligations").value[0].evidenceRefs, [" a.txt", " z.txt"]);
  input.obligations[0].proofRouteRefs = ["route.z", "route.a"];
  assert.equal(families["proof-obligation-algebra"].input(input), true, "ID order is a native constraint");
  native(families["proof-obligation-algebra"], input, "rejected", "native-id-order");
  const canary = "api" + "_key=" + "synthetic".repeat(4);
  for (const family of Object.values(families)) {
    const text = seed(family.command);
    text.nonClaims = [canary];
    const unknown = {...seed(family.command), [canary]: true};
    const duplicate = `{${JSON.stringify(canary)}:1,${JSON.stringify(canary)}:2}`;
    for (const [label, input] of [["text", text], ["key", unknown], ["framing", duplicate]]) {
      const result = native(family, input, "rejected", `${family.command}/${label}/nondisclosure`);
      assert.equal(result.stderr.includes(canary), false, `${family.command}/${label}/leaked-canary`);
    }
  }
});

test("resource limits and minimum-width IDs retain exact predecessor observations", () => {
  const base = seed("proof-obligation-algebra");
  const id = index => `obligation.n${String(index).padStart(4, "0")}`;
  const leaf = index => ({...structuredClone(base.obligations[0]), obligationId: id(index)});
  const graph = obligations => ({...structuredClone(base), obligations});
  const edges = extra => {
    const nodes = Array.from({length: 256 + extra}, (_, index) => leaf(index));
    for (let index = 0; index < 128; index++) Object.assign(nodes[index], {
      obligationKind: "all_of", proofRouteRefs: [], childObligationIds: Array.from({length: 128}, (_, child) => id(128 + child)),
    });
    if (extra) nodes[0].childObligationIds.push(id(256));
    return graph(nodes);
  };
  const closure = extra => {
    const nodes = Array.from({length: 363}, (_, index) => leaf(index));
    for (let index = 0; index < 361; index++) Object.assign(nodes[index], {
      obligationKind: "conditional", proofRouteRefs: [], conditionRefs: ["condition.enabled"], childObligationIds: [id(index+1)],
    });
    Object.assign(nodes[362], {obligationKind: "conditional", proofRouteRefs: [], conditionRefs: ["condition.enabled"], childObligationIds: [id(167-extra)]});
    return graph(nodes);
  };
  const checklist = seed("adoption-checklist");
  checklist.requiredItemIds = Array.from({length: 1001}, (_, index) => `item.n${String(index).padStart(4, "0")}`);
  const reference = structuredClone(families["binding-partition"].rows.find(row => row.name === "crossing-with-delegation").input);
  reference.routeReferences[0].referenceId = "r".repeat(256);
  const surface = seed("binding-partition");
  surface.bindingSurfaces[0].surfaceId = "s".repeat(256);
  surface.routeOwners[0].surfaceId = surface.bindingSurfaces[0].surfaceId;
  const cases = [
    ["proof-obligation-algebra", "obligations-at-2048", graph(Array.from({length: 2048}, (_, index) => leaf(index))), true, "passed"],
    ["proof-obligation-algebra", "obligations-over-2048", graph(Array.from({length: 2049}, (_, index) => leaf(index))), false, "rejected"],
    ["proof-obligation-algebra", "edges-at-16384", edges(0), true, "passed"],
    ["proof-obligation-algebra", "edges-over-16384", edges(1), true, "rejected"],
    ["proof-obligation-algebra", "closure-at-65536", closure(0), true, "passed"],
    ["proof-obligation-algebra", "closure-over-65536", closure(1), true, "rejected"],
    ["adoption-checklist", "minimum-width-failure-ids", checklist, true, "failed"],
    ["binding-partition", "derived-reference-id", reference, true, "passed"],
    ["binding-partition", "derived-surface-id", surface, true, "passed"],
  ];
  const observations = corpus.extremeSources.flatMap(source => source.records);
  assert.equal(observations.length, cases.length);
  for (const [command, name, input, schemaAccepted, expected] of cases) {
    const prior = observations.find(row => row.name === name);
    assert.ok(prior, name);
    assert.equal(sha256(JSON.stringify(input)), prior.inputSHA256, `${name}/input`);
    assert.equal(families[command].input(input), schemaAccepted, `${name}/schema`);
    const result = native(families[command], input, expected, name);
    assert.equal(result.status, prior.exitCode, name);
    assert.equal(result.stderr, prior.stderr ?? "", name);
    assert.equal(sha256(result.stdout), prior.stdoutSHA256, `${name}/output`);
    if (name === "minimum-width-failure-ids") {
      assert.equal(result.output.ruleResults[998].ruleId, "proofkit.adoption-checklist.failure.999");
      assert.equal(result.output.ruleResults[999].ruleId, "proofkit.adoption-checklist.failure.1000");
    }
  }
});

test("CLI transports, literal versions and carrier contracts preserve machine boundaries", () => {
  for (const family of Object.values(families)) {
    const input = seed(family.command), positive = family.rows.find(row => row.name === "positive");
    for (const token of ["0", "2", "1.5"]) {
      const changed = structuredClone(input);
      changed.schemaVersion = Number(token);
      pair(family.command, changed, "rejected", `${family.command}/version/${token}`);
    }
    for (const token of ["1.0", "1e0"]) {
      const raw = JSON.stringify(input).replace('"schemaVersion":1', `"schemaVersion":${token}`);
      native(family, raw, "rejected", `${family.command}/literal-version/${token}`);
    }
    const filename = join(directory, `${family.command}.json`);
    writeFileSync(filename, JSON.stringify({payload: input}));
    const file = spawnSync(binary, [family.command, "--input", filename, "--input-pointer", "/payload"], {encoding: "utf8", timeout: 10_000});
    assert.equal(file.error, undefined);
    assert.equal(file.signal, null);
    assert.equal(file.status, positive.exitCode);
    assert.equal(file.stderr, "");
    assert.equal(sha256(file.stdout), positive.stdoutSHA256);
    const selected = native(family, {payload: input}, "passed", `${family.command}/stdin-pointer`, ["--input-pointer", "/payload"]);
    assert.equal(sha256(selected.stdout), positive.stdoutSHA256);
  }
});
