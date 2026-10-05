import {createHash} from "node:crypto";
import {bindingInput, resolverInput} from "./proof-routing-fixtures.mjs";

const note = "Synthetic declaration; no test execution or completeness claim.";

export function inventoryInput() {
  return {schemaVersion: 1, authority: "caller_owned_inventory", inventoryId: "inventory.one", nonClaims: [note], entries: [{
    testId: "test.one", ownerId: "owner.one", sourcePath: "tests/one.go", selector: "tests/one.go::TestOne",
    evidenceClass: "declared_semantic_falsifier_route", requirementRefs: ["REQ-ONE"], ownerInvariantRefs: [],
    commandRefs: ["test.one"], witnessRefs: ["test.one"], nonClaims: [],
    falsifier: {falsifierId: "falsifier.one", negativeCaseId: "negative.one", wrongImplementationClassId: "wrong.one", dominanceGroup: "group.one", supersedes: []},
    oracle: {oracleId: "oracle.one", oracleKind: "exit_and_state", assertionSummary: "Reject an invalid input.", expectedPublicOutcome: "Nonzero exit with a diagnostic."},
  }]};
}

export function wrappedInventory(inventory = inventoryInput()) {
  return {schema: "proofkit.requirement-test-inventory.v1", inventory};
}

export function annotatedInventoryInput() {
  const input = inventoryInput(), entry = input.entries[0];
  entry.falsifier.supersessionDeclarationRef = "declaration.one";
  entry.nonClaims = ["A retained caller boundary, not native proof."];
  entry.qualityFindings = [{findingId: "finding.one", class: "tautology", severity: "warning", ownerReviewState: "candidate",
    evidenceRefs: ["test.one"], nonClaims: ["Synthetic warning, not confirmed test harm."]}];
  return input;
}

export function sourceSetInput() {
  const inventory = inventoryInput(); inventory.sourceId = "source.one";
  const text = JSON.stringify(wrappedInventory(inventory));
  const path = "specs/inventory.json";
  return {schemaVersion: 1, authority: "caller_owned_inventory_source_set", inventoryId: "inventory.sources", nonClaims: [note],
    sourceColumns: ["source_id", "path", "sha256", "role", "non_claims"],
    sources: [["source.one", path, createHash("sha256").update(text).digest("hex"), "test_evidence_inventory_fragment", [note]]],
    sourceTexts: [{path, text}]};
}

export function twoSourceSetInput({duplicateFalsifier = false, nullFalsifiers = false} = {}) {
  const source = sourceSetInput(), first = inventoryInput(), second = inventoryInput();
  first.sourceId = "source.one"; second.sourceId = "source.two";
  second.entries[0].testId = "test.two";
  second.entries[0].falsifier.negativeCaseId = "negative.two";
  if (!duplicateFalsifier) second.entries[0].falsifier.falsifierId = "falsifier.two";
  if (nullFalsifiers) for (const entry of [first.entries[0], second.entries[0]]) {
    entry.falsifier = null; entry.oracle = null; entry.evidenceClass = "proof_route_candidate";
  }
  source.sources = []; source.sourceTexts = [];
  for (const item of [first, second]) {
    const text = JSON.stringify(wrappedInventory(item)), path = `specs/${item.sourceId}.json`;
    source.sources.push([item.sourceId, path, createHash("sha256").update(text).digest("hex"), "test_evidence_inventory_fragment", [note]]);
    source.sourceTexts.push({path, text});
  }
  return source;
}

export function ownerInvariantRegistry() {
  return {schemaVersion: 1, registryId: "registry.one", nonClaims: [note], invariants: [{
    ownerInvariantId: "invariant.one", ownerId: "owner.one", sourcePath: "specs/owner.json", summary: "Invalid inputs are rejected.", nonClaims: [],
  }]};
}

export function discoveryInput() {
  return {schemaVersion: 1, authority: "caller_owned_test_discovery", draftId: "draft.one", repository: {repositoryId: "repo.one"},
    runner: {runnerId: "runner.one", runnerKind: "go_test", commandRef: "test.one", environmentClass: "local-go"},
    discoveredTests: [{testId: "test.one", ownerId: "owner.one", selector: "tests/one.go::TestOne", sourcePath: "tests/one.go", title: "TestOne",
      candidateRequirementRefs: ["REQ-ONE"], ownerInvariantRefs: [], oracleSignals: ["assertion_present"], selectorSignals: ["structured_selector"]}]};
}

export function requirementSource() {
  return {kind: "proofkit.requirement-source", schemaVersion: 2, sourceId: "source.one", specPackagePath: "specs", sourceNonClaims: [note],
    groups: [{groupId: "RGRP-ONE", profileId: "", statementStem: "", sharedPremises: [], members: [{
      requirementId: "REQ-ONE", statementCompletion: "Invalid inputs are rejected.", fields: {ownerId: "owner.one", claimLevel: "blocking", riskClass: "high",
        lifecycle: {state: "active", replacementRequirementIds: [], evidenceRefs: []}, deferral: null,
        proofBindingRefs: ["proofkit/bindings.json"], nonClaimRefs: [], externalNonClaimRefs: [], nonClaims: [],
        updatePolicy: {reviewOwnerId: "owner.one", requiresImpactDeclaration: true, requiresProofBindingReview: true}}}]}]};
}

export function proofInventoryInput() {
  return {schemaVersion: 3, inventoryId: "inventory.proof", commandRefPolicy: {prefix: "commands"},
    requirementSource: requirementSource(), compactProofContract: resolverInput()};
}

export function directComposeInput() {
  const binding = bindingInput(); binding.requirements[0].specPath = "specs/requirements.v2.json";
  return {schemaVersion: 3, composerInputId: "compose.one", viewInputId: "view.one", selectedOwnerIds: ["owner.one"],
    requirementSource: requirementSource(), requirementProofBinding: binding, testEvidenceInventory: inventoryInput(),
    coverageUniverse: {schemaVersion: 1, authority: "caller_owned_inventory", universeId: "universe.one", completenessDeclaration: "selected_owner_surfaces",
      ownerIds: ["owner.one"], commandRefs: [], codeSurfaces: [], specSurfaces: [], testSurfaces: [], nonClaims: [note]}};
}

export function normalizedComposeInput(normalized) {
  const input = directComposeInput();
  delete input.requirementProofBinding; delete input.testEvidenceInventory;
  input.normalizedTestEvidenceInventory = normalized;
  input.compactProofContract = resolverInput();
  input.localEnvironmentPolicy = {authority: "caller_provided", localEnvironmentClasses: ["local-go"]};
  return input;
}
