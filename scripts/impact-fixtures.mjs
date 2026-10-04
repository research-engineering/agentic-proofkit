import {createHash} from "node:crypto";

// Synthetic wire records are independent of the Go builders and schema owners.
const digest = value => `sha256:${createHash("sha256").update(JSON.stringify(value, Object.keys(value).sort(), 2) + "\n").digest("hex")}`;
const witnessPath = "tests/impact_test.go";
export function obligation(requirementId = "REQ-IMPACT-001") {
  const scenarioId = "impact.surface::scenario.one", surfaceId = "impact.surface";
  const bindingRecordId = digest({domain: "proofkit.compact.binding-record.v2", requirementId, scenarioId, surfaceId});
  const declaredWitnessRoutes = ["positive", "falsification"].map(role => {
    const selector = `${witnessPath}::${role}`;
    const witnessRouteId = digest({bindingRecordId, domain: "proofkit.compact.witness-route.v2", role, selector});
    return {bindingRecordId, environmentClasses: ["local-go"], resolutionOrderIndex: 0, role, selector,
      verifyCommands: ["go test ./..."], witnessRouteId};
  }).sort((a, b) => a.witnessRouteId < b.witnessRouteId ? -1 : 1);
  return {bindingRecordId, blockingStatus: "blocking", commands: ["go test ./..."],
    declaredMutationResistanceClaimId: "claim.unverified", declaredWitnessRoutes, preconditioned: false,
    requirementId, requiredEnvironmentClasses: ["local-go"], scenarioId, surfaceId};
}
export function impactInput(populated = false) {
  const input = {schemaVersion: 2, baseCommit: "base", baseRef: "main", headCommit: null, headRef: "feature/impact",
    changedPaths: [], changedRequirementIds: [], changedBindingRecordIds: [], changedWitnessPathCoverage: [],
    generatedArtifactRules: [], ignoredProofLikePaths: [], proofLikePaths: [], obligationCatalog: [],
    preexistingFailures: [], nonClaims: ["Synthetic routes do not prove witness execution."]};
  if (populated) {
    const record = obligation();
    input.obligationCatalog = [record]; input.changedRequirementIds = [record.requirementId];
    input.changedBindingRecordIds = [record.bindingRecordId]; input.changedPaths = [witnessPath];
    input.proofLikePaths = [witnessPath];
    input.changedWitnessPathCoverage = [{path: witnessPath, routes: record.declaredWitnessRoutes.map(
      ({environmentClasses: _environments, verifyCommands: _commands, ...route}) => route)}];
    input.generatedArtifactRules = [{generatedPath: "docs/generated.md", sourcePathPatterns: ["src/**"]}];
  }
  return input;
}

export function composeInput() {
  const requirementId = "REQ-IMPACT-001", surfaceId = "impact.surface", scenarioId = "impact.surface::scenario.one";
  const source = {kind: "proofkit.requirement-source", schemaVersion: 2, sourceId: "impact.source",
    specPackagePath: "docs/specs/impact", sourceNonClaims: ["Synthetic source is not product evidence."],
    groups: [{groupId: "RGRP-IMPACT", profileId: "", statementStem: "", sharedPremises: [], members: [{
      requirementId, statementCompletion: "Changed requirements retain their declared proof routes.",
      fields: {ownerId: "impact.owner", claimLevel: "blocking", riskClass: "medium",
        proofBindingRefs: ["docs/contracts/impact.json"], nonClaimRefs: [], externalNonClaimRefs: [], nonClaims: [],
        lifecycle: {state: "active", evidenceRefs: [], replacementRequirementIds: []}, deferral: null,
        updatePolicy: {requiresImpactDeclaration: true, requiresProofBindingReview: true, reviewOwnerId: "impact.owner"}},
    }]}]};
  const witness = (role, order) => [`${witnessPath}::${role}`, ["local-go"], ["go test ./..."], order];
  const compact = {schema_version: 2, authority_state: "caller_owned_declaration",
    contract_kind: "requirement_proof_route_declaration", contract_id: "impact.contract",
    normalization_profile: "proofkit.compact.declaration.v2", non_claims: ["Synthetic compact routes do not execute tests."],
    surface_columns: ["surface_id", "required_environment_classes", "preconditioned_environment_classes"],
    binding_columns: ["requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status",
      "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"],
    witness_columns: ["selector", "environment_classes", "verify_commands", "resolution_order_index"],
    surfaces: [[surfaceId, ["local-go"], []]],
    bindings: [[requirementId, surfaceId, scenarioId, "contract", "impact.changed_route", "blocking", ["local-go"],
      witness("positive", 0), witness("falsification", 1), ["go test ./..."], "claim.unverified"]]};
  return {schemaVersion: 3, composerInputId: "impact.composer", baseCommit: "base", baseRef: "main", headRef: "feature/impact",
    headCommit: null, baseRequirementSources: [structuredClone(source)], currentRequirementSources: [source],
    baseCompactProofContract: structuredClone(compact), currentCompactProofContract: compact,
    changedPathSources: [{sourceId: "git.diff", paths: ["docs/specs/impact/requirements.v2.json"]}],
    proofBindingSourcePaths: ["docs/contracts/impact.json"], localEnvironmentPolicy: {localEnvironmentClasses: ["local-go"]},
    proofLikePathPolicy: {ignoredProofLikePaths: [], proofLikePathPatterns: ["tests/**"], nonClaims: ["Paths alone are not proof."]},
    generatedArtifactPolicyState: {source: "caller.verifier", state: "complete", uncoveredGeneratedPaths: []},
    generatedArtifactRules: [{generatedPath: "docs/generated.md", sourcePathPatterns: ["docs/specs/impact/**"]}],
    preexistingFailures: [], nonClaims: ["Composition does not imply execution or merge approval."]};
}
