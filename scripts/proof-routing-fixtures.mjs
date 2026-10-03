// Independently authored domains, not records generated from the schemas.
export function bindingInput() {
  return {
    schemaVersion: 1, bindingId: "proofkit.binding", nonClaims: ["Synthetic lookup only."],
    requirements: [{requirementId: "REQ-ONE", ownerId: "owner.one", specPath: "specs/one.json",
      claimLevel: "blocking", proofState: "witness_backed", nonClaims: []}],
    bindings: [{requirementId: "REQ-ONE", scenarioId: "scenario.one", witnessId: "test.one", witnessKind: "technical",
      witnessPath: "tests/one.go", commandIds: ["test.one"], environmentClasses: ["local-go"],
      witnessSelectors: [{command: "go test ./tests -run TestOne", selector: "TestOne"}]}],
    witnessCommands: [{commandId: "test.one", command: "go test ./tests -run TestOne", environmentClass: "local-go"}],
  };
}

export function vocabulary() {
  return {artifactKinds: ["report"], credentialClasses: ["none"], environmentClasses: ["local-go"],
    environmentClassPolicies: [{environmentClass: "local-go", networkPolicies: ["none"], credentialClasses: ["none"], cachePolicies: ["disabled"]}],
    parallelGroups: ["local"], maxTimeoutMs: 10000, nonCacheableCredentialClasses: []};
}

export function witnessInput() {
  return {vocabulary: vocabulary(), commands: [{schemaVersion: 1, id: "test.one", cwd: ".",
    argv: ["go", "test", "./tests", "-run", "TestOne"], timeoutMs: 1000,
    networkPolicy: "none", credentialClass: "none", cachePolicy: "disabled", parallelGroup: "local",
    environment: {inherit: "none", allowlist: [], classes: ["local-go"]},
    expectedArtifacts: [{kind: "report", path: "artifacts/report.json", required: true}],
    exitCodePolicy: {kind: "zero", successCodes: [0]}}]};
}

export function projectedWitnessInput() {
  return {schemaVersion: 1, projection: "requirement-bindings", requirementProofBinding: bindingInput(), vocabulary: vocabulary()};
}

export function schedulerInput() {
  return {...witnessInput(), schemaVersion: 1, schedulerPlanId: "scheduler.one", nonClaims: ["Synthetic scheduling only."],
    policies: [{commandId: "test.one", inputSelectors: [], outputSelectors: [], resourceReads: [], resourceWrites: [],
      exclusiveLocks: [], sideEffectClass: "none", deterministicOutput: true, cacheAdmissionRefs: [],
      retryPolicy: {kind: "none", maxAttempts: 1}, cancellationPolicy: {kind: "cooperative", graceMs: 1},
      timeoutPolicy: {kind: "bounded", timeoutMs: 1000}, nonClaims: ["Synthetic policy only."]}]};
}

export function resolverInput() {
  return {schema_version: 2, authority_state: "caller_owned_declaration", contract_id: "contract.one",
    contract_kind: "requirement_proof_route_declaration", normalization_profile: "proofkit.compact.declaration.v2",
    non_claims: ["Synthetic declaration only."],
    surface_columns: ["surface_id", "required_environment_classes", "preconditioned_environment_classes"],
    surfaces: [["surface.one", ["local-go"], []]],
    witness_columns: ["selector", "environment_classes", "verify_commands", "resolution_order_index"],
    binding_columns: ["requirement_id", "surface_id", "scenario_id", "invariant_role", "owned_invariant", "blocking_status",
      "required_environment_classes", "positive_witness", "falsification_witness", "verify_commands", "declared_mutation_resistance_claim_id"],
    bindings: [["REQ-ONE", "surface.one", "surface.one::case.one", "contract", "invariant.one", "blocking", ["local-go"],
      ["tests/one.go::TestOne", ["local-go"], ["go test ./tests -run TestOne"], 0],
      ["tests/one.go::TestReject", ["local-go"], ["go test ./tests -run TestReject"], 1],
      ["go test ./tests"], "claim.one"]]};
}
