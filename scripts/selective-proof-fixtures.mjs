// Authored wire fixtures do not import native constants or generated schemas.
export const note = "Synthetic selective proof fixture only.";
export const decisionStates = ["invalid_producer", "invalid_receipt", "stale_receipt", "failed", "missing_receipt", "blocked_missing_precondition", "unavailable_live", "unknown_scope", "deferred_admitted", "advisory_skipped", "not_applicable", "satisfied"];
export function scan() {
  return {command: "go test ./scan", commandId: "scan.one", commandOwnership: "caller_owned_external", mode: "diff-scoped", reason: "external_secret_scan", required: true};
}
export function planInput() {
  return {schemaVersion: 1, archiveOrBinaryPathPatterns: [], artifactIntegrityPolicies: [], baseCommands: [], changedPaths: [],
    dependencyFreshness: {command: "go test ./deps", paths: []}, generatedArtifactRules: [], ignoredProofLikePaths: [], nonClaims: [note],
    packageCommands: [], preexistingFailures: [], privatePathPrefixes: [], proofLikePathPatterns: [], publicApi: {command: "go test ./api", touched: false},
    requirementImpact: {command: "go test ./requirements", touched: false}, scanObligation: scan(), touchedRequirementWitnesses: []};
}
export function populatedPlanInput() {
  const value = planInput();
  Object.assign(value, {archiveOrBinaryPathPatterns: ["build/*.zip"], artifactIntegrityPolicies: [{command: "go test ./archive", pathPattern: "build/*.zip", policy: "archive.hash"}],
    baseCommands: [{command: "go test ./base", id: "base.one", reason: "baseline", sourcePath: "src/base.go"}],
    changedPaths: ["build/code.zip", "src/item.go", "tests/item.go"], dependencyFreshness: {command: "go test ./deps", paths: ["go.mod"]},
    fallbackCoverage: [{command: {command: "go test ./fallback", id: "fallback.one", reason: "fallback"}, edgeClasses: ["dynamic_or_unknown"], reason: "Explicit fallback."}],
    fullWorkspaceCommand: {command: "go test ./workspace", id: "workspace.one", reason: "full"},
    generatedArtifactRules: [{command: "go test ./generated", generator: "generator.one", path: "generated/item.go", sourceOfTruthPatterns: ["src/**"]}],
    ignoredProofLikePaths: ["docs/ignored.md"], packageCommands: [{command: "go test ./package", id: "package.one", reason: "package"}],
    pathTriggeredCommands: [{command: {command: "go test ./paths", id: "path.one", reason: "path"}, pathPatterns: ["src/**"]}],
    privatePathPrefixes: ["private/"], proofLikePathPatterns: ["tests/**"], publicApi: {command: "go test ./api", touched: true},
    requirementImpact: {command: "go test ./requirements", touched: true},
    touchedRequirementWitnesses: [{commands: ["go test ./witness"], path: "tests/item.go", requirementIds: ["REQ-ONE"]}],
    unknownEdges: [{edgeClass: "dynamic_or_unknown", edgeId: "edge.one", path: "src/item.go", reason: "Caller-declared uncertainty."}]});
  return value;
}
export function admittedPlan() {
  const s = scan();
  return {schemaVersion: 1, artifactIntegrity: [], changedPaths: [], failures: [], fallbackCoverage: [], generatedArtifacts: [], nonClaims: [], planState: "ok",
    privatePathExclusions: {appliesTo: [], pathPrefixes: []}, proofLikePaths: [], publicApiContractTouched: false,
    requiredCommands: [{command: s.command, id: s.commandId, commandOwnership: s.commandOwnership, reason: s.reason}], scanObligation: s,
    skippedGates: [], touchedRequirementWitnesses: [], unknownEdges: []};
}
export function evidenceInput() {
  return {schemaVersion: 1, evidenceClass: "advisory", evidenceId: "evidence.one", nonClaims: [note], plan: admittedPlan(), preexistingFailures: [],
    receipts: [{artifactRefs: ["evidence/report.json"], command: "go test ./scan", evidenceRef: "evidence/report.json", exitCode: 0, id: "scan.one", status: "passed"}]};
}
export function projectionInput() {
  return {schemaVersion: 1, decisionId: "decision.one", evidence: evidenceInput(), nonClaims: [note],
    commandRoutes: [{command: "go test ./scan", commandId: "scan.one", evidenceRefs: ["evidence/route.json"], nonClaims: [note],
      obligationClass: "blocking", obligationId: "obligation.one", owner: "owner.one", proofRouteRef: "route.one", reason: "Verify the supplied receipt.", requirementId: "REQ-ONE"}]};
}
export function decisionInput() {
  return {schemaVersion: 1, decisionId: "decision.one", nonClaims: [note], obligations: [{candidateStates: ["satisfied"], evidenceRefs: ["evidence/report.json"], nonClaims: [note],
    obligationClass: "blocking", obligationId: "obligation.one", owner: "owner.one", proofRouteRef: "route.one", reason: "Verify the supplied receipt.", requirementId: "REQ-ONE"}]};
}
export function boundProjectionInput() {
  const value = projectionInput(), digest = "sha256:" + "a".repeat(64);
  value.evidence.evidenceClass = "merge_satisfying";
  value.evidence.receipts[0].producerReceiptId = "receipt.one";
  value.evidence.producerAdmission = {schemaVersion: 1, environmentClasses: ["local-go"], nonClaims: [note], policyId: "producer.policy", receiptKinds: ["test.result"],
    producers: [{admissionLevel: "merge_satisfying", environmentClasses: ["local-go"], evidenceRefs: ["evidence/producer.json"], nonClaim: note, owner: "owner.one", producerId: "producer.one", receiptKinds: ["test.result"]}],
    receipts: [{artifactRefs: ["evidence/report.json"], environmentClass: "local-go", evidenceRef: "evidence/report.json", nonClaim: note, producerId: "producer.one", provenanceRef: "evidence/provenance.json",
      receiptId: "receipt.one", receiptKind: "test.result", satisfiesMergeObligation: true, status: "passed", subjectRef: "scan.one"}]};
  value.receiptCurrentnessScopeAdmission = {schemaVersion: 1, admissionId: "currentness.one", nonClaims: [note], obligationReceipts: [{obligationId: "obligation.one", receiptId: "receipt.one",
    requirementId: "REQ-ONE", proofRouteRef: "route.one", owner: "owner.one", reason: "Synthetic currentness.", evidenceRefs: ["evidence/currentness.json"], nonClaims: [note],
    currentnessChecks: [{checkId: "check.one", checkClass: "digest.one", recordedDigest: digest, currentDigest: digest, evidenceRefs: ["evidence/currentness.json"], nonClaims: [note]}],
    scopeChecks: [{checkId: "scope.one", scopeClass: "scope.local", admissionState: "admitted_current_scope", recordedScopeDigest: digest, currentScopeDigest: digest,
      reason: "Synthetic scope.", evidenceRefs: ["evidence/scope.json"], nonClaims: [note]}]}]};
  value.receiptTrustClassAdmission = {schemaVersion: 1, policyId: "trust.policy", nonClaims: [note],
    trustClasses: [{trustClassId: "trust.one", rank: 1, allowedProducerAdmissionLevels: ["merge_satisfying"], allowedReceiptStatuses: ["passed"], requiresArtifactRefs: true, requiresProvenanceRef: true, nonClaims: [note]}],
    proofClasses: [{proofClassId: "proof.one", minimumTrustClassId: "trust.one", allowedEnvironmentClasses: ["local-go"], allowedReceiptKinds: ["test.result"], owner: "owner.one", rationale: "Synthetic policy.", riskClass: "risk.one", nonClaims: [note]}],
    obligationReceipts: [{obligationId: "obligation.one", receiptId: "receipt.one", requirementId: "REQ-ONE", proofRouteRef: "route.one", proofClassId: "proof.one", trustClassId: "trust.one", receiptKind: "test.result",
      environmentClass: "local-go", receiptStatus: "passed", producerAdmissionClass: "merge_satisfying", provenanceRef: "evidence/provenance.json", artifactRefs: ["evidence/report.json"], evidenceRefs: ["evidence/trust.json"], nonClaims: [note]}]};
  return value;
}
