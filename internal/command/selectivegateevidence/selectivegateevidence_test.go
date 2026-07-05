package selectivegateevidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/obligationdecision"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

func TestBuildAcceptsProducerBoundPassedReceipt(t *testing.T) {
	result, err := Build(validEvidenceInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s", result.ExitCode, result.Report.State)
	}
}

func TestBuildRejectsNonBooleanPublicAPIPlanFlag(t *testing.T) {
	input := validEvidenceInput()
	evidencePlan(input)["publicApiContractTouched"] = "false"

	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "publicApiContractTouched must be boolean") {
		t.Fatalf("Build() error=%v, want publicApiContractTouched boolean rejection", err)
	}
}

func TestProjectObligationDecisionBuildsInputAndRejectsUnroutedCommand(t *testing.T) {
	projected, err := ProjectObligationDecision(validProjectionInput())
	if err != nil {
		t.Fatalf("ProjectObligationDecision() error=%v", err)
	}
	if projected["schemaVersion"] != json.Number("1") || projected["decisionId"] == "" {
		t.Fatalf("projected obligation decision is malformed: %#v", projected)
	}
	obligations := projected["obligations"].([]any)
	if len(obligations) != 1 {
		t.Fatalf("obligation count=%d, want 1", len(obligations))
	}

	input := validProjectionInput()
	input["commandRoutes"] = []any{}
	_, err = ProjectObligationDecision(input)
	if err == nil || !strings.Contains(err.Error(), "missing route for command") {
		t.Fatalf("ProjectObligationDecision() error=%v, want missing route", err)
	}
}

func TestProjectObligationDecisionRejectsDuplicateObligationIDs(t *testing.T) {
	input := validProjectionInput()
	plan := evidencePlan(input["evidence"].(map[string]any))
	plan["requiredCommands"] = []any{
		plannedCommand(),
		map[string]any{
			"id":      "proofkit.go-vet",
			"command": "go vet ./...",
			"reason":  "Go vet is required by the synthetic selective plan.",
		},
	}
	input["commandRoutes"] = []any{
		input["commandRoutes"].([]any)[0],
		map[string]any{
			"commandId":       "proofkit.go-vet",
			"command":         "go vet ./...",
			"sourcePath":      nil,
			"obligationId":    "proofkit.obligation.go-test",
			"requirementId":   "REQ-PROOFKIT-001",
			"proofRouteRef":   "proofkit.route.go-vet",
			"obligationClass": "blocking",
			"owner":           "proofkit.test",
			"reason":          "Go vet command is required by the selective plan.",
			"evidenceRefs":    []any{"docs/contracts/proof.json"},
			"nonClaims":       []any{"Projection route test input does not approve merge."},
		},
	}

	_, err := ProjectObligationDecision(input)
	if err == nil || !strings.Contains(err.Error(), "obligationId values must be unique") {
		t.Fatalf("ProjectObligationDecision() error=%v, want duplicate obligationId rejection", err)
	}
}

func TestProjectObligationDecisionWithoutCurrentnessOrTrustDoesNotSatisfyBlockingObligation(t *testing.T) {
	projected, err := ProjectObligationDecision(validProjectionInput())
	if err != nil {
		t.Fatalf("ProjectObligationDecision() error=%v", err)
	}
	result, err := obligationdecision.Build(projected)
	if err != nil {
		t.Fatalf("obligationdecision.Build() error=%v", err)
	}
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("obligation decision exit=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	encoded, _ := json.Marshal(result.Report.JSONValue())
	if !strings.Contains(string(encoded), "invalid_producer") || !strings.Contains(string(encoded), "unknown_scope") {
		t.Fatalf("obligation decision missing trust/currentness blockers: %s", encoded)
	}
}

func TestProjectObligationDecisionUsesChildOwnedCurrentnessAndTrustProjection(t *testing.T) {
	input := validProjectionInput()
	input["receiptCurrentnessScopeAdmission"] = validCurrentnessScopeAdmission()
	input["receiptTrustClassAdmission"] = validReceiptTrustAdmission()

	projected, err := ProjectObligationDecision(input)
	if err != nil {
		t.Fatalf("ProjectObligationDecision() error=%v", err)
	}
	result, err := obligationdecision.Build(projected)
	if err != nil {
		t.Fatalf("obligationdecision.Build() error=%v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("obligation decision exit=%d state=%s, want passed: %#v", result.ExitCode, result.Report.State, result.Report.JSONValue())
	}
}

func TestProjectObligationDecisionAdmitsEveryProofVocabularyObligationClass(t *testing.T) {
	for _, class := range proofvocab.ObligationClasses() {
		t.Run(class, func(t *testing.T) {
			input := validProjectionInput()
			route := input["commandRoutes"].([]any)[0].(map[string]any)
			route["obligationClass"] = class

			if _, err := ProjectObligationDecision(input); err != nil {
				t.Fatalf("ProjectObligationDecision() rejected owner obligation class %q: %v", class, err)
			}
		})
	}
}

func TestProjectObligationDecisionRejectsUnknownObligationClass(t *testing.T) {
	input := validProjectionInput()
	route := input["commandRoutes"].([]any)[0].(map[string]any)
	route["obligationClass"] = "invented"

	_, err := ProjectObligationDecision(input)
	if err == nil || !strings.Contains(err.Error(), "selective evidence obligation projection obligationClass must be one of") {
		t.Fatalf("ProjectObligationDecision() error=%v, want obligation class vocabulary rejection", err)
	}
}

func TestBuildRejectsProducerAdmissionBindingDrift(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "missing producer receipt id",
			mutate: func(input map[string]any) {
				delete(selectiveReceipt(input), "producerReceiptId")
			},
			want: "lacks producerReceiptId",
		},
		{
			name: "unknown producer receipt id",
			mutate: func(input map[string]any) {
				selectiveReceipt(input)["producerReceiptId"] = "receipt.producer.unknown"
			},
			want: "unknown producer receipt",
		},
		{
			name: "subject drift",
			mutate: func(input map[string]any) {
				producerReceipt(input)["subjectRef"] = "proofkit.other-command"
			},
			want: "subjectRef does not match",
		},
		{
			name: "evidence drift",
			mutate: func(input map[string]any) {
				producerReceipt(input)["evidenceRef"] = "artifacts/test/other-report.json"
			},
			want: "evidenceRef does not match",
		},
		{
			name: "artifact refs drift",
			mutate: func(input map[string]any) {
				producerReceipt(input)["artifactRefs"] = []any{"artifacts/test/other-report.json"}
			},
			want: "artifactRefs do not match",
		},
		{
			name: "status drift",
			mutate: func(input map[string]any) {
				producerReceipt(input)["status"] = "failed"
			},
			want: "claims merge obligation without passed status",
		},
		{
			name: "not merge satisfying",
			mutate: func(input map[string]any) {
				producerReceipt(input)["satisfiesMergeObligation"] = false
			},
			want: "does not satisfy merge obligation",
		},
		{
			name: "missing provenance",
			mutate: func(input map[string]any) {
				delete(producerReceipt(input), "provenanceRef")
			},
			want: "without provenanceRef",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := cloneMap(t, validEvidenceInput())
			item.mutate(input)

			result, err := Build(input)
			if err != nil {
				t.Fatalf("Build() unexpected error = %v", err)
			}
			if result.ExitCode == 0 || result.Report.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", result.ExitCode, result.Report.State)
			}
			assertFailedRuleDiagnostic(t, result, "proofkit.selective-gate-evidence.producer-admission", item.want)
		})
	}
}

func TestBuildRejectsFailedProducerAdmissionReport(t *testing.T) {
	input := validEvidenceInput()
	producerInput := input["producerAdmission"].(map[string]any)
	producer := producerInput["producers"].([]any)[0].(map[string]any)
	producer["admissionLevel"] = "advisory"

	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	assertFailedRuleDiagnostic(t, result, "proofkit.selective-gate-evidence.producer-admission", "claims merge obligation with advisory producer")
}

func TestBuildRejectsMergeSatisfyingEvidenceWithoutProducerAdmission(t *testing.T) {
	input := validEvidenceInput()
	delete(input, "producerAdmission")

	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	assertFailedRuleDiagnostic(t, result, "proofkit.selective-gate-evidence.producer-admission", "requires producerAdmission")
}

func TestBuildAcceptsAdvisoryEvidenceWithoutProducerAdmission(t *testing.T) {
	input := validEvidenceInput()
	input["evidenceClass"] = "advisory"
	delete(input, "producerAdmission")

	result, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", result.ExitCode, result.Report.State)
	}
	if result.Report.Summary["evidenceClass"] != "advisory" {
		t.Fatalf("evidenceClass summary=%v, want advisory", result.Report.Summary["evidenceClass"])
	}
	mergeEvidence := result.Report.Summary["mergeEvidence"].(map[string]any)
	if mergeEvidence["evidenceClass"] != "advisory" ||
		mergeEvidence["producerAdmissionRequired"] != false ||
		mergeEvidence["producerAdmissionProvided"] != false ||
		mergeEvidence["producerAdmissionPassed"] != false ||
		mergeEvidence["mergeAdmissionOwner"] != "consumer_repository" ||
		mergeEvidence["consumerObligationDecisionRequired"] != true {
		t.Fatalf("mergeEvidence=%#v, want advisory evidence metadata without merge approval", mergeEvidence)
	}
}

func TestBuildRejectsStatusExitCodeContradictions(t *testing.T) {
	cases := []struct {
		name   string
		status string
		code   json.Number
		want   string
	}{
		{name: "passed nonzero", status: "passed", code: json.Number("1"), want: "passed receipts must declare zero exitCode"},
		{name: "failed zero", status: "failed", code: json.Number("0"), want: "failed receipts must declare non-zero exitCode"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validEvidenceInput()
			receipt := selectiveReceipt(input)
			receipt["status"] = item.status
			receipt["exitCode"] = item.code
			_, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildRejectsDisplayOnlyCommandShellControlTokens(t *testing.T) {
	input := validEvidenceInput()
	selectiveReceipt(input)["command"] = "go test ./... && curl example.test"
	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("Build() error=%v, want display-only command rejection", err)
	}
}

func TestBuildRejectsUnknownNestedPlanFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "planned command",
			mutate: func(input map[string]any) {
				plannedCommandInput(input)["shadowPolicy"] = true
			},
		},
		{
			name: "private exclusions",
			mutate: func(input map[string]any) {
				evidencePlan(input)["privatePathExclusions"].(map[string]any)["skipSecrets"] = true
			},
		},
		{
			name: "secret scan",
			mutate: func(input map[string]any) {
				evidencePlan(input)["secretScan"].(map[string]any)["skipOnFork"] = true
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validEvidenceInput()
			item.mutate(input)
			_, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "unsupported field") {
				t.Fatalf("Build() error=%v, want unsupported field rejection", err)
			}
		})
	}
}

func TestBuildRejectsUnsafePrivatePathExclusionPrefix(t *testing.T) {
	input := validEvidenceInput()
	privateExclusions := evidencePlan(input)["privatePathExclusions"].(map[string]any)
	privateExclusions["pathPrefixes"] = []any{"C:/secrets/"}

	_, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "repository-relative") {
		t.Fatalf("Build() error=%v, want repository-relative prefix rejection", err)
	}
}

func TestBuildRejectsUnknownPlanEdgeClassAndCoverageState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "edge class",
			mutate: func(input map[string]any) {
				evidencePlan(input)["unknownEdges"] = []any{map[string]any{
					"coverageState":      "covered_by_declared_fallback",
					"edgeClass":          "unknown_edge_class",
					"edgeId":             "edge.unknown",
					"fallbackCommandIds": []any{"proofkit.go-test"},
					"path":               "internal/test.go",
					"reason":             "Synthetic unknown edge.",
				}}
			},
			want: "plan unknownEdge edgeClass must be one of",
		},
		{
			name: "coverage state",
			mutate: func(input map[string]any) {
				evidencePlan(input)["unknownEdges"] = []any{map[string]any{
					"coverageState":      "partially_covered",
					"edgeClass":          "dynamic_or_unknown",
					"edgeId":             "edge.unknown",
					"fallbackCommandIds": []any{"proofkit.go-test"},
					"path":               "internal/test.go",
					"reason":             "Synthetic unknown edge.",
				}}
			},
			want: "plan unknownEdge coverageState must be one of",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validEvidenceInput()
			item.mutate(input)

			_, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildAdmitsEveryProofVocabularyReceiptStatus(t *testing.T) {
	for _, status := range proofvocab.ReceiptStatuses() {
		t.Run(status, func(t *testing.T) {
			input := validEvidenceInput()
			selectiveReceipt(input)["status"] = status
			selectiveReceipt(input)["exitCode"] = selectiveReceiptExitCode(status)
			producerReceipt(input)["status"] = status
			producerReceipt(input)["satisfiesMergeObligation"] = status == "passed"

			if _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner receipt status %q: %v", status, err)
			}
		})
	}
}

func TestBuildAdmitsEveryProofVocabularySelectiveEdgeClassAndCoverageState(t *testing.T) {
	for _, class := range proofvocab.SelectiveEdgeClasses() {
		t.Run("edge-"+class, func(t *testing.T) {
			input := validEvidenceInput()
			evidencePlan(input)["unknownEdges"] = []any{unknownEdgeRecord(class, proofvocab.SelectiveEdgeCoverageCoveredByFallback())}

			if _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner selective edge class %q: %v", class, err)
			}
		})
	}
	for _, state := range proofvocab.SelectiveEdgeCoverageStates() {
		t.Run("coverage-"+state, func(t *testing.T) {
			input := validEvidenceInput()
			evidencePlan(input)["unknownEdges"] = []any{unknownEdgeRecord("dynamic_or_unknown", state)}

			if _, err := Build(input); err != nil {
				t.Fatalf("Build() rejected owner selective edge coverage state %q: %v", state, err)
			}
		})
	}
}

func TestBuildAddsBoundaryNonClaims(t *testing.T) {
	result, err := Build(validEvidenceInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !anyStringContains(result.Report.NonClaims, "do not authenticate receipt producers") {
		t.Fatalf("nonClaims=%#v, want producer-authentication boundary nonclaim", result.Report.NonClaims)
	}
	if !anyStringContains(result.Report.NonClaims, "do not approve merge") {
		t.Fatalf("nonClaims=%#v, want merge authority boundary nonclaim", result.Report.NonClaims)
	}
	if anyStringContains(result.Report.NonClaims, "satisfy merge obligations") {
		t.Fatalf("nonClaims=%#v, must not contain positive merge-satisfaction wording", result.Report.NonClaims)
	}
}

func TestBuildReportsMergeEvidenceWithoutApprovingMerge(t *testing.T) {
	result, err := Build(validEvidenceInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	mergeEvidence := result.Report.Summary["mergeEvidence"].(map[string]any)
	if mergeEvidence["evidenceClass"] != "merge_satisfying" ||
		mergeEvidence["producerAdmissionRequired"] != true ||
		mergeEvidence["producerAdmissionProvided"] != true ||
		mergeEvidence["producerAdmissionPassed"] != true ||
		mergeEvidence["mergeAdmissionOwner"] != "consumer_repository" ||
		mergeEvidence["consumerObligationDecisionRequired"] != true {
		t.Fatalf("mergeEvidence=%#v, want explicit non-authoritative merge evidence metadata", mergeEvidence)
	}
	if strings.Contains(mergeEvidence["nonClaim"].(string), "satisfies merge obligations") {
		t.Fatalf("mergeEvidence nonClaim must not approve merge: %#v", mergeEvidence)
	}
}

func validEvidenceInput() map[string]any {
	return map[string]any{
		"schemaVersion":       json.Number("1"),
		"evidenceClass":       "merge_satisfying",
		"evidenceId":          "proofkit.test.selective-evidence",
		"nonClaims":           []any{"Selective evidence test input does not claim producer authenticity."},
		"preexistingFailures": []any{},
		"plan": map[string]any{
			"schemaVersion":               json.Number("1"),
			"artifactIntegrity":           []any{},
			"changedPaths":                []any{"internal/test.go"},
			"failures":                    []any{},
			"fallbackCoverage":            []any{},
			"generatedArtifacts":          []any{},
			"nonClaims":                   []any{},
			"planState":                   "ok",
			"privatePathExclusions":       map[string]any{"appliesTo": []any{}, "pathPrefixes": []any{}},
			"proofLikePaths":              []any{},
			"publicApiContractTouched":    false,
			"requiredCommands":            []any{plannedCommand()},
			"secretScan":                  map[string]any{"changedArchiveOrBinaryPaths": []any{}, "command": "agentic-proofkit secret-scan", "mode": "diff-scoped", "required": true},
			"skippedGates":                []any{},
			"touchedRequirementWitnesses": []any{},
			"unknownEdges":                []any{},
		},
		"receipts":          []any{selectiveReceiptRecord()},
		"producerAdmission": producerAdmissionInput(),
	}
}

func validProjectionInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"decisionId":    "proofkit.test.obligation-decision",
		"evidence":      validEvidenceInput(),
		"commandRoutes": []any{
			map[string]any{
				"commandId":       "proofkit.go-test",
				"command":         "go test ./...",
				"sourcePath":      nil,
				"obligationId":    "proofkit.obligation.go-test",
				"requirementId":   "REQ-PROOFKIT-001",
				"proofRouteRef":   "proofkit.route.go-test",
				"obligationClass": "blocking",
				"owner":           "proofkit.test",
				"reason":          "Go test command is required by the selective plan.",
				"evidenceRefs":    []any{"docs/contracts/proof.json"},
				"nonClaims":       []any{"Projection route test input does not approve merge."},
			},
		},
		"receiptCurrentnessScopeAdmission": nil,
		"receiptTrustClassAdmission":       nil,
		"nonClaims":                        []any{"Projection test input is synthetic."},
	}
}

func validCurrentnessScopeAdmission() map[string]any {
	digest := "sha256:" + strings.Repeat("a", 64)
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"admissionId":   "proofkit.test.currentness",
		"obligationReceipts": []any{
			map[string]any{
				"obligationId":  "proofkit.obligation.go-test",
				"receiptId":     "receipt.producer.one",
				"requirementId": "REQ-PROOFKIT-001",
				"proofRouteRef": "proofkit.route.go-test",
				"owner":         "proofkit.test",
				"reason":        "Synthetic currentness record is current for projection tests.",
				"evidenceRefs":  []any{"artifacts/test/currentness.json"},
				"currentnessChecks": []any{
					map[string]any{
						"checkId":        "proofkit.test.currentness.digest",
						"checkClass":     "proofkit.test.digest",
						"recordedDigest": digest,
						"currentDigest":  digest,
						"evidenceRefs":   []any{"artifacts/test/currentness.json"},
						"nonClaims":      []any{"Currentness fixture does not read files."},
					},
				},
				"scopeChecks": []any{
					map[string]any{
						"checkId":             "proofkit.test.currentness.scope",
						"scopeClass":          "proofkit.test.scope",
						"admissionState":      "admitted_current_scope",
						"recordedScopeDigest": digest,
						"currentScopeDigest":  digest,
						"reason":              "Synthetic scope matches.",
						"evidenceRefs":        []any{"artifacts/test/currentness.json"},
						"nonClaims":           []any{"Scope fixture does not prove checkout freshness."},
					},
				},
				"nonClaims": []any{"Currentness obligation fixture is synthetic."},
			},
		},
		"nonClaims": []any{"Currentness admission fixture is synthetic."},
	}
}

func validReceiptTrustAdmission() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"policyId":      "proofkit.test.receipt-trust",
		"trustClasses": []any{
			map[string]any{
				"trustClassId":                   "proofkit.test.trusted",
				"rank":                           json.Number("1"),
				"allowedProducerAdmissionLevels": []any{"merge_satisfying"},
				"allowedReceiptStatuses":         []any{"passed"},
				"requiresArtifactRefs":           true,
				"requiresProvenanceRef":          true,
				"nonClaims":                      []any{"Trust class fixture does not authenticate providers."},
			},
		},
		"proofClasses": []any{
			map[string]any{
				"proofClassId":              "proofkit.test.package-gate",
				"minimumTrustClassId":       "proofkit.test.trusted",
				"allowedEnvironmentClasses": []any{"local-go"},
				"allowedReceiptKinds":       []any{"proofkit.package-gate"},
				"owner":                     "proofkit.test",
				"rationale":                 "Synthetic proof class admits package gate receipts.",
				"riskClass":                 "proofkit.test.risk",
				"nonClaims":                 []any{"Proof class fixture does not approve merge."},
			},
		},
		"obligationReceipts": []any{
			map[string]any{
				"obligationId":           "proofkit.obligation.go-test",
				"receiptId":              "receipt.producer.one",
				"requirementId":          "REQ-PROOFKIT-001",
				"proofRouteRef":          "proofkit.route.go-test",
				"proofClassId":           "proofkit.test.package-gate",
				"trustClassId":           "proofkit.test.trusted",
				"receiptKind":            "proofkit.package-gate",
				"environmentClass":       "local-go",
				"receiptStatus":          "passed",
				"producerAdmissionClass": "merge_satisfying",
				"provenanceRef":          "artifacts/test/provenance.json",
				"artifactRefs":           []any{"artifacts/test/report.json"},
				"evidenceRefs":           []any{"artifacts/test/trust.json"},
				"nonClaims":              []any{"Trust obligation fixture is synthetic."},
			},
		},
		"nonClaims": []any{"Trust admission fixture is synthetic."},
	}
}

func anyStringContains(values []any, needle string) bool {
	for _, value := range values {
		text, ok := value.(string)
		if ok && strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func plannedCommand() map[string]any {
	return map[string]any{
		"id":      "proofkit.go-test",
		"command": "go test ./...",
		"reason":  "Go tests cover changed command boundary.",
	}
}

func evidencePlan(input map[string]any) map[string]any {
	return input["plan"].(map[string]any)
}

func plannedCommandInput(input map[string]any) map[string]any {
	return evidencePlan(input)["requiredCommands"].([]any)[0].(map[string]any)
}

func selectiveReceiptRecord() map[string]any {
	return map[string]any{
		"artifactRefs":      []any{"artifacts/test/report.json"},
		"command":           "go test ./...",
		"evidenceRef":       "artifacts/test/report.json",
		"exitCode":          json.Number("0"),
		"id":                "proofkit.go-test",
		"producerReceiptId": "receipt.producer.one",
		"status":            "passed",
	}
}

func producerAdmissionInput() map[string]any {
	return map[string]any{
		"schemaVersion":      json.Number("1"),
		"environmentClasses": []any{"local-go"},
		"nonClaims":          []any{"Producer admission test input does not authenticate producers."},
		"policyId":           "proofkit.test.producer-policy",
		"receiptKinds":       []any{"proofkit.package-gate"},
		"producers": []any{
			map[string]any{
				"admissionLevel":     "merge_satisfying",
				"environmentClasses": []any{"local-go"},
				"evidenceRefs":       []any{"docs/test.md"},
				"nonClaim":           "Synthetic producer only admits this test receipt.",
				"owner":              "proofkit.test",
				"producerId":         "github.actions.package",
				"receiptKinds":       []any{"proofkit.package-gate"},
			},
		},
		"receipts": []any{
			map[string]any{
				"artifactRefs":             []any{"artifacts/test/report.json"},
				"environmentClass":         "local-go",
				"evidenceRef":              "artifacts/test/report.json",
				"nonClaim":                 "Synthetic producer receipt for selective evidence binding.",
				"producerId":               "github.actions.package",
				"provenanceRef":            "artifacts/test/provenance.json",
				"receiptId":                "receipt.producer.one",
				"receiptKind":              "proofkit.package-gate",
				"satisfiesMergeObligation": true,
				"status":                   "passed",
				"subjectRef":               "proofkit.go-test",
			},
		},
	}
}

func selectiveReceipt(input map[string]any) map[string]any {
	return input["receipts"].([]any)[0].(map[string]any)
}

func producerReceipt(input map[string]any) map[string]any {
	producerInput := input["producerAdmission"].(map[string]any)
	return producerInput["receipts"].([]any)[0].(map[string]any)
}

func selectiveReceiptExitCode(status string) any {
	switch status {
	case "passed":
		return json.Number("0")
	case "failed":
		return json.Number("1")
	default:
		return nil
	}
}

func unknownEdgeRecord(class string, state string) map[string]any {
	return map[string]any{
		"coverageState":      state,
		"edgeClass":          class,
		"edgeId":             "edge." + class + "." + state,
		"fallbackCommandIds": []any{"proofkit.go-test"},
		"path":               "internal/test.go",
		"reason":             "Synthetic unknown edge.",
	}
}

func cloneMap(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(encoded), 8<<20)
	if err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	cloned, ok := value.(map[string]any)
	if !ok {
		t.Fatal("cloned input is not an object")
	}
	return cloned
}

func assertFailedRuleDiagnostic(t *testing.T, result Result, ruleID string, want string) {
	t.Helper()
	for _, rule := range result.Report.RuleResults {
		if rule.RuleID != ruleID {
			continue
		}
		if rule.Status != "failed" {
			t.Fatalf("%s status=%s, want failed", ruleID, rule.Status)
		}
		for _, diagnostic := range rule.Diagnostics {
			if text, ok := diagnostic.Value.(string); ok && strings.Contains(text, want) {
				return
			}
		}
		t.Fatalf("%s diagnostics do not contain %q: %#v", ruleID, want, rule.Diagnostics)
	}
	t.Fatalf("missing rule %s", ruleID)
}
