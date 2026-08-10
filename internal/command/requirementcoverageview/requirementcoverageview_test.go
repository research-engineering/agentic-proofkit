package requirementcoverageview

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildJSONBuildsDeclaredRequirementAndCommandRouteMapping(t *testing.T) {
	view, exitCode, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON() exitCode=%d view=%#v", exitCode, view)
	}
	record := view.(map[string]any)
	if record["state"] != "passed" || record["viewKind"] != "proofkit.requirement-coverage-view" {
		t.Fatalf("unexpected view: %#v", record)
	}
	requirement := record["requirementCoverage"].([]any)[0].(map[string]any)
	if requirement["coverageState"] != "mapped_to_declared_semantic_falsifier_route" {
		t.Fatalf("coverageState=%v", requirement["coverageState"])
	}
	if requirement["tests"].([]any)[0].(map[string]any)["oracleSummary"] == "" {
		t.Fatalf("semantic coverage should expose test oracle detail: %#v", requirement)
	}
	command := record["commandCoverage"].([]any)[0].(map[string]any)
	if command["coverageState"] != "command_declared_semantic_falsifier_route_present" {
		t.Fatalf("command coverageState=%v", command["coverageState"])
	}
}

func TestBuildJSONMissingSelectorRemainsMappingOnly(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["sourcePath"] = "internal/command/does-not-exist/missing_test.go"
	entry["selector"] = "go test ./internal/command/does-not-exist -run TestMissing"
	testSurface := input.(map[string]any)["coverageUniverse"].(map[string]any)["testSurfaces"].([]any)[0].(map[string]any)
	testSurface["path"] = "internal/command/does-not-exist/missing_test.go"

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON() exitCode=%d view=%#v, want successful mapping report", exitCode, view)
	}
	record := view.(map[string]any)
	requirement := record["requirementCoverage"].([]any)[0].(map[string]any)
	if got := requirement["coverageState"]; got != "mapped_to_declared_semantic_falsifier_route" {
		t.Fatalf("coverageState=%v, want mapping-only state", got)
	}
	command := record["commandCoverage"].([]any)[0].(map[string]any)
	if got := command["coverageState"]; got != "command_declared_semantic_falsifier_route_present" {
		t.Fatalf("command coverageState=%v, want declared-route state", got)
	}
	for _, row := range []map[string]any{requirement, command} {
		state := row["coverageState"].(string)
		if strings.Contains(state, "covered_by") || strings.Contains(state, "verified") || strings.Contains(state, "closed") {
			t.Fatalf("caller declaration acquired assurance state %q", state)
		}
	}
	if !stringArrayContains(record["nonClaims"], "Mapped declaration routes do not prove selector resolution, oracle quality, execution, freshness, trust, sensitivity, or assurance closure.") {
		t.Fatalf("mapping-only boundary non-claim missing: %#v", record["nonClaims"])
	}
}

func TestAdmitOutputRejectsUnknownNestedFieldsAndBreaksCallerAliases(t *testing.T) {
	view, _, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	record := view.(map[string]any)
	test := record["requirementCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)
	test["unownedField"] = true
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("AdmitOutput() error=%v, want unknown nested field rejection", err)
	}
	delete(test, "unownedField")
	admitted, err := AdmitOutput(record)
	if err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	record["requirementCoverage"].([]any)[0].(map[string]any)["coverageState"] = "mutated"
	if got := admitted["requirementCoverage"].([]any)[0].(map[string]any)["coverageState"]; got == "mutated" {
		t.Fatalf("AdmitOutput() retained caller alias")
	}
}

func TestAdmitOutputRejectsAssuranceVocabularyAndInconsistentStateClasses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "legacy covered state",
			mutate: func(record map[string]any) {
				record["requirementCoverage"].([]any)[0].(map[string]any)["coverageState"] = "covered_by_semantic_falsifier"
			},
			want: "coverageState is unsupported",
		},
		{
			name: "legacy evidence class",
			mutate: func(record map[string]any) {
				test := record["requirementCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)
				test["evidenceClass"] = "semantic_falsifier"
			},
			want: "evidenceClass must be one of",
		},
		{
			name: "verified owner review state",
			mutate: func(record map[string]any) {
				test := record["requirementCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)
				test["qualityFindings"] = []any{map[string]any{
					"class": "missing_edge", "evidenceRefs": []any{"test.coverage.semantic"},
					"findingId": "finding.coverage.forged", "nonClaims": []any{},
					"ownerReviewState": "verified", "severity": "warning",
				}}
			},
			want: "ownerReviewState must be one of",
		},
		{
			name: "verified requirement proof state",
			mutate: func(record map[string]any) {
				record["requirementCoverage"].([]any)[0].(map[string]any)["proofState"] = "verified"
			},
			want: "proofState must be one of",
		},
		{
			name: "inconsistent mapping pair",
			mutate: func(record map[string]any) {
				record["requirementCoverage"].([]any)[0].(map[string]any)["evidenceClass"] = "declared_property_or_fuzz_route"
			},
			want: "coverageState and evidenceClass are inconsistent",
		},
		{
			name: "closed command state",
			mutate: func(record map[string]any) {
				record["commandCoverage"].([]any)[0].(map[string]any)["coverageState"] = "closed"
			},
			want: "coverageState must be one of",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			record := view.(map[string]any)
			item.mutate(record)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitOutput() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitOutputRejectsForgedDerivedCoverageAlgebra(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "passed state with failures",
			mutate: func(record map[string]any) {
				record["failures"] = []any{"proof_route_candidate_only:REQ-PROOFKIT-COVERAGE-001"}
				record["failureCount"] = 1
			},
			want: "state is inconsistent with failures",
		},
		{
			name: "forged classification",
			mutate: func(record map[string]any) {
				record["failureClassifications"] = []any{map[string]any{
					"classificationId": "verified",
					"diagnostic":       "forged",
					"severity":         "failure",
				}}
			},
			want: "failureClassifications is inconsistent",
		},
		{
			name: "forged guidance",
			mutate: func(record map[string]any) {
				record["guidanceSummary"].(map[string]any)["state"] = "failed"
			},
			want: "guidanceSummary is inconsistent",
		},
		{
			name: "parent state disagrees with projected child class",
			mutate: func(record map[string]any) {
				mutateProjectedTestCopies(t, record, "test.coverage.semantic", func(test map[string]any) {
					test["evidenceClass"] = "proof_route_candidate"
				})
				refreshCoverageBasisInventoryDigest(t, record)
			},
			want: "not derived from projected tests and lifecycle",
		},
		{
			name: "parent test ids disagree with projection",
			mutate: func(record map[string]any) {
				record["requirementCoverage"].([]any)[0].(map[string]any)["testIds"] = []any{}
			},
			want: "must equal projected test identities",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			record := view.(map[string]any)
			item.mutate(record)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitOutput() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitOutputRejectsAggregateRowDiagnosticDrift(t *testing.T) {
	for _, item := range []struct {
		name       string
		diagnostic string
	}{
		{name: "requirement failure", diagnostic: "proof_route_candidate_only:REQ-PROOFKIT-COVERAGE-001"},
		{name: "command failure", diagnostic: "command_proof_route_candidate_only:proofkit.coverage.command"},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := validCoverageInput(t)
			entry := inventoryEntry(input)
			entry["evidenceClass"] = "proof_route_candidate"
			entry["falsifier"] = nil
			entry["oracle"] = nil
			view, _, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			record := view.(map[string]any)
			setCoverageAggregateDiagnostics(record, withoutDiagnostic(stringArray(record["failures"]), item.diagnostic), stringArray(record["warnings"]))
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "inconsistent with retained rows") {
				t.Fatalf("AdmitOutput() error=%v, want aggregate row diagnostic rejection", err)
			}
		})
	}

	t.Run("owner warning", func(t *testing.T) {
		input := validCoverageInput(t).(map[string]any)
		input["ownerInvariantRegistry"] = map[string]any{
			"schemaVersion": json.Number("1"),
			"registryId":    "proofkit.coverage.owner-invariants",
			"invariants": []any{map[string]any{
				"ownerInvariantId": "invariant.coverage.unmapped",
				"ownerId":          "proofkit.coverage",
				"sourcePath":       "docs/specs/proofkit-coverage/requirements.v1.json",
				"summary":          "Unmapped owner invariant fixture.",
				"nonClaims":        []any{"Fixture does not claim native execution."},
			}},
			"nonClaims": []any{"Registry fixture is caller-owned."},
		}
		view, _, err := BuildJSON(input, Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error = %v", err)
		}
		record := view.(map[string]any)
		diagnostic := "missing_owner_invariant_inventory:invariant.coverage.unmapped"
		setCoverageAggregateDiagnostics(record, stringArray(record["failures"]), withoutDiagnostic(stringArray(record["warnings"]), diagnostic))
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "inconsistent with retained rows") {
			t.Fatalf("AdmitOutput() error=%v, want aggregate owner warning rejection", err)
		}
	})

	t.Run("surplus requirement diagnostic", func(t *testing.T) {
		view, _, err := BuildJSON(validCoverageInput(t), Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error = %v", err)
		}
		record := view.(map[string]any)
		failures := append(stringArray(record["failures"]), "missing_test_inventory:REQ-PROOFKIT-COVERAGE-FORGED")
		setCoverageAggregateDiagnostics(record, sortedUnique(failures), stringArray(record["warnings"]))
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "inconsistent with retained rows") {
			t.Fatalf("AdmitOutput() error=%v, want surplus row diagnostic rejection", err)
		}
	})
}

func TestAdmitOutputRejectsMalformedCommandCoverageRows(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "missing failures", mutate: func(row map[string]any) { delete(row, "failures") }, want: "missing required field failures"},
		{name: "missing test ids", mutate: func(row map[string]any) { delete(row, "testIds") }, want: "missing required field testIds"},
		{name: "wrong test ids type", mutate: func(row map[string]any) { row["testIds"] = "test.coverage.semantic" }, want: "testIds must be an array"},
		{name: "empty test ids with present route", mutate: func(row map[string]any) { row["testIds"] = []any{} }, want: "must equal projected test identities"},
		{name: "duplicate test ids", mutate: func(row map[string]any) { row["testIds"] = []any{"test.coverage.semantic", "test.coverage.semantic"} }, want: "must be sorted and unique"},
		{name: "unsorted test ids", mutate: func(row map[string]any) { row["testIds"] = []any{"test.coverage.z", "test.coverage.a"} }, want: "must be sorted and unique"},
		{name: "invalid test id", mutate: func(row map[string]any) { row["testIds"] = []any{"not a rule id"} }, want: "must equal projected test identities"},
		{name: "forged failures", mutate: func(row map[string]any) { row["failures"] = []any{"forged"} }, want: "failures is inconsistent"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			record := view.(map[string]any)
			item.mutate(record["commandCoverage"].([]any)[0].(map[string]any))
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitOutput() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitOutputRejectsMissingCommandStateWithTestIdentity(t *testing.T) {
	input := validCoverageInput(t)
	universe := input.(map[string]any)["coverageUniverse"].(map[string]any)
	universe["commandRefs"] = []any{"proofkit.coverage.command", "proofkit.coverage.uncovered"}
	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	record := view.(map[string]any)
	for _, rawRow := range record["commandCoverage"].([]any) {
		row := rawRow.(map[string]any)
		if row["commandId"] == "proofkit.coverage.uncovered" {
			row["testIds"] = []any{"test.coverage.forged"}
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "must equal projected test identities") {
				t.Fatalf("AdmitOutput() error=%v, want command test-projection cardinality rejection", err)
			}
			return
		}
	}
	t.Fatal("missing command row not found")
}

func TestAdmitOutputRejectsCommandStateWeakerThanRetainedTestProjection(t *testing.T) {
	view, _, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	record := view.(map[string]any)
	command := record["commandCoverage"].([]any)[0].(map[string]any)
	command["coverageState"] = "command_proof_route_candidate_only"
	command["failures"] = []any{"command_proof_route_candidate_only:proofkit.coverage.command"}
	setCoverageAggregateDiagnostics(record, []string{"command_proof_route_candidate_only:proofkit.coverage.command"}, stringArray(record["warnings"]))

	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "not derived from projected tests") {
		t.Fatalf("AdmitOutput() error=%v, want correlated command-state rejection", err)
	}
}

func TestAdmitOutputRejectsProjectedTestParentRefDrift(t *testing.T) {
	t.Run("requirement parent", func(t *testing.T) {
		view, _, err := BuildJSON(validCoverageInput(t), Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error = %v", err)
		}
		record := view.(map[string]any)
		mutateProjectedTestCopies(t, record, "test.coverage.semantic", func(test map[string]any) {
			test["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-OTHER"}
		})
		refreshCoverageBasisInventoryDigest(t, record)
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "does not reference its projected parent") {
			t.Fatalf("AdmitOutput() error=%v, want requirement parent-ref rejection", err)
		}
	})

	t.Run("owner invariant parent", func(t *testing.T) {
		input := validCoverageInput(t).(map[string]any)
		input["ownerInvariantRegistry"] = map[string]any{
			"schemaVersion": json.Number("1"), "registryId": "proofkit.coverage.owner-invariants",
			"invariants": []any{map[string]any{
				"ownerInvariantId": "invariant.coverage.semantic", "ownerId": "proofkit.coverage",
				"sourcePath": "docs/specs/proofkit-coverage/requirements.v1.json",
				"summary":    "Coverage owner invariant fixture.", "nonClaims": []any{"Fixture does not claim execution."},
			}},
			"nonClaims": []any{"Registry fixture is caller-owned."},
		}
		entry := inventoryEntry(input)
		entry["ownerInvariantRefs"] = []any{"invariant.coverage.semantic"}
		view, _, err := BuildJSON(input, Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error = %v", err)
		}
		record := view.(map[string]any)
		mutateProjectedTestCopies(t, record, "test.coverage.semantic", func(test map[string]any) {
			test["ownerInvariantRefs"] = []any{"invariant.coverage.other"}
		})
		refreshCoverageBasisInventoryDigest(t, record)
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "does not reference its projected parent") {
			t.Fatalf("AdmitOutput() error=%v, want owner-invariant parent-ref rejection", err)
		}
	})
}

func TestAdmitOutputRejectsInconsistentRepeatedTestProjection(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	input["ownerInvariantRegistry"] = map[string]any{
		"schemaVersion": json.Number("1"), "registryId": "proofkit.coverage.owner-invariants",
		"invariants": []any{map[string]any{
			"ownerInvariantId": "invariant.coverage.semantic", "ownerId": "proofkit.coverage",
			"sourcePath": "docs/specs/proofkit-coverage/requirements.v1.json",
			"summary":    "Coverage owner invariant fixture.", "nonClaims": []any{"Fixture does not claim execution."},
		}},
		"nonClaims": []any{"Registry fixture is caller-owned."},
	}
	entry := inventoryEntry(input)
	entry["ownerInvariantRefs"] = []any{"invariant.coverage.semantic"}
	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	record := view.(map[string]any)
	requirementTest := record["requirementCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)
	ownerTest := record["ownerInvariantCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)
	requirementTest["ownerInvariantRefs"] = []any{}
	ownerTest["requirementRefs"] = []any{}

	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "inconsistent projections") {
		t.Fatalf("AdmitOutput() error=%v, want repeated test projection rejection", err)
	}
}

func TestSelectRequirementsDoesNotAliasAdmittedCoverage(t *testing.T) {
	view, _, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	admitted, err := AdmitOutput(view)
	if err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	fragment := SelectRequirements(admitted, map[string]struct{}{"REQ-PROOFKIT-COVERAGE-001": {}})
	fragmentRow := fragment["requirementCoverage"].([]any)[0].(map[string]any)
	fragmentRow["coverageState"] = "mutated"
	fragmentTest := fragmentRow["tests"].([]any)[0].(map[string]any)
	fragmentTest["commandRefs"].([]any)[0] = "proofkit.mutated"

	admittedRow := admitted["requirementCoverage"].([]any)[0].(map[string]any)
	if admittedRow["coverageState"] == "mutated" {
		t.Fatal("SelectRequirements retained a row-map alias")
	}
	admittedTest := admittedRow["tests"].([]any)[0].(map[string]any)
	if admittedTest["commandRefs"].([]any)[0] == "proofkit.mutated" {
		t.Fatal("SelectRequirements retained a nested-array alias")
	}
}

func setCoverageAggregateDiagnostics(record map[string]any, failures []string, warnings []string) {
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record["failures"] = admit.StringSliceToAny(failures)
	record["failureCount"] = len(failures)
	record["failureClassifications"] = mapsToAny(diagnosticClassifications(failures, "failure"))
	record["warnings"] = admit.StringSliceToAny(warnings)
	record["warningCount"] = len(warnings)
	record["warningClassifications"] = mapsToAny(diagnosticClassifications(warnings, "warning"))
	record["state"] = state
	record["guidanceSummary"] = guidanceSummary(state, failures, warnings)
}

func withoutDiagnostic(values []string, removed string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != removed {
			result = append(result, value)
		}
	}
	return result
}

func TestBuildJSONDoesNotPromoteProofRouteCandidateToSemanticCoverage(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["evidenceClass"] = "proof_route_candidate"
	entry["falsifier"] = nil
	entry["oracle"] = nil
	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("BuildJSON() exitCode=%d, want uncovered failure", exitCode)
	}
	record := view.(map[string]any)
	requirement := record["requirementCoverage"].([]any)[0].(map[string]any)
	if requirement["coverageState"] != "proof_route_candidate_only" {
		t.Fatalf("proof-route candidate state=%v, want explicit candidate-only state", requirement["coverageState"])
	}
	command := record["commandCoverage"].([]any)[0].(map[string]any)
	if command["coverageState"] != "command_proof_route_candidate_only" {
		t.Fatalf("proof-route command state=%v, want explicit candidate-only state", command["coverageState"])
	}
	requireExactClassifications(t, record, "failures", "failureClassifications", "failure", map[string]string{
		"command_proof_route_candidate_only:proofkit.coverage.command": "proof_route_candidate_only",
		"proof_route_candidate_only:REQ-PROOFKIT-COVERAGE-001":         "proof_route_candidate_only",
	})
	if _, err := AdmitOutput(record); err != nil {
		t.Fatalf("AdmitOutput(candidate-only report) error = %v", err)
	}
}

func TestBuildJSONUsesNormalizedOnlyInventoryProjection(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	inventory := input["testEvidenceInventory"]
	delete(input, "testEvidenceInventory")
	input["normalizedTestEvidenceInventory"] = map[string]any{
		"schemaVersion":         json.Number("1"),
		"normalizedInventoryId": "proofkit.coverage.inventory.normalized",
		"normalizedKind":        "proofkit.test-evidence-inventory.normalized",
		"sourceAuthority":       "caller_owned_inventory",
		"sourceCount":           json.Number("0"),
		"sourceColumns":         []any{"source_id", "path", "sha256", "role", "non_claims"},
		"sources":               []any{},
		"entrySources":          []any{},
		"inputPaths":            []any{},
		"inventory":             inventory,
		"nonClaims":             []any{"Normalized inventory fixture does not execute native tests."},
	}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON(normalized-only) error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON(normalized-only) exitCode=%d view=%#v", exitCode, view)
	}
	record := view.(map[string]any)
	if record["testInventoryId"] != "proofkit.coverage.inventory" {
		t.Fatalf("testInventoryId=%v, want nested inventory id", record["testInventoryId"])
	}
	if stringArrayContains(record["warnings"], "missing_test_inventory:input") {
		t.Fatalf("normalized-only inventory was validated but treated as missing: %#v", record["warnings"])
	}
}

func TestBuildJSONCompactProjectionExposesScenarioAndInventoryCommandRefs(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	record["requirementProofBinding"] = nil
	record["compactProofContract"] = validCompactCoverageContract()
	record["localEnvironmentPolicy"] = map[string]any{
		"authority":               "caller_provided",
		"localEnvironmentClasses": []any{"local-go"},
	}
	inventoryEntry(input)["witnessRefs"] = []any{}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON(compact) error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON(compact) exitCode=%d view=%#v", exitCode, view)
	}
	requirement := view.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)
	if got := stringArray(requirement["commandIds"]); len(got) != 1 || got[0] != "proofkit.coverage.command" {
		t.Fatalf("compact requirement commandIds=%v, want inventory command ref", got)
	}
	if requirement["scenarioCount"] != 1 {
		t.Fatalf("compact scenarioCount=%v want 1: %#v", requirement["scenarioCount"], requirement)
	}
	scenario := requirement["scenarios"].([]any)[0].(map[string]any)
	if scenario["scenarioId"] != "proofkit.coverage::scenario" {
		t.Fatalf("compact scenarioId=%v", scenario["scenarioId"])
	}
	if got := stringArray(scenario["commandIds"]); len(got) != 0 {
		t.Fatalf("compact scenario commandIds=%v, want no synthesized scenario command refs", got)
	}
	if scenario["witnessId"] != "" {
		t.Fatalf("compact scenario witnessId=%v, want no synthesized representative witness", scenario["witnessId"])
	}
	if scenario["witnessPath"] != "" {
		t.Fatalf("compact scenario witnessPath=%v, want no synthesized path", scenario["witnessPath"])
	}
	if got := stringArray(requirement["witnessSelectors"]); len(got) != 2 {
		t.Fatalf("compact witnessSelectors=%v, want positive and falsification selectors", got)
	}
}

func TestBuildJSONStructuredProjectionDoesNotFallbackToInventoryCommandRefs(t *testing.T) {
	input := validCoverageInput(t)
	proofBinding := input.(map[string]any)["requirementProofBinding"].(map[string]any)
	binding := proofBinding["bindings"].([]any)[0].(map[string]any)
	binding["commandIds"] = []any{"proofkit.coverage.proof_command"}
	proofBinding["witnessCommands"] = []any{map[string]any{
		"commandId":        "proofkit.coverage.proof_command",
		"command":          "go test ./internal/command/requirementcoverageview -run TestProofOwnedCommand",
		"environmentClass": "local-go",
	}}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON(structured proof command) error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("structured proof command without matching semantic inventory must fail command coverage: %#v", view)
	}
	requirement := view.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)
	want := []string{"proofkit.coverage.proof_command"}
	if got := stringArray(requirement["commandIds"]); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("structured requirement commandIds=%v, want proof-owned commandId %v", got, want)
	}
	scenarios := requirement["scenarios"].([]any)
	scenario := findScenario(t, scenarios, "proofkit.coverage.scenario")
	if got := stringArray(scenario["commandIds"]); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("structured scenario commandIds=%v, want proof-owned commandId %v", got, want)
	}
}

func TestBuildJSONCompactProjectionAggregatesScenariosAndRequirementLocalCommands(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	record["requirementProofBinding"] = nil
	record["compactProofContract"] = validCompactCoverageContract(
		compactCoverageBinding("proofkit.coverage::scenario.alpha"),
		compactCoverageBinding("proofkit.coverage::scenario.beta"),
	)
	record["localEnvironmentPolicy"] = map[string]any{
		"authority":               "caller_provided",
		"localEnvironmentClasses": []any{"local-go"},
	}
	entry := inventoryEntry(input)
	entry["witnessRefs"] = []any{}
	source := record["requirementSource"].(map[string]any)
	source["requirements"] = append(source["requirements"].([]any), map[string]any{
		"claimLevel":       "advisory",
		"deferral":         nil,
		"invariant":        "Unrelated coverage fixture must not affect the selected requirement command projection.",
		"lifecycle":        map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
		"nonClaimRefs":     []any{},
		"nonClaims":        []any{"Unrelated fixture is present only to prove requirement-local command isolation."},
		"ownerId":          "proofkit.coverage",
		"proofBindingRefs": []any{},
		"requirementId":    "REQ-PROOFKIT-COVERAGE-002",
		"riskClass":        "low",
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  false,
			"requiresProofBindingReview": false,
			"reviewOwnerId":              "proofkit.coverage",
		},
	})
	universe := record["coverageUniverse"].(map[string]any)
	universe["commandRefs"] = []any{"proofkit.coverage.command", "proofkit.coverage.unrelated"}
	inventory := record["testEvidenceInventory"].(map[string]any)
	inventory["entries"] = append(inventory["entries"].([]any), map[string]any{
		"testId":             "test.coverage.unrelated",
		"selector":           "go test ./internal/command/requirementcoverageview -run TestUnrelated",
		"sourcePath":         "internal/command/requirementcoverageview/requirementcoverageview_test.go",
		"ownerId":            "proofkit.coverage",
		"evidenceClass":      "declared_semantic_falsifier_route",
		"requirementRefs":    []any{"REQ-PROOFKIT-COVERAGE-002"},
		"ownerInvariantRefs": []any{},
		"commandRefs":        []any{"proofkit.coverage.unrelated"},
		"witnessRefs":        []any{},
		"falsifier": map[string]any{
			"falsifierId":                "falsifier.coverage.unrelated",
			"negativeCaseId":             "case.coverage.unrelated",
			"wrongImplementationClassId": "wrong.coverage.unrelated",
			"dominanceGroup":             "coverage.unrelated",
			"supersedes":                 []any{},
		},
		"oracle": map[string]any{
			"assertionSummary":      "Unrelated fixture.",
			"expectedPublicOutcome": "failed report with diagnostic",
			"oracleId":              "oracle.coverage.unrelated",
			"oracleKind":            "negative_exit_and_diagnostic",
		},
		"nonClaims": []any{},
	})

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON(compact multi-scenario) error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON(compact multi-scenario) exitCode=%d view=%#v", exitCode, view)
	}
	requirement := view.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)
	if got := stringArray(requirement["commandIds"]); len(got) != 1 || got[0] != "proofkit.coverage.command" {
		t.Fatalf("compact requirement commandIds=%v, want only requirement-local inventory command ref", got)
	}
	scenarios := requirement["scenarios"].([]any)
	if len(scenarios) != 2 {
		t.Fatalf("compact scenarios len=%d want 2: %#v", len(scenarios), scenarios)
	}
	scenarioIDs := []string{}
	for _, rawScenario := range scenarios {
		item := rawScenario.(map[string]any)
		scenarioIDs = append(scenarioIDs, item["scenarioId"].(string))
		if got := stringArray(item["commandIds"]); len(got) != 0 {
			t.Fatalf("compact scenario commandIds=%v, want no synthesized scenario command refs", got)
		}
		if item["witnessId"] != "" {
			t.Fatalf("compact scenario witnessId=%v, want no synthesized representative witness", item["witnessId"])
		}
		if item["witnessPath"] != "" {
			t.Fatalf("compact scenario witnessPath=%v, want no synthesized path", item["witnessPath"])
		}
	}
	if strings.Join(sortedUnique(scenarioIDs), ",") != "proofkit.coverage::scenario.alpha,proofkit.coverage::scenario.beta" {
		t.Fatalf("compact scenario ids=%v", scenarioIDs)
	}
}

func TestBuildJSONCompactProjectionRejectsNonWitnessBackedBindingState(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	second := compactCoverageBinding("proofkit.coverage::scenario.conflicting")
	second[5] = "not_bound"
	record["requirementProofBinding"] = nil
	record["compactProofContract"] = validCompactCoverageContract(
		compactCoverageBinding("proofkit.coverage::scenario"),
		second,
	)
	record["localEnvironmentPolicy"] = map[string]any{
		"authority":               "caller_provided",
		"localEnvironmentClasses": []any{"local-go"},
	}

	_, _, err := BuildJSON(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "must be witness_backed") {
		t.Fatalf("expected witness-bearing compact state rejection, got %v", err)
	}
}

func TestBuildJSONAgentEnvelopeUsesSharedEnvelopeKernel(t *testing.T) {
	envelope, exitCode, err := BuildJSON(validCoverageInput(t), Options{AgentEnvelope: true})
	if err != nil {
		t.Fatalf("BuildJSON(agent envelope) error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildJSON(agent envelope) exitCode=%d envelope=%#v", exitCode, envelope)
	}
	record := envelope.(map[string]any)
	if record["envelopeId"] != "proofkit.requirement-coverage-view.agent-envelope" {
		t.Fatalf("envelopeId=%v", record["envelopeId"])
	}
	if record["schemaVersion"] != 1 {
		t.Fatalf("schemaVersion=%v", record["schemaVersion"])
	}
	cost := record["costContract"].(map[string]any)
	if cost["stopReason"] != "caller_review_required" {
		t.Fatalf("stopReason=%v", cost["stopReason"])
	}
	contextRefs := record["contextRefs"].([]any)
	if len(contextRefs) != 5 {
		t.Fatalf("contextRefs len=%d refs=%#v", len(contextRefs), contextRefs)
	}
}

func TestBuildJSONRejectsRouteOnlyCoverageForBlockingRequirement(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.031691819956938118822991045596460919977101593213780644803440154333791119868791")
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["evidenceClass"] = "routing_smoke_nonclaim"
	entry["requirementRefs"] = []any{}
	entry["falsifier"] = nil
	entry["oracle"] = nil
	entry["nonClaims"] = []any{"Route-only smoke proves CLI wiring only."}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("route-only coverage unexpectedly passed: %#v", view)
	}
	record := view.(map[string]any)
	requirement := record["requirementCoverage"].([]any)[0].(map[string]any)
	if requirement["coverageState"] != "missing_test_inventory" {
		t.Fatalf("route-only coverage counted as semantic: %#v", requirement)
	}
	command := record["commandCoverage"].([]any)[0].(map[string]any)
	if command["coverageState"] != "command_route_only_nonclaim" {
		t.Fatalf("route-only command state not preserved: %#v", command)
	}
	requireExactClassifications(t, record, "failures", "failureClassifications", "failure", map[string]string{
		"missing_test_inventory:REQ-PROOFKIT-COVERAGE-001": "missing_declared_test_route",
	})
	requireExactClassifications(t, record, "warnings", "warningClassifications", "warning", map[string]string{
		"command_route_only_nonclaim:proofkit.coverage.command": "routing_smoke_only",
	})
}

func TestBuildJSONFailsMissingRequirementBindingRoute(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	proof := record["requirementProofBinding"].(map[string]any)
	proof["requirements"] = []any{}
	proof["bindings"] = []any{}
	proof["witnessCommands"] = []any{}
	entry := inventoryEntry(input)
	entry["witnessRefs"] = []any{}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("missing proof binding route passed: %#v", view)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"missing_proof_binding_route:REQ-PROOFKIT-COVERAGE-001": "missing_requirement_binding",
	})
}

func TestBuildJSONRejectsInventorySelectorSourcePathDrift(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["selector"] = "internal/command/requirementcoverageview/other_test.go::TestCoverage"

	_, _, err := BuildJSON(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "sourcePath must match selector path") {
		t.Fatalf("BuildJSON() error=%v, want embedded inventory selector/sourcePath drift", err)
	}
}

func TestBuildJSONFailsMissingCommandDeclaredSemanticFalsifierRouteFromUniverse(t *testing.T) {
	input := validCoverageInput(t)
	universe := input.(map[string]any)["coverageUniverse"].(map[string]any)
	universe["commandRefs"] = []any{"proofkit.coverage.command", "proofkit.coverage.uncovered"}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("missing command semantic falsifier passed: %#v", view)
	}
	failures := strings.Join(stringArray(view.(map[string]any)["failures"]), "\n")
	if !strings.Contains(failures, "missing_command_declared_semantic_falsifier_route:proofkit.coverage.uncovered") {
		t.Fatalf("missing command failure not reported: %s", failures)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"missing_command_declared_semantic_falsifier_route:proofkit.coverage.uncovered": "missing_declared_test_route",
	})
}

func TestBuildJSONProjectsOwnerInvariantCoverage(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	record["ownerInvariantRegistry"] = map[string]any{
		"schemaVersion": json.Number("1"),
		"registryId":    "proofkit.coverage.owner-invariants",
		"invariants": []any{
			map[string]any{
				"ownerInvariantId": "invariant.coverage.semantic",
				"ownerId":          "proofkit.coverage",
				"sourcePath":       "docs/specs/proofkit-coverage/requirements.v1.json",
				"summary":          "Coverage owner invariant rows must render linked semantic tests.",
				"nonClaims":        []any{"Owner invariant fixture does not claim native execution."},
			},
		},
		"nonClaims": []any{"Owner invariant registry fixture is caller-owned."},
	}
	entry := inventoryEntry(input)
	entry["requirementRefs"] = []any{}
	entry["ownerInvariantRefs"] = []any{"invariant.coverage.semantic"}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("requirement without requirement test should still fail while owner invariant projects: %#v", view)
	}
	coverage := view.(map[string]any)["ownerInvariantCoverage"].([]any)
	if len(coverage) != 1 {
		t.Fatalf("ownerInvariantCoverage len=%d want 1: %#v", len(coverage), coverage)
	}
	invariant := coverage[0].(map[string]any)
	if invariant["ownerInvariantId"] != "invariant.coverage.semantic" ||
		invariant["coverageState"] != "mapped_to_declared_semantic_falsifier_route" ||
		invariant["evidenceClass"] != "declared_semantic_falsifier_route" {
		t.Fatalf("unexpected owner invariant coverage: %#v", invariant)
	}
	tests := invariant["tests"].([]any)
	if len(tests) != 1 || tests[0].(map[string]any)["testId"] != "test.coverage.semantic" {
		t.Fatalf("owner invariant tests not projected: %#v", invariant)
	}
	output, _, err := BuildMarkdown(input)
	if err != nil {
		t.Fatalf("BuildMarkdown() error = %v", err)
	}
	visibleMarkdown := strings.ReplaceAll(output, "\\.", ".")
	if !strings.Contains(output, "## Owner Invariants") || !strings.Contains(visibleMarkdown, "invariant.coverage.semantic") {
		t.Fatalf("markdown missing owner invariant coverage:\n%s", output)
	}
	htmlOutput, _, err := BuildHTML(input)
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	if !strings.Contains(htmlOutput, "Owner invariants") || !strings.Contains(htmlOutput, "invariant.coverage.semantic") {
		t.Fatalf("html missing owner invariant coverage:\n%s", htmlOutput)
	}
}

func TestBuildJSONFailsClosedOnDeclaredDeadZonesForSelectedOwnerAndFullRepository(t *testing.T) {
	for _, declaration := range []string{"selected_owner_surfaces", "full_repository"} {
		t.Run(declaration, func(t *testing.T) {
			input := validCoverageInput(t)
			addUnboundCodeSurface(input, declaration)

			view, exitCode, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			if exitCode == 0 {
				t.Fatalf("declared dead zone passed: %#v", view)
			}
			failures := strings.Join(stringArray(view.(map[string]any)["failures"]), "\n")
			if !strings.Contains(failures, "dead_zone:unbound_code_surface:proofkit.unbound.code") {
				t.Fatalf("dead-zone failure missing: %s", failures)
			}
			requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
				"dead_zone:unbound_code_surface:proofkit.unbound.code": "declared_dead_zone",
			})
		})
	}
}

func TestBuildJSONKeepsDeadZonesAdvisoryForSelectedPaths(t *testing.T) {
	input := validCoverageInput(t)
	addUnboundCodeSurface(input, "selected_paths_advisory")

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("selected path dead zone should be advisory: %#v", view)
	}
	warnings := strings.Join(stringArray(view.(map[string]any)["warnings"]), "\n")
	if !strings.Contains(warnings, "dead_zone_advisory:unbound_code_surface:proofkit.unbound.code") {
		t.Fatalf("dead-zone advisory warning missing: %s", warnings)
	}
	requireExactClassifications(t, view.(map[string]any), "warnings", "warningClassifications", "warning", map[string]string{
		"dead_zone_advisory:unbound_code_surface:proofkit.unbound.code": "declared_dead_zone",
	})
}

func TestAdmitOutputRejectsDeadZoneProjectionDrift(t *testing.T) {
	for _, declaration := range []string{"selected_owner_surfaces", "selected_paths_advisory"} {
		t.Run(declaration+" missing aggregate diagnostic", func(t *testing.T) {
			input := validCoverageInput(t)
			addUnboundCodeSurface(input, declaration)
			view, _, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			record := view.(map[string]any)
			failures := stringArray(record["failures"])
			warnings := stringArray(record["warnings"])
			if declaration == "selected_paths_advisory" {
				warnings = withoutDiagnostic(warnings, "dead_zone_advisory:unbound_code_surface:proofkit.unbound.code")
			} else {
				failures = withoutDiagnostic(failures, "dead_zone:unbound_code_surface:proofkit.unbound.code")
			}
			setCoverageAggregateDiagnostics(record, failures, warnings)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "retained projection") {
				t.Fatalf("AdmitOutput() error=%v, want retained dead-zone diagnostic rejection", err)
			}
		})
	}

	t.Run("surplus aggregate diagnostic", func(t *testing.T) {
		view, _, err := BuildJSON(validCoverageInput(t), Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error = %v", err)
		}
		record := view.(map[string]any)
		failures := append(stringArray(record["failures"]), "dead_zone:unbound_code_surface:proofkit.forged")
		setCoverageAggregateDiagnostics(record, sortedUnique(failures), stringArray(record["warnings"]))
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "retained projection") {
			t.Fatalf("AdmitOutput() error=%v, want surplus dead-zone rejection", err)
		}
	})

	t.Run("malformed row", func(t *testing.T) {
		view, _, err := BuildJSON(validCoverageInput(t), Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error = %v", err)
		}
		record := view.(map[string]any)
		record["deadZones"] = []any{map[string]any{
			"deadZoneKind": "unbound_code_surface", "ownerId": "proofkit.coverage",
			"path": "../escape", "surfaceId": "proofkit.forged",
		}}
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "must not escape the repository root") {
			t.Fatalf("AdmitOutput() error=%v, want malformed dead-zone rejection", err)
		}
	})
}

func TestBuildJSONClassifiesFailedTestInventory(t *testing.T) {
	input := validCoverageInput(t)
	oracle := inventoryEntry(input)["oracle"].(map[string]any)
	oracle["assertionSummary"] = ""

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("failed inventory coverage view passed: %#v", view)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"missing_test_inventory:REQ-PROOFKIT-COVERAGE-001":  "missing_declared_test_route",
		"test_inventory_failed:proofkit.coverage.inventory": "failed_test_inventory",
	})
}

func TestBuildJSONRejectsUnknownInventoryRefs(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(map[string]any)
		want     string
		expected map[string]string
	}{
		{
			name: "requirement",
			mutate: func(entry map[string]any) {
				entry["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-999"}
			},
			want: "unknown_requirement_ref:test.coverage.semantic:REQ-PROOFKIT-COVERAGE-999",
			expected: map[string]string{
				"missing_test_inventory:REQ-PROOFKIT-COVERAGE-001":                         "missing_declared_test_route",
				"unknown_requirement_ref:test.coverage.semantic:REQ-PROOFKIT-COVERAGE-999": "unknown_reference",
			},
		},
		{
			name: "owner invariant",
			mutate: func(entry map[string]any) {
				entry["ownerInvariantRefs"] = []any{"invariant.coverage.unknown"}
			},
			want: "unknown_owner_invariant_ref:test.coverage.semantic:invariant.coverage.unknown",
			expected: map[string]string{
				"unknown_owner_invariant_ref:test.coverage.semantic:invariant.coverage.unknown": "unknown_reference",
			},
		},
		{
			name: "command",
			mutate: func(entry map[string]any) {
				entry["commandRefs"] = []any{"proofkit.coverage.unknown"}
			},
			want: "unknown_command_or_witness_ref:test.coverage.semantic:proofkit.coverage.unknown",
			expected: map[string]string{
				"missing_command_declared_semantic_falsifier_route:proofkit.coverage.command":     "missing_declared_test_route",
				"unknown_command_or_witness_ref:test.coverage.semantic:proofkit.coverage.unknown": "unknown_reference",
			},
		},
		{
			name: "witness",
			mutate: func(entry map[string]any) {
				entry["witnessRefs"] = []any{"proofkit.coverage.unknown-witness"}
			},
			want: "unknown_command_or_witness_ref:test.coverage.semantic:proofkit.coverage.unknown-witness",
			expected: map[string]string{
				"unknown_command_or_witness_ref:test.coverage.semantic:proofkit.coverage.unknown-witness": "unknown_reference",
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validCoverageInput(t)
			item.mutate(inventoryEntry(input))

			view, exitCode, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			if exitCode == 0 {
				t.Fatalf("unknown inventory ref passed: %#v", view)
			}
			failures := strings.Join(stringArray(view.(map[string]any)["failures"]), "\n")
			if !strings.Contains(failures, item.want) {
				t.Fatalf("failures missing %q: %s", item.want, failures)
			}
			requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", item.expected)
		})
	}
}

func TestBuildJSONClassifiesUnknownRefsByDiagnosticKindNotPayloadText(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["testId"] = "test.routing_smoke_nonclaim"
	entry["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-999"}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("unknown requirement ref passed: %#v", view)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"missing_test_inventory:REQ-PROOFKIT-COVERAGE-001":                              "missing_declared_test_route",
		"unknown_requirement_ref:test.routing_smoke_nonclaim:REQ-PROOFKIT-COVERAGE-999": "unknown_reference",
	})
}

func TestBuildJSONClassifiesRemovedRequirementAsNotApplicableWarning(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	requirement := sourceRequirement(input)
	requirement["claimLevel"] = "advisory"
	requirement["lifecycle"] = map[string]any{
		"evidenceRefs":              []any{"docs/specs/proofkit-coverage/removal.md"},
		"replacementRequirementIds": []any{},
		"state":                     "removed",
	}
	record["coverageUniverse"].(map[string]any)["completenessDeclaration"] = "selected_paths_advisory"

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("removed requirement should be advisory in selected paths: %#v", view)
	}
	requireExactClassifications(t, view.(map[string]any), "warnings", "warningClassifications", "warning", map[string]string{
		"not_applicable:REQ-PROOFKIT-COVERAGE-001": "not_applicable_with_reason",
	})
}

func TestBuildJSONScopesSelectedOwnersWithoutBlockingOutOfScopeRequirements(t *testing.T) {
	input := validCoverageInput(t)
	requirements := input.(map[string]any)["requirementSource"].(map[string]any)["requirements"].([]any)
	requirements = append(requirements, map[string]any{
		"claimLevel":       "blocking",
		"deferral":         nil,
		"invariant":        "Out of scope requirement must not change a selected owner coverage view.",
		"lifecycle":        map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
		"nonClaimRefs":     []any{},
		"nonClaims":        []any{"Out of scope fixture is not part of the coverage universe."},
		"ownerId":          "proofkit.other",
		"proofBindingRefs": []any{"proofkit/requirement-bindings.json"},
		"requirementId":    "REQ-PROOFKIT-COVERAGE-999",
		"riskClass":        "high",
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  true,
			"requiresProofBindingReview": true,
			"reviewOwnerId":              "proofkit.other",
		},
	})
	input.(map[string]any)["requirementSource"].(map[string]any)["requirements"] = requirements
	binding := input.(map[string]any)["requirementProofBinding"].(map[string]any)
	binding["requirements"] = append(binding["requirements"].([]any), map[string]any{
		"claimLevel":    "blocking",
		"nonClaims":     []any{"Out of scope proof fixture does not execute witnesses."},
		"ownerId":       "proofkit.other",
		"proofState":    "witness_backed",
		"requirementId": "REQ-PROOFKIT-COVERAGE-999",
		"specPath":      "docs/specs/proofkit-other/requirements.v1.json",
	})
	binding["bindings"] = append(binding["bindings"].([]any), map[string]any{
		"commandIds":         []any{"proofkit.other.command"},
		"environmentClasses": []any{"local-go"},
		"requirementId":      "REQ-PROOFKIT-COVERAGE-999",
		"scenarioId":         "proofkit.other.scenario",
		"witnessId":          "proofkit.other.witness",
		"witnessKind":        "contract",
		"witnessPath":        "internal/command/other/other_test.go",
	})
	binding["witnessCommands"] = append(binding["witnessCommands"].([]any), map[string]any{
		"command":          "go test ./internal/command/other",
		"commandId":        "proofkit.other.command",
		"environmentClass": "local-go",
	})

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("out-of-scope requirement blocked selected owner view: %#v", view)
	}
	record := view.(map[string]any)
	if record["requirementCoverageCount"] != 1 {
		t.Fatalf("requirementCoverageCount=%v want 1", record["requirementCoverageCount"])
	}
	if record["commandCoverageCount"] != 1 {
		t.Fatalf("commandCoverageCount=%v want 1", record["commandCoverageCount"])
	}
}

func TestBuildJSONRejectsFullRepositoryOwnerScopeMismatch(t *testing.T) {
	input := validCoverageInput(t)
	requirements := input.(map[string]any)["requirementSource"].(map[string]any)["requirements"].([]any)
	requirements = append(requirements, map[string]any{
		"claimLevel":       "blocking",
		"deferral":         nil,
		"invariant":        "Full repository coverage cannot omit a source owner.",
		"lifecycle":        map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
		"nonClaimRefs":     []any{},
		"nonClaims":        []any{"Full repository mismatch fixture does not execute tests."},
		"ownerId":          "proofkit.other",
		"proofBindingRefs": []any{"proofkit/requirement-bindings.json"},
		"requirementId":    "REQ-PROOFKIT-COVERAGE-999",
		"riskClass":        "high",
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  true,
			"requiresProofBindingReview": true,
			"reviewOwnerId":              "proofkit.other",
		},
	})
	input.(map[string]any)["requirementSource"].(map[string]any)["requirements"] = requirements
	input.(map[string]any)["coverageUniverse"].(map[string]any)["completenessDeclaration"] = "full_repository"

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("full repository owner mismatch passed: %#v", view)
	}
	failures := strings.Join(stringArray(view.(map[string]any)["failures"]), "\n")
	if !strings.Contains(failures, "full_repository_source_requirement_outside_owner_scope:REQ-PROOFKIT-COVERAGE-999") {
		t.Fatalf("owner scope failure missing: %s", failures)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"full_repository_source_requirement_outside_owner_scope:REQ-PROOFKIT-COVERAGE-999": "owner_scope_violation",
	})
}

func TestBuildJSONRejectsCoverageUniverseSurfaceOutsideOwnerScope(t *testing.T) {
	input := validCoverageInput(t)
	surface := input.(map[string]any)["coverageUniverse"].(map[string]any)["codeSurfaces"].([]any)[0].(map[string]any)
	surface["ownerId"] = "proofkit.other"

	_, _, err := BuildJSON(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "must reference coverageUniverse ownerIds") {
		t.Fatalf("unexpected owner scope error: %v", err)
	}
}

func TestBuildJSONRejectsDuplicateCoverageUniverseOwnerPath(t *testing.T) {
	input := validCoverageInput(t)
	universe := input.(map[string]any)["coverageUniverse"].(map[string]any)
	codeSurfaces := universe["codeSurfaces"].([]any)
	duplicate := map[string]any{}
	for key, value := range codeSurfaces[0].(map[string]any) {
		duplicate[key] = value
	}
	duplicate["surfaceId"] = "proofkit.coverage.duplicate_code"
	universe["codeSurfaces"] = append(codeSurfaces, duplicate)

	if _, _, err := BuildJSON(input, Options{}); err == nil || !strings.Contains(err.Error(), "duplicate owner/path surface") {
		t.Fatalf("BuildJSON() error=%v, want duplicate owner/path rejection", err)
	}
}

func TestBuildJSONRejectsInventoryEntryOutsideOwnerScope(t *testing.T) {
	input := validCoverageInput(t)
	inventoryEntry(input)["ownerId"] = "proofkit.other"

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("inventory owner mismatch passed: %#v", view)
	}
	failures := strings.Join(stringArray(view.(map[string]any)["failures"]), "\n")
	if !strings.Contains(failures, "inventory_entry_owner_outside_scope:test.coverage.semantic:proofkit.other") {
		t.Fatalf("inventory owner failure missing: %s", failures)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"inventory_entry_owner_outside_scope:test.coverage.semantic:proofkit.other": "owner_scope_violation",
	})
}

func TestBuildJSONRejectsGovernanceEvidenceForBlockingSemanticRequirement(t *testing.T) {
	newInput := func() any {
		input := validCoverageInput(t)
		entry := inventoryEntry(input)
		entry["evidenceClass"] = "governance_or_release"
		entry["falsifier"] = nil
		entry["oracle"] = nil
		entry["nonClaims"] = []any{"Governance evidence is not semantic product coverage."}
		return input
	}

	view, exitCode, err := BuildJSON(newInput(), Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode == 0 {
		t.Fatalf("governance evidence satisfied blocking semantic coverage: %#v", view)
	}
	requirement := view.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)
	if requirement["coverageState"] != "mapped_to_declared_governance_or_release_route_nonproduct" {
		t.Fatalf("unexpected governance coverage state: %#v", requirement)
	}
	command := view.(map[string]any)["commandCoverage"].([]any)[0].(map[string]any)
	if command["coverageState"] != "command_owner_nonsemantic_evidence" {
		t.Fatalf("governance evidence should not satisfy semantic command closure: %#v", command)
	}
	failures := strings.Join(stringArray(view.(map[string]any)["failures"]), "\n")
	if !strings.Contains(failures, "mapped_to_declared_governance_or_release_route_nonproduct:REQ-PROOFKIT-COVERAGE-001") {
		t.Fatalf("governance non-semantic failure missing: %s", failures)
	}
	requireExactClassifications(t, view.(map[string]any), "failures", "failureClassifications", "failure", map[string]string{
		"mapped_to_declared_governance_or_release_route_nonproduct:REQ-PROOFKIT-COVERAGE-001": "nonsemantic_governance_evidence",
		"nonsemantic_command_evidence:proofkit.coverage.command":                              "nonsemantic_command_evidence",
	})

	markdown, _, err := BuildMarkdown(newInput())
	if err != nil {
		t.Fatalf("BuildMarkdown() error = %v", err)
	}
	html, _, err := BuildHTML(newInput())
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	envelope, _, err := BuildJSON(newInput(), Options{AgentEnvelope: true})
	if err != nil {
		t.Fatalf("BuildJSON(agent envelope) error = %v", err)
	}
	encodedView, _ := json.Marshal(view)
	encodedEnvelope, _ := json.Marshal(envelope)
	for name, output := range map[string]string{
		"agent envelope": string(encodedEnvelope),
		"HTML":           html,
		"JSON":           string(encodedView),
		"Markdown":       markdown,
	} {
		if strings.Contains(output, "covered_by") {
			t.Fatalf("%s laundered declaration mapping into coverage vocabulary: %s", name, output)
		}
	}
}

func TestBuildJSONClassifiesNonsemanticCommandEvidenceClasses(t *testing.T) {
	for _, evidenceClass := range []string{"benchmark", "declared_contract_admission_route", "helper_or_testkit", "declared_property_or_fuzz_route"} {
		t.Run(evidenceClass, func(t *testing.T) {
			input := validCoverageInput(t)
			entry := inventoryEntry(input)
			entry["evidenceClass"] = evidenceClass
			if evidenceClass == "benchmark" || evidenceClass == "helper_or_testkit" {
				entry["falsifier"] = nil
				entry["oracle"] = nil
			}
			entry["nonClaims"] = []any{"Nonsemantic command evidence fixture does not prove command behavior."}

			view, exitCode, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error = %v", err)
			}
			if exitCode == 0 {
				t.Fatalf("%s evidence satisfied command semantic closure: %#v", evidenceClass, view)
			}
			command := view.(map[string]any)["commandCoverage"].([]any)[0].(map[string]any)
			if command["coverageState"] != "command_owner_nonsemantic_evidence" {
				t.Fatalf("%s should not satisfy semantic command closure: %#v", evidenceClass, command)
			}
			requireClassificationIncludes(t, view.(map[string]any), "failures", "failureClassifications", "failure", "nonsemantic_command_evidence:proofkit.coverage.command", "nonsemantic_command_evidence")
		})
	}
}

func TestBuildJSONWarnsForNonsemanticCommandEvidenceInAdvisoryScope(t *testing.T) {
	input := validCoverageInput(t)
	input.(map[string]any)["coverageUniverse"].(map[string]any)["completenessDeclaration"] = "selected_paths_advisory"
	entry := inventoryEntry(input)
	entry["evidenceClass"] = "declared_contract_admission_route"
	entry["nonClaims"] = []any{"Contract admission evidence fixture does not prove command behavior."}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("advisory scope should warn instead of fail on nonsemantic command evidence: %#v", view)
	}
	command := view.(map[string]any)["commandCoverage"].([]any)[0].(map[string]any)
	if command["coverageState"] != "command_owner_nonsemantic_evidence" {
		t.Fatalf("contract evidence should not satisfy semantic command closure: %#v", command)
	}
	requireClassificationIncludes(t, view.(map[string]any), "warnings", "warningClassifications", "warning", "nonsemantic_command_evidence:proofkit.coverage.command", "nonsemantic_command_evidence")
}

func TestBuildJSONWarnsWhenOwnerInvariantHasNoInventory(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	record["ownerInvariantRegistry"] = map[string]any{
		"schemaVersion": json.Number("1"),
		"registryId":    "proofkit.coverage.owner-invariants",
		"invariants": []any{
			map[string]any{
				"ownerInvariantId": "invariant.coverage.uncovered",
				"ownerId":          "proofkit.coverage",
				"sourcePath":       "docs/specs/proofkit-coverage/requirements.v1.json",
				"summary":          "Coverage owner invariant rows must emit missing-inventory warnings.",
				"nonClaims":        []any{"Owner invariant fixture does not claim native execution."},
			},
		},
		"nonClaims": []any{"Owner invariant registry fixture is caller-owned."},
	}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("missing owner-invariant coverage is advisory: %#v", view)
	}
	coverage := view.(map[string]any)["ownerInvariantCoverage"].([]any)
	if len(coverage) != 1 {
		t.Fatalf("ownerInvariantCoverage len=%d want 1: %#v", len(coverage), coverage)
	}
	invariant := coverage[0].(map[string]any)
	if invariant["coverageState"] != "missing_test_inventory" {
		t.Fatalf("unexpected owner invariant coverage: %#v", invariant)
	}
	if got := stringArray(invariant["warnings"]); len(got) != 1 || got[0] != "missing_owner_invariant_inventory:invariant.coverage.uncovered" {
		t.Fatalf("row-local owner invariant warnings=%v", got)
	}
	requireClassificationIncludes(t, view.(map[string]any), "warnings", "warningClassifications", "warning", "missing_owner_invariant_inventory:invariant.coverage.uncovered", "missing_declared_test_route")
}

func TestBuildJSONRequiresExactlyOneProofInput(t *testing.T) {
	input := validCoverageInput(t)
	input.(map[string]any)["compactProofContract"] = map[string]any{"schema_version": 1}
	_, _, err := BuildJSON(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("unexpected both-proof-input error: %v", err)
	}
	delete(input.(map[string]any), "compactProofContract")
	input.(map[string]any)["requirementProofBinding"] = nil
	_, _, err = BuildJSON(input, Options{})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("unexpected missing-proof-input error: %v", err)
	}
}

func TestBuildHTMLEscapesCoverageSpecificCallerFields(t *testing.T) {
	input := validCoverageInput(t)
	sourceRequirement(input)["invariant"] = "Invariant <script>alert(1)</script>"
	entry := inventoryEntry(input)
	entry["selector"] = "go test ./internal/coverage -run TestEvil"
	entry["oracle"].(map[string]any)["assertionSummary"] = "Oracle <img src=x onerror=alert(1)>"
	entry["sourcePath"] = "internal/command/requirementcoverageview/evil_test.go"
	testSurface := input.(map[string]any)["coverageUniverse"].(map[string]any)["testSurfaces"].([]any)[0].(map[string]any)
	testSurface["path"] = "internal/command/requirementcoverageview/evil_test.go"

	output, exitCode, err := BuildHTML(input)
	if err != nil {
		t.Fatalf("BuildHTML() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildHTML() exitCode=%d", exitCode)
	}
	for _, forbidden := range []string{"<script>alert(1)</script>", "<img src=x"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("HTML contains raw caller payload %q:\n%s", forbidden, output)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;", "Test evidence"} {
		if !strings.Contains(output, want) {
			t.Fatalf("HTML missing escaped payload/detail %q:\n%s", want, output)
		}
	}
}

func TestDiagnosticClassIDVocabulary(t *testing.T) {
	cases := []struct {
		diagnostic string
		want       string
	}{
		{"dead_zone:unbound_code_surface:proofkit.unbound.code", "declared_dead_zone"},
		{"dead_zone_advisory:unbound_code_surface:proofkit.unbound.code", "declared_dead_zone"},
		{"missing_proof_binding_route:REQ-PROOFKIT-COVERAGE-001", "missing_requirement_binding"},
		{"proof_binding_unknown_requirement:REQ-PROOFKIT-COVERAGE-999", "missing_requirement_binding"},
		{"missing_test_inventory:REQ-PROOFKIT-COVERAGE-001", "missing_declared_test_route"},
		{"missing_command_declared_semantic_falsifier_route:proofkit.coverage.command", "missing_declared_test_route"},
		{"route_only_nonclaim:REQ-PROOFKIT-COVERAGE-001", "routing_smoke_only"},
		{"command_route_only_nonclaim:proofkit.coverage.command", "routing_smoke_only"},
		{"unknown_requirement_ref:test.routing_smoke_nonclaim:REQ-PROOFKIT-COVERAGE-999", "unknown_reference"},
		{"unknown_requirement_ref:test.coverage:REQ-UNKNOWN", "unknown_reference"},
		{"unknown_owner_invariant_ref:test.coverage:invariant.unknown", "unknown_reference"},
		{"unknown_command_or_witness_ref:test.coverage:proofkit.unknown", "unknown_reference"},
		{"full_repository_source_requirement_outside_owner_scope:REQ-PROOFKIT-COVERAGE-999", "owner_scope_violation"},
		{"inventory_entry_owner_outside_scope:test.coverage:proofkit.other", "owner_scope_violation"},
		{"test_inventory_failed:repo.tests", "failed_test_inventory"},
		{"mapped_to_declared_governance_or_release_route_nonproduct:REQ-PROOFKIT-COVERAGE-001", "nonsemantic_governance_evidence"},
		{"missing_owner_invariant_inventory:invariant.coverage.semantic", "missing_declared_test_route"},
		{"nonsemantic_command_evidence:proofkit.coverage.command", "nonsemantic_command_evidence"},
		{"not_applicable:REQ-PROOFKIT-COVERAGE-001", "not_applicable_with_reason"},
		{"future_unmapped_diagnostic:example", "unclassified_gap"},
	}
	for _, item := range cases {
		t.Run(item.diagnostic, func(t *testing.T) {
			if got := diagnosticClassID(item.diagnostic); got != item.want {
				t.Fatalf("diagnosticClassID(%q)=%q want %q", item.diagnostic, got, item.want)
			}
		})
	}
}

func requireExactClassifications(t *testing.T, view map[string]any, diagnosticsField string, classificationsField string, severity string, expected map[string]string) {
	t.Helper()
	diagnostics := stringArray(view[diagnosticsField])
	if len(diagnostics) != len(expected) {
		t.Fatalf("%s=%v, want diagnostics %v", diagnosticsField, diagnostics, expected)
	}
	for _, diagnostic := range diagnostics {
		if _, ok := expected[diagnostic]; !ok {
			t.Fatalf("%s has unexpected diagnostic %q; all diagnostics=%v expected=%v", diagnosticsField, diagnostic, diagnostics, expected)
		}
	}
	classifications, ok := view[classificationsField].([]any)
	if !ok {
		t.Fatalf("%s missing or not array: %#v", classificationsField, view[classificationsField])
	}
	if len(classifications) != len(expected) {
		t.Fatalf("%s len=%d want %d: %#v", classificationsField, len(classifications), len(expected), classifications)
	}
	seen := map[string]struct{}{}
	for _, raw := range classifications {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s contains non-object item: %#v", classificationsField, raw)
		}
		diagnostic, ok := item["diagnostic"].(string)
		if !ok {
			t.Fatalf("%s item missing diagnostic: %#v", classificationsField, item)
		}
		if _, duplicate := seen[diagnostic]; duplicate {
			t.Fatalf("%s duplicates diagnostic %q: %#v", classificationsField, diagnostic, classifications)
		}
		seen[diagnostic] = struct{}{}
		if item["severity"] != severity {
			t.Fatalf("%s diagnostic %q severity=%v want %q", classificationsField, diagnostic, item["severity"], severity)
		}
		if item["classificationId"] != expected[diagnostic] {
			t.Fatalf("%s diagnostic %q classificationId=%v want %q", classificationsField, diagnostic, item["classificationId"], expected[diagnostic])
		}
	}
}

func requireClassificationIncludes(t *testing.T, view map[string]any, diagnosticsField string, classificationsField string, severity string, diagnostic string, classificationID string) {
	t.Helper()
	diagnostics := stringArray(view[diagnosticsField])
	if !containsString(diagnostics, diagnostic) {
		t.Fatalf("%s missing %q; all diagnostics=%v", diagnosticsField, diagnostic, diagnostics)
	}
	classifications, ok := view[classificationsField].([]any)
	if !ok {
		t.Fatalf("%s missing or not array: %#v", classificationsField, view[classificationsField])
	}
	for _, raw := range classifications {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s contains non-object item: %#v", classificationsField, raw)
		}
		if item["diagnostic"] != diagnostic {
			continue
		}
		if item["severity"] != severity {
			t.Fatalf("%s diagnostic %q severity=%v want %q", classificationsField, diagnostic, item["severity"], severity)
		}
		if item["classificationId"] != classificationID {
			t.Fatalf("%s diagnostic %q classificationId=%v want %q", classificationsField, diagnostic, item["classificationId"], classificationID)
		}
		return
	}
	t.Fatalf("%s missing classification for %q; all classifications=%#v", classificationsField, diagnostic, classifications)
}

func validCoverageInput(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "viewInputId": "proofkit.coverage.view",
  "requirementSource": {
    "schemaVersion": 1,
    "sourceId": "proofkit.coverage.source",
    "specPackagePath": "docs/specs/proofkit-coverage",
    "overviewPath": "docs/specs/proofkit-coverage/overview.md",
    "requirementsPath": "docs/specs/proofkit-coverage/requirements.v1.json",
    "requirements": [
      {
        "requirementId": "REQ-PROOFKIT-COVERAGE-001",
        "ownerId": "proofkit.coverage",
        "invariant": "Coverage view must not count proof routes as semantic test coverage.",
        "claimLevel": "blocking",
        "riskClass": "high",
        "proofBindingRefs": ["proofkit/requirement-bindings.json"],
        "nonClaimRefs": [],
        "nonClaims": ["Coverage fixture does not execute tests."],
        "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
        "deferral": null,
        "updatePolicy": {
          "reviewOwnerId": "proofkit.coverage",
          "requiresImpactDeclaration": true,
          "requiresProofBindingReview": true
        }
      }
    ],
    "nonClaims": ["Coverage fixture source does not own native tests."]
  },
  "requirementProofBinding": {
    "schemaVersion": 1,
    "bindingId": "proofkit.coverage.binding",
    "requirements": [
      {
        "requirementId": "REQ-PROOFKIT-COVERAGE-001",
        "ownerId": "proofkit.coverage",
        "specPath": "docs/specs/proofkit-coverage/requirements.v1.json",
        "claimLevel": "blocking",
        "proofState": "witness_backed",
        "nonClaims": ["Coverage fixture binding does not execute witnesses."]
      }
    ],
    "bindings": [
      {
        "requirementId": "REQ-PROOFKIT-COVERAGE-001",
        "scenarioId": "proofkit.coverage.scenario",
        "witnessId": "proofkit.coverage.witness",
        "witnessKind": "contract",
        "witnessPath": "internal/command/requirementcoverageview/requirementcoverageview_test.go",
        "commandIds": ["proofkit.coverage.command"],
        "environmentClasses": ["local-go"]
      }
    ],
    "witnessCommands": [
      {
        "commandId": "proofkit.coverage.command",
        "command": "go test ./internal/command/requirementcoverageview",
        "environmentClass": "local-go"
      }
    ],
    "selection": {"changedPaths": [], "ownerIds": [], "requirementIds": []},
    "nonClaims": ["Coverage fixture binding does not prove command pass evidence."]
  },
  "compactProofContract": null,
  "ownerInvariantRegistry": null,
  "coverageUniverse": {
    "schemaVersion": 1,
    "universeId": "proofkit.coverage.universe",
    "authority": "caller_owned_inventory",
    "completenessDeclaration": "selected_owner_surfaces",
    "ownerIds": ["proofkit.coverage"],
    "codeSurfaces": [{"surfaceId": "proofkit.coverage.code", "ownerId": "proofkit.coverage", "path": "internal/command/requirementcoverageview"}],
    "specSurfaces": [{"surfaceId": "proofkit.coverage.spec", "ownerId": "proofkit.coverage", "path": "docs/specs/proofkit-coverage/requirements.v1.json"}],
    "testSurfaces": [{"surfaceId": "proofkit.coverage.test", "ownerId": "proofkit.coverage", "path": "internal/command/requirementcoverageview/requirementcoverageview_test.go"}],
    "commandRefs": ["proofkit.coverage.command"],
    "nonClaims": ["Coverage universe is selected-owner scope only."]
  },
  "testEvidenceInventory": {
    "schemaVersion": 1,
    "inventoryId": "proofkit.coverage.inventory",
    "authority": "caller_owned_inventory",
    "entries": [
      {
        "testId": "test.coverage.semantic",
        "selector": "go test ./internal/command/requirementcoverageview -run TestCoverage",
        "sourcePath": "internal/command/requirementcoverageview/requirementcoverageview_test.go",
        "ownerId": "proofkit.coverage",
        "evidenceClass": "declared_semantic_falsifier_route",
        "requirementRefs": ["REQ-PROOFKIT-COVERAGE-001"],
        "ownerInvariantRefs": [],
        "commandRefs": ["proofkit.coverage.command"],
        "witnessRefs": ["proofkit.coverage.witness"],
        "falsifier": {
          "falsifierId": "falsifier.coverage.semantic",
          "negativeCaseId": "case.coverage.route-only",
          "wrongImplementationClassId": "wrong.coverage.counts-route-only",
          "dominanceGroup": "coverage.semantic",
          "supersedes": []
        },
        "oracle": {
          "oracleId": "oracle.coverage.semantic",
          "oracleKind": "negative_exit_and_diagnostic",
          "expectedPublicOutcome": "failed report with diagnostic",
          "assertionSummary": "Route-only evidence leaves blocking semantic coverage failed."
        },
        "nonClaims": []
      }
    ],
    "nonClaims": ["Coverage inventory fixture does not execute native tests."]
  },
  "localEnvironmentPolicy": null,
  "options": {"scope": "graph"}
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode coverage fixture: %v", err)
	}
	return input
}

func validCompactCoverageContract(bindings ...[]any) map[string]any {
	if len(bindings) == 0 {
		bindings = [][]any{compactCoverageBinding("proofkit.coverage::scenario")}
	}
	bindingRows := make([]any, 0, len(bindings))
	for _, binding := range bindings {
		bindingRows = append(bindingRows, binding)
	}
	return map[string]any{
		"schema_version":        json.Number("1"),
		"authority_state":       "canonical",
		"contract_id":           "proofkit.coverage.compact",
		"contract_kind":         "requirement_proof_binding",
		"normalization_profile": "proofkit.compact.v1",
		"non_claims":            []any{"Compact coverage fixture does not execute witnesses."},
		"surface_columns":       []any{"surface_id", "required_environment_classes", "preconditioned_environment_classes"},
		"surfaces":              []any{[]any{"proofkit.coverage", []any{"local-go"}, []any{}}},
		"witness_columns":       []any{"selector", "environment_classes", "verify_commands", "resolution_order_index"},
		"binding_columns": []any{
			"requirement_id",
			"surface_id",
			"scenario_id",
			"invariant_role",
			"owned_invariant",
			"proof_contract_state",
			"blocking_status",
			"required_environment_classes",
			"positive_witness",
			"falsification_witness",
			"verify_commands",
			"mutation_resistance_state",
		},
		"bindings": bindingRows,
	}
}

func compactCoverageBinding(scenarioID string) []any {
	selectorSuffix := strings.NewReplacer("::", "_", ".", "_").Replace(scenarioID)
	return []any{
		"REQ-PROOFKIT-COVERAGE-001",
		"proofkit.coverage",
		scenarioID,
		"contract",
		"proofkit.coverage.invariant",
		"witness_backed",
		"blocking",
		[]any{"local-go"},
		compactCoverageWitness("internal/command/requirementcoverageview/requirementcoverageview_test.go::positive."+selectorSuffix, json.Number("0")),
		compactCoverageWitness("internal/command/requirementcoverageview/requirementcoverageview_test.go::falsification."+selectorSuffix, json.Number("1")),
		[]any{"go test ./internal/command/requirementcoverageview"},
		"no_known_advisory_gap",
	}
}

func compactCoverageWitness(selector string, order json.Number) []any {
	return []any{selector, []any{"local-go"}, []any{"go test ./internal/command/requirementcoverageview"}, order}
}

func findScenario(t *testing.T, scenarios []any, scenarioID string) map[string]any {
	t.Helper()
	for _, rawScenario := range scenarios {
		scenario := rawScenario.(map[string]any)
		if scenario["scenarioId"] == scenarioID {
			return scenario
		}
	}
	t.Fatalf("scenario %s not found in %#v", scenarioID, scenarios)
	return nil
}

func inventoryEntry(input any) map[string]any {
	inventory := input.(map[string]any)["testEvidenceInventory"].(map[string]any)
	return inventory["entries"].([]any)[0].(map[string]any)
}

func addUnboundCodeSurface(input any, declaration string) {
	universe := input.(map[string]any)["coverageUniverse"].(map[string]any)
	universe["completenessDeclaration"] = declaration
	universe["ownerIds"] = append(universe["ownerIds"].([]any), "proofkit.unbound")
	universe["codeSurfaces"] = append(universe["codeSurfaces"].([]any), map[string]any{
		"ownerId":   "proofkit.unbound",
		"path":      "internal/unbound",
		"surfaceId": "proofkit.unbound.code",
	})
}

func sourceRequirement(input any) map[string]any {
	source := input.(map[string]any)["requirementSource"].(map[string]any)
	return source["requirements"].([]any)[0].(map[string]any)
}

func stringArrayContains(raw any, want string) bool {
	for _, value := range stringArray(raw) {
		if value == want {
			return true
		}
	}
	return false
}
