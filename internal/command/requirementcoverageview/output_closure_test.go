package requirementcoverageview

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAdmitOutputRejectsRequirementProofProjectionDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "scenario removal",
			mutate: func(row map[string]any) {
				row["scenarios"] = []any{}
				row["scenarioCount"] = 0
			},
			want: "proofState and scenarios are inconsistent",
		},
		{
			name: "scenario count",
			mutate: func(row map[string]any) {
				row["scenarioCount"] = 0
			},
			want: "scenarioCount does not match scenarios",
		},
		{
			name: "command union",
			mutate: func(row map[string]any) {
				row["commandIds"] = []any{}
			},
			want: "commandIds are not derived from scenarios",
		},
		{
			name: "environment union",
			mutate: func(row map[string]any) {
				row["environmentClasses"] = []any{}
			},
			want: "environmentClasses are not derived from scenarios",
		},
		{
			name: "witness union",
			mutate: func(row map[string]any) {
				row["witnessRefs"] = []any{}
			},
			want: "witnessRefs are not derived from scenarios",
		},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error=%v", err)
			}
			record := view.(map[string]any)
			item.mutate(record["requirementCoverage"].([]any)[0].(map[string]any))
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitOutput() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitOutputRejectsIncompleteProjectedTestFields(t *testing.T) {
	for _, field := range projectedTestKeys {
		t.Run(field, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error=%v", err)
			}
			record := view.(map[string]any)
			mutateProjectedTestCopies(t, record, "test.coverage.semantic", func(test map[string]any) {
				delete(test, field)
			})
			if _, err := AdmitOutput(record); err == nil {
				t.Fatalf("AdmitOutput() admitted projected test without %s", field)
			}
		})
	}
}

func TestAdmitOutputRejectsMissingInverseParentProjection(t *testing.T) {
	for _, rowsKey := range []string{"requirementCoverage", "ownerInvariantCoverage", "commandCoverage"} {
		t.Run(rowsKey, func(t *testing.T) {
			record := coverageRecordWithOwnerInvariant(t)
			row := record[rowsKey].([]any)[0].(map[string]any)
			row["tests"] = []any{}
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "missing from retained parent") {
				t.Fatalf("AdmitOutput() error=%v, want inverse parent projection rejection", err)
			}
		})
	}
}

func TestAdmitOutputRejectsCompactProjectionDrift(t *testing.T) {
	buildCompact := func(t *testing.T) map[string]any {
		t.Helper()
		input := validCoverageInput(t).(map[string]any)
		input["requirementProofBinding"] = nil
		input["compactProofContract"] = validCompactCoverageContract()
		input["localEnvironmentPolicy"] = map[string]any{
			"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"},
		}
		inventoryEntry(input)["witnessRefs"] = []any{}
		view, _, err := BuildJSON(input, Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error=%v", err)
		}
		return view.(map[string]any)
	}
	for _, item := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "command ids", mutate: func(row map[string]any) { row["commandIds"] = []any{"proofkit.coverage.other"} }, want: "commandIds are not derived from projected tests"},
		{name: "witness selector", mutate: func(row map[string]any) {
			row["declaredWitnessRoutes"].([]any)[0].(map[string]any)["selector"] = "not-a-selector"
		}, want: "repo/path::stable_anchor"},
		{name: "verify command", mutate: func(row map[string]any) { row["verifyCommands"] = []any{"go test ./...; false"} }, want: "shell control tokens"},
		{name: "valid witness selector substitution", mutate: func(row map[string]any) {
			row["declaredWitnessRoutes"].([]any)[0].(map[string]any)["selector"] = "internal/command/requirementcoverageview/requirementcoverageview_test.go::falsification.substituted"
		}, want: "witnessRouteId does not match"},
		{name: "valid verify command substitution", mutate: func(row map[string]any) {
			row["verifyCommands"] = []any{"go test ./internal/command/requirementcontext"}
		}, want: "verifyCommands are not derived from scenarios"},
		{name: "delimiter collision in route verify commands", mutate: func(row map[string]any) {
			scenario := row["scenarios"].([]any)[0].(map[string]any)
			scenarioRoute := scenario["declaredWitnessRoutes"].([]any)[0].(map[string]any)
			projectedRoute := row["declaredWitnessRoutes"].([]any)[0].(map[string]any)
			scenarioRoute["verifyCommands"] = []any{"alpha", "beta"}
			projectedRoute["verifyCommands"] = []any{"alpha\x1fbeta"}
			scenario["verifyCommands"] = []any{"alpha", "beta", "go test ./internal/command/requirementcoverageview"}
			row["verifyCommands"] = []any{"alpha", "beta", "go test ./internal/command/requirementcoverageview"}
		}, want: "declaredWitnessRoutes are not the exact scenario route union"},
		{name: "valid but unscoped scenario id", mutate: func(row map[string]any) {
			row["scenarios"].([]any)[0].(map[string]any)["scenarioId"] = "arbitrary-scenario"
		}, want: "surface_id::stable_anchor"},
		{name: "scenario surface mismatch", mutate: func(row map[string]any) {
			row["scenarios"].([]any)[0].(map[string]any)["scenarioId"] = "other.surface::scenario"
		}, want: "scenarioId must be scoped to surfaceId"},
		{name: "scenario parent requirement mismatch", mutate: func(row map[string]any) {
			row["scenarios"].([]any)[0].(map[string]any)["requirementId"] = "REQ-PROOFKIT-COVERAGE-OTHER"
		}, want: "requirementId must match its parent requirement row"},
	} {
		t.Run(item.name, func(t *testing.T) {
			record := buildCompact(t)
			item.mutate(record["requirementCoverage"].([]any)[0].(map[string]any))
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitOutput() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitOutputRequiresEveryCompactScenarioAndRouteField(t *testing.T) {
	compactRecord := func(t *testing.T) map[string]any {
		t.Helper()
		input := validCoverageInput(t).(map[string]any)
		input["requirementProofBinding"] = nil
		input["compactProofContract"] = validCompactCoverageContract()
		input["localEnvironmentPolicy"] = map[string]any{
			"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"},
		}
		inventoryEntry(input)["witnessRefs"] = []any{}
		view, _, err := BuildJSON(input, Options{})
		if err != nil {
			t.Fatalf("BuildJSON() error=%v", err)
		}
		return view.(map[string]any)
	}
	scenarioKeys := []string{"bindingRecordId", "bindingVerifyCommands", "declaredWitnessRoutes", "environmentClasses", "requiredEnvironmentClasses", "requirementId", "scenarioId", "surfaceId", "verifyCommands"}
	for _, field := range scenarioKeys {
		t.Run("scenario/"+field, func(t *testing.T) {
			record := compactRecord(t)
			scenario := record["requirementCoverage"].([]any)[0].(map[string]any)["scenarios"].([]any)[0].(map[string]any)
			delete(scenario, field)
			if _, err := AdmitOutput(record); err == nil {
				t.Fatalf("AdmitOutput() admitted compact scenario without %s", field)
			}
		})
	}
	for _, field := range compactWitnessRouteKeys() {
		t.Run("route/"+field, func(t *testing.T) {
			record := compactRecord(t)
			route := record["requirementCoverage"].([]any)[0].(map[string]any)["scenarios"].([]any)[0].(map[string]any)["declaredWitnessRoutes"].([]any)[0].(map[string]any)
			delete(route, field)
			if _, err := AdmitOutput(record); err == nil {
				t.Fatalf("AdmitOutput() admitted compact route without %s", field)
			}
		})
	}
}

func TestAdmitOutputRequiresEveryDeclaredRootField(t *testing.T) {
	for _, field := range outputKeys {
		t.Run(field, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error=%v", err)
			}
			record := view.(map[string]any)
			delete(record, field)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "missing required field "+field) {
				t.Fatalf("AdmitOutput() error=%v, want missing required field %s", err, field)
			}
		})
	}
}

func TestAdmitOutputRequiresEveryCoverageRowField(t *testing.T) {
	for _, descriptor := range coverageRowDescriptors {
		for _, field := range coverageRowKeys(descriptor.rowsKey, "structured") {
			t.Run(descriptor.rowsKey+"/"+field, func(t *testing.T) {
				record := coverageRecordWithOwnerInvariant(t)
				delete(record[descriptor.rowsKey].([]any)[0].(map[string]any), field)
				if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "missing required field "+field) {
					t.Fatalf("AdmitOutput() error=%v, want missing required field %s", err, field)
				}
			})
		}
	}
}

func TestAdmitOutputValidatesEveryCoverageRowMetadataField(t *testing.T) {
	tests := []struct {
		name    string
		rowsKey string
		field   string
		value   any
	}{
		{name: "requirement claim level", rowsKey: "requirementCoverage", field: "claimLevel", value: json.Number("7")},
		{name: "requirement invariant", rowsKey: "requirementCoverage", field: "invariant", value: json.Number("7")},
		{name: "requirement lifecycle", rowsKey: "requirementCoverage", field: "lifecycleState", value: "unknown"},
		{name: "requirement non claims", rowsKey: "requirementCoverage", field: "nonClaims", value: "not-an-array"},
		{name: "requirement owner", rowsKey: "requirementCoverage", field: "ownerId", value: json.Number("7")},
		{name: "requirement path", rowsKey: "requirementCoverage", field: "specPath", value: "docs/../outside.json"},
		{name: "owner invariant non claims", rowsKey: "ownerInvariantCoverage", field: "nonClaims", value: "not-an-array"},
		{name: "owner invariant owner", rowsKey: "ownerInvariantCoverage", field: "ownerId", value: json.Number("7")},
		{name: "owner invariant path", rowsKey: "ownerInvariantCoverage", field: "sourcePath", value: "docs/../outside.json"},
		{name: "owner invariant summary", rowsKey: "ownerInvariantCoverage", field: "summary", value: json.Number("7")},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			record := coverageRecordWithOwnerInvariant(t)
			record[item.rowsKey].([]any)[0].(map[string]any)[item.field] = item.value
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.field) {
				t.Fatalf("AdmitOutput() error=%v, want %s metadata rejection", err, item.field)
			}
		})
	}
}

func TestAdmitOutputRejectsNonCanonicalWireProjectionText(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(map[string]any)
	}{
		{
			name:  "requirement invariant",
			field: "invariant",
			mutate: func(record map[string]any) {
				row := record["requirementCoverage"].([]any)[0].(map[string]any)
				row["invariant"] = " " + row["invariant"].(string) + " "
			},
		},
		{
			name:  "test selector",
			field: "selector",
			mutate: func(record map[string]any) {
				row := record["requirementCoverage"].([]any)[0].(map[string]any)
				test := row["tests"].([]any)[0].(map[string]any)
				test["selector"] = " " + test["selector"].(string) + " "
			},
		},
		{
			name:  "test inventory digest",
			field: "testInventoryDigest",
			mutate: func(record map[string]any) {
				basis := record["coverageBasis"].(map[string]any)
				basis["testInventoryDigest"] = " " + basis["testInventoryDigest"].(string) + " "
			},
		},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			record := coverageRecordWithOwnerInvariant(t)
			item.mutate(record)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), item.field) {
				t.Fatalf("AdmitOutput() error=%v, want non-canonical %s rejection", err, item.field)
			}
		})
	}
}

func TestAdmitOutputRequiresCanonicalCoverageRowOrder(t *testing.T) {
	secondIDs := map[string]string{
		"requirementCoverage":    "REQ-PROOFKIT-COVERAGE-000",
		"ownerInvariantCoverage": "invariant.coverage.alpha",
		"commandCoverage":        "proofkit.coverage.alpha",
	}
	for _, descriptor := range coverageRowDescriptors {
		t.Run(descriptor.rowsKey, func(t *testing.T) {
			record := coverageRecordWithOwnerInvariant(t)
			rows := record[descriptor.rowsKey].([]any)
			second := cloneCoverageJSONValue(rows[0]).(map[string]any)
			second[descriptor.idKey] = secondIDs[descriptor.rowsKey]
			record[descriptor.rowsKey] = append(rows, second)
			record[descriptor.countKey] = 2
			if err := admitCoverageOutputRows(record, descriptor.rowsKey, descriptor.countKey, descriptor.idKey, record["proofMode"].(string)); err == nil || !strings.Contains(err.Error(), "sorted and unique") {
				t.Fatalf("admitCoverageOutputRows() error=%v, want canonical-order rejection", err)
			}
		})
	}
}

func TestAdmitOutputRetainsCommandOwnedNonClaims(t *testing.T) {
	view, _, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	record := view.(map[string]any)
	record["nonClaims"] = []any{"Benign caller-owned non-claim."}
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "command-owned boundary") {
		t.Fatalf("AdmitOutput() error=%v, want command-owned non-claim rejection", err)
	}
}

func TestAdmitOutputReplaysMissingInventoryWarning(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	input["testEvidenceInventory"] = nil
	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	record := view.(map[string]any)
	setCoverageAggregateDiagnostics(
		record,
		stringArray(record["failures"]),
		withoutDiagnostic(stringArray(record["warnings"]), "missing_test_inventory:input"),
	)
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "missing_test_inventory:input warning") {
		t.Fatalf("AdmitOutput() error=%v, want missing-inventory warning rejection", err)
	}
}

func TestAdmitOutputRejectsRemovedValidUnmappedInventoryEntry(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["evidenceClass"] = "helper_or_testkit"
	entry["commandRefs"] = []any{}
	entry["ownerInvariantRefs"] = []any{}
	entry["requirementRefs"] = []any{}
	entry["witnessRefs"] = []any{}
	delete(entry, "falsifier")
	delete(entry, "oracle")
	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	record := view.(map[string]any)
	if len(record["unmappedTests"].([]any)) != 1 {
		t.Fatalf("unmappedTests=%#v, want one valid helper entry", record["unmappedTests"])
	}
	record["unmappedTests"] = []any{}
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "testInventoryDigest") {
		t.Fatalf("AdmitOutput() error=%v, want inventory digest rejection", err)
	}
}

func TestAdmitOutputReplaysOwnerScopeFailures(t *testing.T) {
	input := validCoverageInput(t)
	inventoryEntry(input)["ownerId"] = "proofkit.other"
	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	record := view.(map[string]any)
	diagnostic := "inventory_entry_owner_outside_scope:test.coverage.semantic:proofkit.other"
	setCoverageAggregateDiagnostics(
		record,
		withoutDiagnostic(stringArray(record["failures"]), diagnostic),
		stringArray(record["warnings"]),
	)
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "owner-scope failures") {
		t.Fatalf("AdmitOutput() error=%v, want owner-scope diagnostic rejection", err)
	}
}

func TestAdmitOutputReplaysFullRepositorySourceOwnerScopeFailures(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	universe := input["coverageUniverse"].(map[string]any)
	universe["completenessDeclaration"] = "full_repository"
	source := input["requirementSource"].(map[string]any)
	requirements := source["requirements"].([]any)
	outOfScope := cloneCoverageJSONValue(requirements[0]).(map[string]any)
	outOfScope["requirementId"] = "REQ-PROOFKIT-COVERAGE-002"
	outOfScope["ownerId"] = "proofkit.other"
	outOfScope["updatePolicy"].(map[string]any)["reviewOwnerId"] = "proofkit.other"
	source["requirements"] = append(requirements, outOfScope)

	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	record := view.(map[string]any)
	diagnostic := "full_repository_source_requirement_outside_owner_scope:REQ-PROOFKIT-COVERAGE-002"
	setCoverageAggregateDiagnostics(
		record,
		withoutDiagnostic(stringArray(record["failures"]), diagnostic),
		stringArray(record["warnings"]),
	)
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "owner-scope failures") {
		t.Fatalf("AdmitOutput() error=%v, want full-repository owner-scope rejection", err)
	}
}

func TestAdmitOutputRequiresEveryCoverageBasisField(t *testing.T) {
	for _, field := range coverageBasisKeys {
		t.Run(field, func(t *testing.T) {
			view, _, err := BuildJSON(validCoverageInput(t), Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error=%v", err)
			}
			record := view.(map[string]any)
			delete(record["coverageBasis"].(map[string]any), field)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "missing required field "+field) {
				t.Fatalf("AdmitOutput() error=%v, want missing coverageBasis field %s", err, field)
			}
		})
	}
}

func TestAdmitOutputRequiresModeOwnedIdentity(t *testing.T) {
	structured, _, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil {
		t.Fatalf("BuildJSON(structured) error=%v", err)
	}
	compactInput := validCoverageInput(t).(map[string]any)
	compactInput["requirementProofBinding"] = nil
	compactInput["compactProofContract"] = validCompactCoverageContract()
	compactInput["localEnvironmentPolicy"] = map[string]any{
		"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"},
	}
	inventoryEntry(compactInput)["witnessRefs"] = []any{}
	compact, _, err := BuildJSON(compactInput, Options{})
	if err != nil {
		t.Fatalf("BuildJSON(compact) error=%v", err)
	}
	for _, item := range []struct {
		name   string
		record map[string]any
		mutate func(map[string]any)
		want   string
	}{
		{name: "structured binding id", record: structured.(map[string]any), mutate: func(record map[string]any) { record["bindingId"] = "" }, want: "bindingId"},
		{name: "structured contract id", record: structured.(map[string]any), mutate: func(record map[string]any) { record["contractId"] = "proofkit.coverage.contract" }, want: "contractId must be empty"},
		{name: "compact binding id", record: compact.(map[string]any), mutate: func(record map[string]any) { record["bindingId"] = "proofkit.coverage.binding" }, want: "bindingId must be empty"},
		{name: "compact contract id", record: compact.(map[string]any), mutate: func(record map[string]any) { record["contractId"] = "" }, want: "contractId"},
	} {
		t.Run(item.name, func(t *testing.T) {
			encoded, err := json.Marshal(item.record)
			if err != nil {
				t.Fatalf("json.Marshal() error=%v", err)
			}
			copy := map[string]any{}
			decoder := json.NewDecoder(strings.NewReader(string(encoded)))
			decoder.UseNumber()
			if err := decoder.Decode(&copy); err != nil {
				t.Fatalf("json.Decode() error=%v", err)
			}
			item.mutate(copy)
			if _, err := AdmitOutput(copy); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitOutput() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestAdmitOutputReplaysFailedInventoryQualitySemantics(t *testing.T) {
	input := validCoverageInput(t)
	inventoryEntry(input)["qualityFindings"] = []any{map[string]any{
		"class": "implementation_mirror", "evidenceRefs": []any{"test.coverage.semantic"},
		"findingId":        "finding.coverage.implementation-mirror",
		"nonClaims":        []any{"Caller-owned finding does not prove native execution."},
		"ownerReviewState": "confirmed", "severity": "failure",
	}}
	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	if exitCode == 0 {
		t.Fatal("failure-severity quality finding must fail coverage output")
	}
	record := view.(map[string]any)
	setCoverageAggregateDiagnostics(
		record,
		withoutDiagnostic(stringArray(record["failures"]), "test_inventory_failed:proofkit.coverage.inventory"),
		stringArray(record["warnings"]),
	)
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "test-inventory failures") {
		t.Fatalf("AdmitOutput() error=%v, want retained inventory-failure rejection", err)
	}
}

func TestAdmitOutputRetainsFailedInventoryEntriesWithoutProjectedParents(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["commandRefs"] = []any{}
	entry["ownerInvariantRefs"] = []any{}
	entry["requirementRefs"] = []any{}
	entry["witnessRefs"] = []any{}
	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	if exitCode == 0 {
		t.Fatal("unanchored inventory entry must fail coverage output")
	}
	record := view.(map[string]any)
	unmapped := record["unmappedTests"].([]any)
	if len(unmapped) != 1 || unmapped[0].(map[string]any)["testId"] != "test.coverage.semantic" {
		t.Fatalf("unmappedTests=%#v, want exact failed inventory entry", unmapped)
	}
	if _, err := AdmitOutput(record); err != nil {
		t.Fatalf("AdmitOutput(valid failed output) error=%v", err)
	}
	record["unmappedTests"] = []any{}
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "testInventoryDigest") {
		t.Fatalf("AdmitOutput() error=%v, want removed unmapped-entry rejection", err)
	}
}

func coverageRecordWithOwnerInvariant(t *testing.T) map[string]any {
	t.Helper()
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
	inventoryEntry(input)["ownerInvariantRefs"] = []any{"invariant.coverage.semantic"}
	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	return view.(map[string]any)
}

func TestBuildJSONTreatsNonWitnessProofStateAsMissingRoute(t *testing.T) {
	input := validCoverageInput(t)
	record := input.(map[string]any)
	proof := record["requirementProofBinding"].(map[string]any)
	proofRequirement := proof["requirements"].([]any)[0].(map[string]any)
	proofRequirement["claimLevel"] = "advisory"
	proofRequirement["proofState"] = "not_bound"
	proof["bindings"] = []any{}
	proof["witnessCommands"] = []any{}
	sourceRequirement(input)["claimLevel"] = "advisory"
	inventoryEntry(input)["witnessRefs"] = []any{}

	view, exitCode, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("advisory non-witness route should remain a warning: %#v", view)
	}
	requirement := view.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)
	if requirement["proofState"] != "not_bound" || requirement["coverageState"] != "missing_proof_binding_route" {
		t.Fatalf("non-witness proof state was not retained as a missing route: %#v", requirement)
	}
}

func TestAdmitOutputRejectsRemovedRetainedUnknownReferenceDiagnostics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "requirement",
			mutate: func(entry map[string]any) {
				entry["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-999"}
			},
			want: "unknown_requirement_ref:test.coverage.semantic:REQ-PROOFKIT-COVERAGE-999",
		},
		{
			name: "owner invariant",
			mutate: func(entry map[string]any) {
				entry["ownerInvariantRefs"] = []any{"invariant.coverage.unknown"}
			},
			want: "unknown_owner_invariant_ref:test.coverage.semantic:invariant.coverage.unknown",
		},
		{
			name: "command",
			mutate: func(entry map[string]any) {
				entry["commandRefs"] = []any{"proofkit.coverage.unknown"}
			},
			want: "unknown_command_or_witness_ref:test.coverage.semantic:proofkit.coverage.unknown",
		},
		{
			name: "witness",
			mutate: func(entry map[string]any) {
				entry["witnessRefs"] = []any{"proofkit.coverage.unknown-witness"}
			},
			want: "unknown_command_or_witness_ref:test.coverage.semantic:proofkit.coverage.unknown-witness",
		},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			input := validCoverageInput(t)
			item.mutate(inventoryEntry(input))
			view, _, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("BuildJSON() error=%v", err)
			}
			record := view.(map[string]any)
			setCoverageAggregateDiagnostics(
				record,
				withoutDiagnostic(stringArray(record["failures"]), item.want),
				stringArray(record["warnings"]),
			)
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "unknown-reference diagnostics are inconsistent") {
				t.Fatalf("AdmitOutput() error=%v, want retained unknown-reference rejection", err)
			}
		})
	}
}

func TestAdmitOutputDerivesCommandStateFromCommandLocalTests(t *testing.T) {
	input := validCoverageInput(t)
	entry := inventoryEntry(input)
	entry["evidenceClass"] = "routing_smoke_nonclaim"
	entry["requirementRefs"] = []any{}
	entry["witnessRefs"] = []any{}
	entry["falsifier"] = nil
	entry["oracle"] = nil
	entry["nonClaims"] = []any{"Route-only fixture does not prove command behavior."}

	view, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatalf("BuildJSON() error=%v", err)
	}
	record := view.(map[string]any)
	command := record["commandCoverage"].([]any)[0].(map[string]any)
	if len(command["tests"].([]any)) != 1 {
		t.Fatalf("command-local test projection missing: %#v", command)
	}
	command["coverageState"] = "command_declared_semantic_falsifier_route_present"
	command["failures"] = []any{}
	setCoverageAggregateDiagnostics(record, stringArray(record["failures"]), withoutDiagnostic(stringArray(record["warnings"]), "command_route_only_nonclaim:proofkit.coverage.command"))

	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "coverageState is not derived from projected tests") {
		t.Fatalf("AdmitOutput() error=%v, want command-local state rejection", err)
	}
}

func mutateProjectedTestCopies(t *testing.T, record map[string]any, testID string, mutate func(map[string]any)) {
	t.Helper()
	count := 0
	for _, rowsKey := range []string{"requirementCoverage", "ownerInvariantCoverage", "commandCoverage"} {
		for _, rawRow := range record[rowsKey].([]any) {
			for _, rawTest := range rawRow.(map[string]any)["tests"].([]any) {
				test := rawTest.(map[string]any)
				if test["testId"] == testID {
					mutate(test)
					count++
				}
			}
		}
	}
	if count == 0 {
		t.Fatalf("projected test %s not found", testID)
	}
}

func refreshCoverageBasisInventoryDigest(t *testing.T, record map[string]any) {
	t.Helper()
	registry, err := admitCoverageProjectedTestRegistry(record)
	if err != nil {
		t.Fatalf("admitCoverageProjectedTestRegistry() error=%v", err)
	}
	value, err := testInventoryProjectionDigest(projectedRegistryEntries(registry))
	if err != nil {
		t.Fatalf("testInventoryProjectionDigest() error=%v", err)
	}
	record["coverageBasis"].(map[string]any)["testInventoryDigest"] = value
}
