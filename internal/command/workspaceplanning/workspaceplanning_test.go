package workspaceplanning

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestChangedPackagePlanAdmitsPackagesRootAndSchema(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.012483302559028244967785281995194599578244586042338061566707694834914436961975")
	input := validChangedPackagePlanInput()

	plan, err := BuildChangedPackagePlan(input)
	if err != nil {
		t.Fatalf("BuildChangedPackagePlan() error=%v", err)
	}
	if plan["fullWorkspace"] != false {
		t.Fatalf("fullWorkspace=%v, want false", plan["fullWorkspace"])
	}
	rootNames := plan["rootPackageNames"].([]any)
	if len(rootNames) != 2 || rootNames[0] != "alpha" || rootNames[1] != "beta" {
		t.Fatalf("rootPackageNames=%#v, want changed root plus reverse dependent", rootNames)
	}
	directRootNames := plan["directRootPackageNames"].([]any)
	if len(directRootNames) != 1 || directRootNames[0] != "alpha" {
		t.Fatalf("directRootPackageNames=%#v, want only alpha", directRootNames)
	}
}

func TestChangedPackagePlanEscalatesToFullWorkspaceForMatchedRule(t *testing.T) {
	input := validChangedPackagePlanInput()
	input["escalationRules"] = []any{map[string]any{"pattern": "modules/**", "reason": "workspace.global"}}

	plan, err := BuildChangedPackagePlan(input)
	if err != nil {
		t.Fatalf("BuildChangedPackagePlan() error=%v", err)
	}
	if plan["fullWorkspace"] != true {
		t.Fatalf("fullWorkspace=%v, want true", plan["fullWorkspace"])
	}
	reasons := plan["escalationReasons"].([]any)
	if len(reasons) != 1 || reasons[0] != "workspace.global" {
		t.Fatalf("escalationReasons=%#v, want workspace.global", reasons)
	}
}

func TestChangedPackagePlanRejectsSchemaDrift(t *testing.T) {
	input := validChangedPackagePlanInput()
	input["schemaVersion"] = json.Number("2")

	_, err := BuildChangedPackagePlan(input)
	if err == nil || !strings.Contains(err.Error(), "schemaVersion must be 1") {
		t.Fatalf("BuildChangedPackagePlan() error=%v, want schema rejection", err)
	}
}

func TestChangedPackagePlanRejectsSecretLikePackageName(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := validChangedPackagePlanInput()
	input["packages"].([]any)[0].(map[string]any)["name"] = secret

	_, err := BuildChangedPackagePlan(input)
	if err == nil {
		t.Fatal("BuildChangedPackagePlan() accepted secret-shaped package name")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret-shaped caller text: %v", err)
	}
	if !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("error=%v, want secret-like rejection", err)
	}
}

func TestShardPartitionRejectsUnknownNestedFields(t *testing.T) {
	input := validShardPartitionInput()
	input["packages"].([]any)[0].(map[string]any)["ambientAuthority"] = true

	_, _, err := BuildShardPartition(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("BuildShardPartition() error=%v, want nested unsupported field rejection", err)
	}
}

func TestShardPartitionAdmitsCoveredRootsAndRejectsMissingDependency(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.067233922180114604656007812711586055552725961620481057364664589070016617853243")
	partition, exitCode, err := BuildShardPartition(validShardPartitionInput())
	if err != nil {
		t.Fatalf("BuildShardPartition() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildShardPartition() exit=%d partition=%#v, want 0", exitCode, partition)
	}
	if got := partition["rootPackageCount"]; got != 1 {
		t.Fatalf("rootPackageCount=%v, want 1", got)
	}

	input := validShardPartitionInput()
	input["roots"].([]any)[0].(map[string]any)["workspaceDependencies"] = []any{"beta"}
	partition, exitCode, err = BuildShardPartition(input)
	if err != nil {
		t.Fatalf("BuildShardPartition() missing dependency error=%v", err)
	}
	if exitCode == 0 {
		t.Fatalf("BuildShardPartition() accepted missing dependency: partition=%#v", partition)
	}
	failures := partition["failures"].([]any)
	if len(failures) == 0 || !strings.Contains(failures[0].(string), "depends on missing workspace package beta") {
		t.Fatalf("failures=%#v, want missing dependency", failures)
	}
}

func validChangedPackagePlanInput() map[string]any {
	return map[string]any{
		"schemaVersion":            json.Number("1"),
		"changedPaths":             []any{"modules/alpha/file.go"},
		"includeReverseDependents": true,
		"packagesRoot":             "modules",
		"escalationRules":          []any{},
		"packages": []any{
			map[string]any{"dirName": "alpha", "name": "alpha", "workspaceDependencies": []any{}},
			map[string]any{"dirName": "beta", "name": "beta", "workspaceDependencies": []any{"alpha"}},
		},
	}
}

func validShardPartitionInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"shardTotal":    json.Number("1"),
		"roots":         []any{map[string]any{"name": "alpha", "workspaceDependencies": []any{}}},
		"packages":      []any{map[string]any{"name": "alpha", "workspaceDependencies": []any{}}},
	}
}
