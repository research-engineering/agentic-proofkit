package workspaceplanning

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChangedPackagePlanAdmitsPackagesRootAndSchema(t *testing.T) {
	input := validChangedPackagePlanInput()

	plan, err := BuildChangedPackagePlan(input)
	if err != nil {
		t.Fatalf("BuildChangedPackagePlan() error=%v", err)
	}
	if plan["fullWorkspace"] != false {
		t.Fatalf("fullWorkspace=%v, want false", plan["fullWorkspace"])
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

func TestShardPartitionRejectsUnknownNestedFields(t *testing.T) {
	input := validShardPartitionInput()
	input["packages"].([]any)[0].(map[string]any)["ambientAuthority"] = true

	_, _, err := BuildShardPartition(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("BuildShardPartition() error=%v, want nested unsupported field rejection", err)
	}
}

func TestShardPartitionAdmitsCoveredRootsAndRejectsMissingDependency(t *testing.T) {
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
		"packages":                 []any{map[string]any{"dirName": "alpha", "name": "alpha", "workspaceDependencies": []any{}}},
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
