package packageruntimedependency

import (
	"encoding/json"
	"testing"
)

func TestBuildAdmitsExternalRuntimeDependencyAndRejectsWorkspaceResolution(t *testing.T) {
	input := validPackageRuntimeDependencyInput()
	record, exitCode := Build(input)
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input = validPackageRuntimeDependencyInput()
	input["packageResolution"].(map[string]any)["packageRoot"] = "/repo/packages/proofkit"
	input["packageResolution"].(map[string]any)["realPackageRoot"] = "/repo/packages/proofkit"
	input["packageResolution"].(map[string]any)["resolvedEntryPoint"] = "/repo/packages/proofkit/dist/index.js"
	record, exitCode = Build(input)
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build(workspace) exit=%d state=%s, want failed", exitCode, record.State)
	}
}

func validPackageRuntimeDependencyInput() map[string]any {
	return map[string]any{
		"schemaVersion":          json.Number("1"),
		"reportId":               "proofkit.test.runtime_dependency",
		"expectedDependencySpec": "agentic-proofkit@0.1.95",
		"expectedPackageName":    "agentic-proofkit",
		"expectedPackageVersion": "0.1.95",
		"nonClaims":              []any{"Package runtime dependency test input does not read package manifests."},
		"admissibleLocations":    map[string]any{"expectedPackageRoot": "/repo/node_modules/agentic-proofkit", "localWorkspaceRoot": "/repo/packages", "nodeModulesRoot": "/repo/node_modules"},
		"packageResolution":      map[string]any{"dependencySpec": "agentic-proofkit@0.1.95", "lockfileEntryPresent": true, "packageName": "agentic-proofkit", "packageVersion": "0.1.95", "packageRoot": "/repo/node_modules/agentic-proofkit", "realPackageRoot": "/repo/node_modules/agentic-proofkit", "resolvedEntryPoint": "/repo/node_modules/agentic-proofkit/bin/agentic-proofkit"},
	}
}
