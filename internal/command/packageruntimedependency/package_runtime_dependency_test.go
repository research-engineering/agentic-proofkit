package packageruntimedependency

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildAdmitsExternalRuntimeDependencyAndRejectsWorkspaceResolution(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.027617011738725950397530096345580960352335933116627715389463795934691621119686")
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

func TestBuildRejectsLockfileIntegrityDrift(t *testing.T) {
	input := validPackageRuntimeDependencyInput()
	input["packageResolution"].(map[string]any)["lockfileIntegrity"] = "sha512-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	record, exitCode := Build(input)
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	if !strings.Contains(record.RuleResults[1].Message, "lockfile integrity does not match") {
		t.Fatalf("lockfile rule message=%q, want integrity drift", record.RuleResults[1].Message)
	}
}

func TestBuildRejectsSecretLikeReportVisibleText(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := validPackageRuntimeDependencyInput()
	input["nonClaims"] = []any{secret}

	record, exitCode := Build(input)
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("report leaked secret-shaped caller text: %s", string(encoded))
	}
	if !strings.Contains(string(encoded), "secret-like values") {
		t.Fatalf("report=%s, want secret-like rejection", string(encoded))
	}
}

func validPackageRuntimeDependencyInput() map[string]any {
	return map[string]any{
		"schemaVersion":             json.Number("1"),
		"reportId":                  "proofkit.test.runtime_dependency",
		"expectedDependencySpec":    "agentic-proofkit@0.1.95",
		"expectedLockfileIntegrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"expectedPackageName":       "agentic-proofkit",
		"expectedPackageVersion":    "0.1.95",
		"nonClaims":                 []any{"Package runtime dependency test input does not read package manifests."},
		"admissibleLocations":       map[string]any{"expectedPackageRoot": "/repo/node_modules/agentic-proofkit", "localWorkspaceRoot": "/repo/packages", "nodeModulesRoot": "/repo/node_modules"},
		"packageResolution":         map[string]any{"dependencySpec": "agentic-proofkit@0.1.95", "lockfileEntryPresent": true, "lockfileIntegrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "packageName": "agentic-proofkit", "packageVersion": "0.1.95", "packageRoot": "/repo/node_modules/agentic-proofkit", "realPackageRoot": "/repo/node_modules/agentic-proofkit", "resolvedEntryPoint": "/repo/node_modules/agentic-proofkit/bin/agentic-proofkit"},
	}
}
