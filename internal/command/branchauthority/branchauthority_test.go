package branchauthority

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAdmitsAlignedRequiredBranchAndRejectsRequiredDrift(t *testing.T) {
	record, exitCode := Build(validBranchAuthorityInput("main"))
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	record, exitCode = Build(validBranchAuthorityInput("feature/test"))
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "proofkit.test.default") || !strings.Contains(string(encoded), "drifted") {
		t.Fatalf("Build() accepted required branch drift: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func validBranchAuthorityInput(observedBranch string) map[string]any {
	return map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.test.branch-authority",
		"preexistingFailures": []any{},
		"nonClaims":           []any{"Branch authority test input does not read repository settings."},
		"branchRefs": []any{
			map[string]any{
				"evidenceRef":    "docs/release-process.md",
				"expectedBranch": "main",
				"nonClaims":      []any{"This branch ref does not prove branch protection."},
				"observedBranch": observedBranch,
				"refId":          "proofkit.test.default",
				"refKind":        "repository_default",
				"required":       true,
			},
		},
	}
}
