package branchauthority

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"os/exec"
	"strings"
	"testing"
)

func TestBuildAdmitsAlignedRequiredBranchAndRejectsRequiredDrift(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.006246519585105251684624732206882456828785038106904394850474532555486460156892")
	record, exitCode, err := Build(validBranchAuthorityInput("main"))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	record, exitCode, err = Build(validBranchAuthorityInput("feature/test"))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "proofkit.test.default") || !strings.Contains(string(encoded), "drifted") {
		t.Fatalf("Build() accepted required branch drift: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func TestBranchAdmissionMatchesGitShorthandGrammar(t *testing.T) {
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{"main", true},
		{"foo./bar", true},
		{"foo@bar", true},
		{"topic/-bar", true},
		{"@", true},
		{"main.", false},
		{".hidden", false},
		{"topic/.hidden", false},
		{"topic.lock/sub", false},
		{"main@{1}", false},
		{"-danger", false},
		{"topic\x01bad", false},
	} {
		_, err := branchName(test.name, "branch")
		if (err == nil) != test.valid {
			t.Fatalf("branchName(%q) error=%v, valid=%t", test.name, err, test.valid)
		}
		if err := exec.Command("git", "check-ref-format", "--branch", test.name).Run(); (err == nil) != test.valid {
			t.Fatalf("git check-ref-format --branch %q error=%v, valid=%t", test.name, err, test.valid)
		}
		_, _, err = Build(validBranchAuthorityInput(test.name))
		if (err == nil) != test.valid {
			t.Fatalf("Build(observedBranch=%q) error=%v, valid=%t", test.name, err, test.valid)
		}
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
