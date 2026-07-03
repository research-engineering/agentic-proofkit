package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretJSONOwnerGovernance(t *testing.T) {
	deploymentSource := readRepoSource(t, "internal/command/deploymentevidenceadmission/deployment_evidence_admission.go")
	requireSourceToken(t, deploymentSource, "secretjson.Scan", "deployment evidence admission must route JSON traversal through the private secretjson owner")
	rejectSourceTokens(t, deploymentSource, "deployment evidence admission must not reintroduce a command-local secret JSON traversal owner", []string{
		"secretLikeRegexps",
		"urlUserInfoRegexp",
		"rootPathRegexp",
		"type secretFinding struct",
		"func collectFindings(",
		"func collectStringFindings(",
		"func isSecretLike(",
		"authorization\\s",
		"github_pat_",
		"gh[pousr]_",
	})

	readinessSource := readRepoSource(t, "internal/command/readinesscloseout/readinesscloseout.go")
	requireSourceToken(t, readinessSource, "admit.ContainsSecretLikeValue", "readiness closeout must route text secret taxonomy through central admission")
	rejectSourceTokens(t, readinessSource, "readiness closeout must not reintroduce command-local secret taxonomy", []string{
		"secretValuePattern",
		"urlUserInfoPattern",
		"authorization\\s",
		"github_pat_",
		"gh[pousr]_",
	})
}

func readRepoSource(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join("..", path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func requireSourceToken(t *testing.T, source string, token string, reason string) {
	t.Helper()

	if !strings.Contains(source, token) {
		t.Fatalf("%s: missing %q", reason, token)
	}
}

func rejectSourceTokens(t *testing.T, source string, reason string, tokens []string) {
	t.Helper()

	for _, token := range tokens {
		if strings.Contains(source, token) {
			t.Fatalf("%s: forbidden token %q found", reason, token)
		}
	}
}
