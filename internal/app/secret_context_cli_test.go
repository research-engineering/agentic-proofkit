package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestSecretScanCLIRecognizesQuotedAndNormalizedAssignments(t *testing.T) {
	for _, value := range []string{
		`"password": "synthetic-fixture-value"`,
		`\"token\": \"synthetic-fixture-value\"`,
		"api_\u200bkey=synthetic-fixture-value",
	} {
		var stdout, stderr bytes.Buffer
		exit := Run(t.Context(), []string{"secret-scan", "--input", "-"}, strings.NewReader(cliSecretScanInput(value)), &stdout, &stderr)
		if exit != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"state": "failed"`) {
			t.Fatalf("secret scan outcome: exit=%d stderrBytes=%d", exit, stderr.Len())
		}
		if strings.Contains(stdout.String()+stderr.String(), "synthetic-fixture-value") {
			t.Fatal("secret scan disclosed the matched synthetic assignment")
		}
	}
}
