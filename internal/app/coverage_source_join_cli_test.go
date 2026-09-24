package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestCoverageCLIRejectsBindingSourceMetadataMismatch(t *testing.T) {
	for _, item := range []struct{ field, value string }{
		{"ownerId", "another.owner"},
		{"claimLevel", "advisory"},
		{"specPath", "docs/specs/other/requirements.v2.json"},
	} {
		t.Run(item.field, func(t *testing.T) {
			input := strictJSONObjectFromText(t, cliCoverageInput(cliCoverageInventory()), "coverage CLI source join")
			requirement := input["requirementProofBinding"].(map[string]any)["requirements"].([]any)[0].(map[string]any)
			requirement[item.field] = item.value
			var stdout, stderr bytes.Buffer
			status := Run(t.Context(), []string{"requirement-coverage-view", "--input", "-"}, strings.NewReader(cliJSON(input)), &stdout, &stderr)
			if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "source-owned requirement fields") {
				t.Fatalf("mismatched %s admitted: status=%d stdout=%q stderr=%q", item.field, status, stdout.String(), stderr.String())
			}
		})
	}
}
