package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpecOverviewNamesCurrentContextDiffAndGraphIdentities(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/specs/proofkit-spec-proof-core/overview.md"))
	if err != nil {
		t.Fatal(err)
	}
	document := string(content)
	for _, item := range []struct {
		id       string
		required []string
	}{
		{"REQ-PROOFKIT-SPEC-019", []string{"schema-v4 context snapshots", "retired context v1-v3", "are rejected"}},
		{"REQ-PROOFKIT-SPEC-022", []string{"schema-v3 records", "rejects retired v1/v2 adapters"}},
		{"REQ-PROOFKIT-SPEC-023", []string{"graph input schema v3", "admitted context v4"}},
	} {
		start := strings.Index(document, "- `"+item.id+"`:")
		if start < 0 {
			t.Fatalf("overview is missing %s", item.id)
		}
		section := document[start:]
		if end := strings.Index(section, "\n- `REQ-"); end >= 0 {
			section = section[:end]
		}
		for _, phrase := range item.required {
			if !strings.Contains(section, phrase) {
				t.Fatalf("%s overview lost current contract phrase %q", item.id, phrase)
			}
		}
	}
}
