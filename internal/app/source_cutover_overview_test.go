package app

import (
	"encoding/json"
	"fmt"
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
		{"REQ-PROOFKIT-SPEC-022", []string{"reads schema-v3 inputs and writes schema-v4 outputs", "rejects retired v1/v2 inputs and v1-v3 outputs"}},
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

// REQ-PROOFKIT-SPEC-022 and its overview bullet state the semantic diff
// versions; both must name the versions the published contract declares.
func TestSemanticDiffRequirementStatesPublishedContractVersions(t *testing.T) {
	commands, _, err := indexPublicABIRecords(readCLIContractRaw(t)["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	version := func(direction string) json.Number {
		record, _ := commands["requirement-semantic-diff"][direction].(map[string]any)
		value, ok := record["schemaVersion"].(json.Number)
		if !ok {
			t.Fatalf("requirement-semantic-diff %s has no published schemaVersion", direction)
		}
		return value
	}
	input, output := version("inputContract"), version("outputContract")
	retiredOutput, err := output.Int64()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/specs/proofkit-spec-proof-core/requirements.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Groups []struct {
			Members []struct {
				RequirementID       string `json:"requirementId"`
				StatementCompletion string `json:"statementCompletion"`
			} `json:"members"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(content, &source); err != nil {
		t.Fatal(err)
	}
	statement, found := "", 0
	for _, group := range source.Groups {
		for _, member := range group.Members {
			if member.RequirementID == "REQ-PROOFKIT-SPEC-022" {
				statement, found = member.StatementCompletion, found+1
			}
		}
	}
	if found != 1 {
		t.Fatalf("found %d REQ-PROOFKIT-SPEC-022 requirements, want exactly one", found)
	}
	for _, phrase := range []string{
		fmt.Sprintf("schema-v%s input compares", input),
		fmt.Sprintf("producing a schema-v%s canonically ordered output", output),
		fmt.Sprintf("retired v1 to v%d diff outputs are rejected", retiredOutput-1),
	} {
		if !strings.Contains(statement, phrase) {
			t.Fatalf("REQ-PROOFKIT-SPEC-022 must state the published contract versions: missing %q", phrase)
		}
	}
	overview, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/specs/proofkit-spec-proof-core/overview.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{
		fmt.Sprintf("reads schema-v%s inputs and writes schema-v%s outputs", input, output),
		fmt.Sprintf("v1-v%d outputs", retiredOutput-1),
	} {
		if !strings.Contains(strings.Join(strings.Fields(string(overview)), " "), phrase) {
			t.Fatalf("REQ-PROOFKIT-SPEC-022 overview must state the published contract versions: missing %q", phrase)
		}
	}
}
