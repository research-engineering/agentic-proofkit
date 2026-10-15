package app

import (
	"fmt"
	"strings"
	"testing"
)

func adoptionGuideProfileEntry(t *testing.T) map[string]any {
	t.Helper()
	status, help, stderr := executeAgentWorkflowCLI(t, []string{"adopt", "materialize", "plan", "--help"}, panicReader{}, PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("guide status=%d stderr=%q", status, stderr)
	}
	_, tail, found := strings.Cut(help, "  Profile entry:\n")
	entry, _, closed := strings.Cut(tail, "\n  Scenario records")
	if !found || !closed {
		t.Fatal("guide must publish one delimited profile entry")
	}
	return decodeCLIJSON(t, entry).(map[string]any)
}

// The published profile entry must turn the template's single member into a
// two-member group that source admission accepts, and its stated ownership and
// cardinality rules must hold.
func TestAdoptionInputGuideProfileEntryAdmitsSharedMetadata(t *testing.T) {
	sourceWithProfile := func(members int, keepOwner bool) []byte {
		packet := adoptionHelpPacket(t, t.TempDir(), "fresh")
		source := packet["requirementSources"].([]any)[0].(map[string]any)
		group := source["groups"].([]any)[0].(map[string]any)
		first := adoptionHelpMember(packet)
		nonClaims := adoptionHelpRequirementFields(packet)["nonClaims"]
		values := []any{}
		for index := 0; index < members; index++ {
			fields := map[string]any{"nonClaims": nonClaims}
			if keepOwner {
				fields["ownerId"] = "example.backend"
			}
			values = append(values, map[string]any{
				"requirementId":       []string{"REQ-EXAMPLE-001", "REQ-EXAMPLE-002"}[index],
				"statementCompletion": []string{first["statementCompletion"].(string), "Oversized requests are rejected."}[index],
				"fields":              fields,
			})
		}
		group["members"] = values
		entry := adoptionGuideProfileEntry(t)
		group["profileId"] = entry["profileId"]
		source["profiles"] = []any{entry}
		return adoptionHelpJSON(t, source)
	}
	report := runAdoptionHelpCLI(t, sourceWithProfile(2, false), "requirement-source-admission", "--input", "-")
	if report["state"] != "passed" || fmt.Sprint(report["summary"].(map[string]any)["blockingRequirementCount"]) != "2" {
		t.Fatalf("published profile entry did not admit two blocking members: %v", report)
	}
	for _, rejected := range []struct {
		name, want string
		input      []byte
	}{
		{"field owned twice", "metadata_partition_violation: /groups/0/members/0/fields/ownerId", sourceWithProfile(2, true)},
		{"single member", "vacuous_profile: /profiles/0", sourceWithProfile(1, false)},
	} {
		status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"requirement-source-admission", "--input", "-"}, strings.NewReader(string(rejected.input)), PresentationCapabilities{})
		if status != 1 || stdout != "" || !strings.HasPrefix(stderr, rejected.want) {
			t.Fatalf("%s: status=%d stdout=%q stderr=%q, want %q", rejected.name, status, stdout, stderr, rejected.want)
		}
	}
}
