package requirementauthoringplan

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestReferenceRolesPreserveExistingAdmissionVocabulary(t *testing.T) {
	want := []string{"clarification_answer", "code_summary", "design_doc", "implementation_plan", "pr_facts", "test_summary"}
	got := make([]string, 0, len(referenceRoles))
	help := InputGuide(cliexec.PathRenderer())
	for _, role := range referenceRoles {
		got = append(got, role.kind)
		if role.description == "" || strings.Count(help, "  "+role.kind+": ") != 1 {
			t.Fatalf("reference role missing or duplicated in help: %s", role.kind)
		}
		if _, ok := refKindSet[role.kind]; !ok {
			t.Fatalf("help describes an unadmitted role: %s", role.kind)
		}
	}
	if !reflect.DeepEqual(got, want) || len(refKindSet) != len(want) {
		t.Fatalf("existing reference vocabulary changed: %v", got)
	}
	if strings.Contains(help, "{{roles}}") || strings.Contains(help, "{{cli}}") {
		t.Fatal("unresolved authoring help placeholder")
	}
}

func TestReferenceRolesKeepMeaningBoundToKind(t *testing.T) {
	// Expectations are independent of the production role table.
	want := map[string][]string{
		"clarification_answer": {"product intent", "owner answer", "unresolved assumptions"},
		"code_summary":         {"code observations", "baseline and audit"},
		"design_doc":           {"design documents", "external specifications", "not imported authority"},
		"implementation_plan":  {"implementation-plan proposals", "not evidence"},
		"pr_facts":             {"pull-request observations", "not merge approval"},
		"test_summary":         {"test-source observations", "test-coverage observations", "summary and nonClaims"},
	}
	help := InputGuide(cliexec.PathRenderer())
	for kind, fragments := range want {
		_, suffix, found := strings.Cut(help, "  "+kind+": ")
		line, _, _ := strings.Cut(suffix, "\n")
		for _, fragment := range fragments {
			if !found || !strings.Contains(line, fragment) {
				t.Fatalf("reference role %s lost its required meaning %q", kind, fragment)
			}
		}
	}
}
