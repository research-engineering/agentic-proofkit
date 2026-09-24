package requirementcontext_test

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/browserfixture"
)

func TestContextRejectsCoverageFromAnotherSourceRevision(t *testing.T) {
	workspace, err := browserfixture.CoverageWorkspace("structured", false)
	if err != nil {
		t.Fatal(err)
	}
	context := workspace["context"].(map[string]any)
	if _, err := requirementcontext.AdmitSnapshot(context); err != nil {
		t.Fatalf("baseline coverage context: %v", err)
	}
	projections := context["projections"].(map[string]any)
	coverage := projections["coverage"].(map[string]any)
	coverage["sourceId"] = "another.admitted.source"
	if _, err := requirementcontext.AdmitSnapshot(context); err == nil || !strings.Contains(err.Error(), "coverage source is outside") {
		t.Fatalf("unrelated coverage source admitted: %v", err)
	}
	coverage["sourceId"] = "proofkit.browser.coverage.source"
	for _, raw := range projections["requirementSources"].([]any) {
		source := raw.(map[string]any)
		if source["sourceId"] != coverage["sourceId"] {
			continue
		}
		member := source["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)
		member["statementCompletion"] = "A newer invariant requires a different coverage result."
	}
	if _, err := requirementcontext.AdmitSnapshot(context); err == nil || !strings.Contains(err.Error(), "coverage source digest disagrees") {
		t.Fatalf("stale coverage source admitted: %v", err)
	}
}
