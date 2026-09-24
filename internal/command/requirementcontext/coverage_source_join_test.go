package requirementcontext_test

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
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
	originalNonClaims := coverage["nonClaims"].([]any)
	withoutSourceBoundary := []any{}
	for _, raw := range originalNonClaims {
		if raw != "Coverage browser source fixture does not own native tests." {
			withoutSourceBoundary = append(withoutSourceBoundary, raw)
		}
	}
	coverage["nonClaims"] = withoutSourceBoundary
	if _, err := requirementcontext.AdmitSnapshot(context); err == nil || !strings.Contains(err.Error(), "source non-claim") {
		t.Fatalf("coverage without source boundary admitted: %v", err)
	}
	coverage["nonClaims"] = originalNonClaims
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

func TestContextRejectsCoverageOmittingNewSelectedRequirement(t *testing.T) {
	workspace, err := browserfixture.CoverageWorkspace("structured", false)
	if err != nil {
		t.Fatal(err)
	}
	context := workspace["context"].(map[string]any)
	projections := context["projections"].(map[string]any)
	coverage := projections["coverage"].(map[string]any)
	for _, raw := range projections["requirementSources"].([]any) {
		source := raw.(map[string]any)
		if source["sourceId"] != coverage["sourceId"] {
			continue
		}
		group := source["groups"].([]any)[0].(map[string]any)
		first := group["members"].([]any)[0].(map[string]any)
		group["members"] = append(group["members"].([]any), map[string]any{
			"requirementId": "REQ-BROWSER-COVERAGE-002", "statementCompletion": "Another selected requirement needs a coverage row.", "fields": first["fields"],
		})
		admitted, err := requirementsourceadmission.Evaluate(source)
		if err != nil || admitted.ExitCode != 0 {
			t.Fatalf("expanded source admission: %v", err)
		}
		coverage["sourceDigest"], err = requirementsourceadmission.SourceDigest(admitted.Source)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := requirementcontext.AdmitSnapshot(context); err == nil || !strings.Contains(err.Error(), "omit an admitted in-scope requirement") {
		t.Fatalf("snapshot accepted incomplete passed coverage: %v", err)
	}
}
