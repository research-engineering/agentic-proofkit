package selectivegateevidence

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestSelectivePathRolesPreserveExactReferences(t *testing.T) {
	for _, sample := range []struct{ name, ref string }{
		{"ordinary", "artifacts/result.json"}, {"task", "inputs/task-requirements.json"},
		{"risk", "docs/risk-assessment.md"}, {"legacy", "artifacts/run-sk-abcdefghij.log"},
		{"leading_space", " artifacts/result.json"}, {"trailing_space", "artifacts/result.json "},
		{"long", strings.Repeat("segment/", 70) + "task-requirements.json"},
	} {
		ref := sample.ref
		t.Run("artifacts/"+sample.name, func(t *testing.T) {
			input := validEvidenceInput()
			selectiveReceipt(input)["artifactRefs"] = []any{ref}
			producerReceipt(input)["artifactRefs"] = []any{ref}
			value, err := admitEvidenceInput(input)
			if err != nil || !reflect.DeepEqual(value.Receipts[0].ArtifactRefs, []string{ref}) {
				t.Fatalf("receipt artifact identity lost: err=%v", err)
			}
			result, err := Build(input)
			if err != nil || result.ExitCode != 0 || result.Report.State != "passed" {
				t.Fatalf("bound artifact facts no longer agree: code=%d err=%v", result.ExitCode, err)
			}
		})
		t.Run("route/"+sample.name, func(t *testing.T) {
			input := validProjectionInput()
			raw := input["commandRoutes"].([]any)[0].(map[string]any)
			raw["evidenceRefs"] = []any{ref}
			route, _, err := admitRoute(raw)
			if err != nil || !reflect.DeepEqual(route["evidenceRefs"], []string{ref}) {
				t.Fatalf("route evidence identity lost: err=%v", err)
			}
			projection, err := ProjectObligationDecision(input)
			if err != nil {
				t.Fatal(err)
			}
			refs := projection["obligations"].([]any)[0].(map[string]any)["evidenceRefs"]
			found := false
			for _, value := range refs.([]any) {
				found = found || value == ref
			}
			if !found {
				t.Fatal("route reference changed during native projection")
			}
		})
	}
}

func TestSelectivePathAdmissionKeepsNormalizedListPolicy(t *testing.T) {
	want := []string{" a.json", "a.json", "a.json ", "b.json"}
	got, err := sortedPathsFromAny([]any{"b.json", "a.json ", "a.json", " a.json"}, "paths", false)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("path normalization changed identity: got=%q err=%v", got, err)
	}
	for _, raw := range []any{nil, false, "a.json", []any{nil}, []any{7}, []any{"a.json", "a.json"}} {
		if _, err := sortedPathsFromAny(raw, "paths", true); err == nil {
			t.Fatalf("path list accepted invalid %T input", raw)
		}
	}
	if _, err := sortedPathsFromAny([]any{}, "paths", false); err == nil {
		t.Fatal("required route evidence admitted empty list")
	}
	if got, err := sortedPathsFromAny([]any{}, "paths", true); err != nil || len(got) != 0 {
		t.Fatal("optional artifacts refused empty list")
	}
	for _, raw := range []any{nil, []any{}} {
		input := validEvidenceInput()
		selectiveReceipt(input)["artifactRefs"] = raw
		if _, err := admitEvidenceInput(input); (err != nil) != (raw == nil) {
			t.Fatalf("artifact null versus empty-list policy changed: %v", err)
		}
		route := validProjectionInput()["commandRoutes"].([]any)[0].(map[string]any)
		route["evidenceRefs"] = raw
		if _, _, err := admitRoute(route); err == nil {
			t.Fatal("required route references admitted null or empty input")
		}
	}
}

func TestSelectivePathAdmissionRetainsProtectedRefusalsAndProse(t *testing.T) {
	fixtures := admit.ReportVisibleRedactionFixtures()
	if len(fixtures) == 0 {
		t.Fatal("protected signature catalog is empty")
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if _, err := sortedPathsFromAny([]any{"inputs/prefix" + fixture.Input + "suffix.json"}, "paths", false); err == nil {
				t.Fatalf("protected signature class %s admitted", fixture.Name)
			}
		})
	}
	for _, ref := range []string{"", ".", "/absolute", "../outside", "a/../outside", "a//b", "https://example.test/a", "C:/outside", "a\\b", "a\x00b", "a\nb", "a\tb", "a\rb", "a\x7fb"} {
		if _, err := sortedPathsFromAny([]any{ref}, "paths", false); err == nil {
			t.Fatalf("unsafe path admitted: %q", ref)
		}
	}
	input := validEvidenceInput()
	input["nonClaims"] = []any{"inputs/task-requirements.json"}
	if _, err := Build(input); err == nil {
		t.Fatal("path repair weakened evidence prose")
	}
	route := validProjectionInput()["commandRoutes"].([]any)[0].(map[string]any)
	route["reason"] = "docs/risk-assessment.md"
	if _, _, err := admitRoute(route); err == nil {
		t.Fatal("path repair weakened route prose")
	}
}
