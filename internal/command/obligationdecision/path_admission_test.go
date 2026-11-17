package obligationdecision

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestObligationPathRolePreservesExactReferences(t *testing.T) {
	for _, sample := range []struct{ name, ref string }{
		{"ordinary", "artifacts/result.json"}, {"task", "inputs/task-requirements.json"},
		{"risk", "docs/risk-assessment.md"}, {"legacy", "artifacts/run-sk-abcdefghij.log"},
		{"leading_space", " artifacts/result.json"}, {"trailing_space", "artifacts/result.json "},
		{"long", strings.Repeat("segment/", 70) + "task-requirements.json"},
	} {
		ref := sample.ref
		t.Run(sample.name, func(t *testing.T) {
			input := validObligationDecisionInput("satisfied", "not_applicable")
			input["obligations"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{ref}
			result, err := Build(input)
			if err != nil {
				t.Fatalf("canonical obligation evidence refused: %v", err)
			}
			if result.ExitCode != 0 || result.Report.State != "passed" || !reflect.DeepEqual(result.Decisions[0].EvidenceRefs, []string{ref}) {
				t.Fatalf("evidence identity or decision policy changed: %#v", result.Decisions[0])
			}
		})
	}
}

func TestObligationPathAdmissionKeepsNormalizedListPolicy(t *testing.T) {
	want := []string{" a.json", "a.json", "a.json ", "b.json"}
	got, err := sortedPaths([]string{"b.json", "a.json ", "a.json", " a.json"}, "paths")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("path normalization changed identity: got=%q err=%v", got, err)
	}
	for _, refs := range [][]string{nil, {}, {"a.json", "a.json"}} {
		if _, err := sortedPaths(refs, "paths"); err == nil {
			t.Fatal("nonempty unique path policy weakened")
		}
	}
	for _, raw := range []any{nil, false, "a.json", []any{nil}, []any{7}, []any{}} {
		input := validObligationDecisionInput("satisfied", "not_applicable")
		input["obligations"].([]any)[0].(map[string]any)["evidenceRefs"] = raw
		if _, err := Build(input); err == nil {
			t.Fatalf("evidenceRefs accepted wrong type or empty %T input", raw)
		}
	}
}

func TestObligationPathAdmissionRetainsProtectedRefusalsAndProse(t *testing.T) {
	fixtures := admit.ReportVisibleRedactionFixtures()
	if len(fixtures) == 0 {
		t.Fatal("protected signature catalog is empty")
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if _, err := sortedPaths([]string{"inputs/prefix" + fixture.Input + "suffix.json"}, "paths"); err == nil {
				t.Fatalf("protected signature class %s admitted", fixture.Name)
			}
		})
	}
	for _, ref := range []string{"", ".", "/absolute", "../outside", "a/../outside", "a//b", "https://example.test/a", "C:/outside", "a\\b", "a\x00b", "a\nb", "a\tb", "a\rb", "a\x7fb"} {
		if _, err := sortedPaths([]string{ref}, "paths"); err == nil {
			t.Fatalf("unsafe path admitted: %q", ref)
		}
	}
	for _, field := range []string{"owner", "reason", "nonClaims"} {
		input := validObligationDecisionInput("satisfied", "not_applicable")
		obligation := input["obligations"].([]any)[0].(map[string]any)
		if field == "nonClaims" {
			input[field] = []any{"inputs/task-requirements.json"}
		} else {
			obligation[field] = "docs/risk-assessment.md"
		}
		if _, err := Build(input); err == nil {
			t.Fatalf("path repair weakened prose field %s", field)
		}
	}
}
