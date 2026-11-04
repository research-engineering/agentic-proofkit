package requirementcoverageview

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
)

func TestStructuredRenderingsDoNotInferAbsentBindingSelectors(t *testing.T) {
	baseline, exit, err := BuildJSON(validCoverageInput(t), Options{})
	if err != nil || exit != 0 {
		t.Fatalf("baseline JSON: %v exit=%d", err, exit)
	}
	input := validCoverageInput(t).(map[string]any)
	binding := input["requirementProofBinding"].(map[string]any)
	selectors := []any{map[string]any{
		"command":  "go test ./internal/command/requirementcoverageview -run TestCoverage",
		"selector": "TestCoverage",
	}}
	binding["bindings"].([]any)[0].(map[string]any)["witnessSelectors"] = selectors
	graph, exit, err := requirementbinding.BuildEvidenceGraph(binding)
	if err != nil || exit != 0 {
		t.Fatalf("binding owner: %v exit=%d", err, exit)
	}
	scenarios := graph.(map[string]any)["requirements"].([]any)[0].(map[string]any)["scenarios"].([]any)
	if !reflect.DeepEqual(scenarios[0].(map[string]any)["witnessSelectors"], selectors) {
		t.Fatal("binding fixture must retain its nonempty selectors")
	}
	view, exit, err := BuildJSON(input, Options{})
	if err != nil || exit != 0 {
		t.Fatalf("JSON: %v exit=%d", err, exit)
	}
	if !reflect.DeepEqual(view, baseline) {
		t.Fatal("unprojected binding selectors changed the exact coverage JSON")
	}
	if _, err := AdmitOutput(view); err != nil {
		t.Fatalf("JSON re-admission: %v", err)
	}
	md, exit, err := BuildMarkdown(input)
	if err != nil || exit != 0 {
		t.Fatalf("Markdown: %v exit=%d", err, exit)
	}
	document, exit, err := BuildHTML(input)
	if err != nil || exit != 0 {
		t.Fatalf("HTML: %v exit=%d", err, exit)
	}
	for _, output := range []struct {
		name, text, falseAbsence string
		retained                 []string
	}{
		{"Markdown", md, "- Witness selectors: none", []string{"test.coverage.semantic", "proofkit.coverage.witness"}},
		{"HTML", document, "<dt>Witness selectors</dt><dd>none</dd>", []string{"test.coverage.semantic", "proofkit.coverage.scenario", "TestCoverage"}},
	} {
		if strings.Contains(output.text, output.falseAbsence) {
			t.Errorf("%s infers absent selectors from an unprojected field", output.name)
		}
		for _, retained := range output.retained {
			if !strings.Contains(output.text, retained) {
				t.Errorf("%s lost retained test, scenario or inventory selector %s", output.name, retained)
			}
		}
	}
}
