package requirementsourceview

import (
	"reflect"
	"strings"
	"testing"
)

func TestSourceViewRetainsPremisesAndDistinctNonclaimRoles(t *testing.T) {
	input := validRequirementSource()
	input["groups"].([]any)[0].(map[string]any)["sharedPremises"] = []any{"The caller owns <input>."}
	input["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-VIEW", "statement": "No external service result is proven."}}
	fields := viewTestFields(input)
	fields["nonClaimRefs"], fields["externalNonClaimRefs"] = []any{"NCL-VIEW"}, []any{"NC-EXTERNAL"}
	output, code, err := BuildJSON(input)
	if err != nil || code != 0 {
		t.Fatalf("view: %v", err)
	}
	view := output.(map[string]any)
	if !reflect.DeepEqual(view["nonClaimDefinitions"], input["nonClaimDefinitions"]) {
		t.Fatal("source view lost its local definition dictionary")
	}
	requirement := view["requirements"].([]any)[0].(map[string]any)
	if view["schemaVersion"] != 2 || !reflect.DeepEqual(requirement["sharedPremises"], []any{"The caller owns <input>."}) ||
		!reflect.DeepEqual(requirement["nonClaimRefs"], []any{"NCL-VIEW"}) || !reflect.DeepEqual(requirement["externalNonClaimRefs"], []any{"NC-EXTERNAL"}) {
		t.Fatal("effective condition or reference role was lost")
	}
	for _, renderer := range []struct {
		name, premise string
		render        func(any) (string, int, error)
	}{
		{"markdown", "- The caller owns &lt;input&gt;\\.", BuildMarkdown},
		{"html", "<li>The caller owns &lt;input&gt;.</li>", BuildHTML},
	} {
		text, exit, err := renderer.render(input)
		if err != nil || exit != 0 {
			t.Fatalf("render: %v", err)
		}
		for _, expected := range []string{renderer.premise, "NCL-VIEW", "NC-EXTERNAL", "No external service result is proven", "presentation_only"} {
			if !strings.Contains(text, expected) {
				t.Fatalf("%s render omitted %q", renderer.name, expected)
			}
		}
		if strings.Contains(text, "<input>") {
			t.Fatal("premise reached an unescaped render sink")
		}
	}
}
