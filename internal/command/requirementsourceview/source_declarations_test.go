package requirementsourceview

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
)

func declaredSourceFixture() map[string]any {
	input := validRequirementSource()
	group := input["groups"].([]any)[0].(map[string]any)
	group["statementStem"] = "The renderer must"
	group["sharedPremises"] = []any{"The caller selected this source."}
	first := viewTestMember(input)
	first["statementCompletion"] = "preserve groups."
	second := viewTestMember(validRequirementSource())
	second["requirementId"], second["statementCompletion"] = "REQ-PROOFKIT-VIEW-002", "preserve declared scenarios."
	group["members"] = []any{first, second}
	input["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-VIEW", "statement": "Source declarations are not executed evidence."}}
	input["sourceNonClaimRefs"] = []any{"NCL-VIEW"}
	input["vocabulary"] = []any{map[string]any{"termId": "TERM-VIEW", "kind": "subject", "label": "Renderer <input>", "definition": "The caller's <script> vocabulary stays text."}}
	input["scenarios"] = []any{map[string]any{
		"scenarioId": "SCN-VIEW", "requirementIds": []any{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"},
		"parameters": []any{"surface"}, "preconditions": []any{"The ${surface} view is open."},
		"actionSequence":       []any{"Submit Z first.", "Inspect A second."},
		"expectedObservations": []any{"The value remains <input>."}, "forbiddenObservations": []any{"The source becomes execution proof."},
		"examples": []any{
			map[string]any{"exampleId": "EX-VIEW-1", "values": map[string]any{"surface": "primary <input>"}},
			map[string]any{"exampleId": "EX-VIEW-2", "values": map[string]any{"surface": "secondary"}},
		},
		"vocabularyRefs": []any{"TERM-VIEW"}, "nonClaimRefs": []any{"NCL-VIEW"},
	}}
	input["derivations"] = []any{map[string]any{
		"derivationId": "DRV-VIEW", "sourceKind": "owner_decision",
		"sourceRef": map[string]any{"objectFormat": "sha1", "commitOid": strings.Repeat("a", 40), "path": "docs/decisions/view.md", "sha256": strings.Repeat("b", 64)},
		"selector":  map[string]any{"start": "7", "end": "19"}, "requirementIds": []any{"REQ-PROOFKIT-VIEW-002"}, "nonClaimRefs": []any{"NCL-VIEW"},
	}}
	return input
}

func TestCompleteSourceViewPreservesDeclarationsAndGroupMembership(t *testing.T) {
	input := declaredSourceFixture()
	output, exit, err := BuildJSON(input)
	if err != nil || exit != 0 {
		t.Fatalf("source declarations: %v, %d", err, exit)
	}
	view := output.(map[string]any)
	for _, key := range []string{"vocabulary", "scenarios", "derivations", "nonClaimDefinitions", "sourceNonClaimRefs"} {
		if !reflect.DeepEqual(view[key], input[key]) {
			t.Fatalf("complete declaration fields changed: %s", key)
		}
	}
	wantGroups := []any{map[string]any{"groupId": "RGRP-VIEW", "statementStem": "The renderer must", "sharedPremises": []any{"The caller selected this source."}, "requirementIds": []any{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"}}}
	if !reflect.DeepEqual(view["groups"], wantGroups) {
		t.Fatal("group index changed membership, context or identity")
	}
	rows := view["requirements"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["invariant"] != "The renderer must preserve groups." || rows[1].(map[string]any)["invariant"] != "The renderer must preserve declared scenarios." {
		t.Fatal("group view weakened complete atomic requirements")
	}
	sections := sourceDeclarationSections(view)
	want := []declarationRecord{{"DRV-VIEW", []declarationField{
		{"Source kind", []string{"owner_decision"}, true},
		{"Object format", []string{"sha1"}, true},
		{"Commit OID", []string{strings.Repeat("a", 40)}, true},
		{"Path", []string{"docs/decisions/view.md"}, true},
		{"SHA-256", []string{strings.Repeat("b", 64)}, true},
		{"Selector start", []string{"7"}, true},
		{"Selector end", []string{"19"}, true},
		{"Requirements", []string{"REQ-PROOFKIT-VIEW-002"}, true},
		{"Source-local non-claim refs", []string{"NCL-VIEW"}, true},
	}}}
	if !reflect.DeepEqual(sections[3].records, want) {
		t.Fatal("derivation human projection lost coordinates or roles")
	}
	if !reflect.DeepEqual(sections[2].records[0].fields, []declarationField{
		{"Requirements", []string{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"}, true},
		{"Parameters", []string{"surface"}, true},
		{"Preconditions", []string{"The ${surface} view is open."}, false},
		{"Action sequence", []string{"1. Submit Z first.", "2. Inspect A second."}, false},
		{"Expected observations", []string{"The value remains <input>."}, false},
		{"Forbidden observations", []string{"The source becomes execution proof."}, false},
		{"Vocabulary references", []string{"TERM-VIEW"}, true},
		{"Source-local non-claim refs", []string{"NCL-VIEW"}, true},
		{"Example EX-VIEW-1", []string{"surface: primary <input>"}, false},
		{"Example EX-VIEW-2", []string{"surface: secondary"}, false},
	}) {
		t.Fatal("scenario human projection lost a field, example parameter or action order")
	}
	if !reflect.DeepEqual(view["scenarios"], input["scenarios"]) {
		t.Fatal("formatting action ordinals mutated canonical scenario values")
	}
	input["vocabulary"].([]any)[0].(map[string]any)["label"] = "Changed caller input."
	if view["vocabulary"].([]any)[0].(map[string]any)["label"] != "Renderer <input>" {
		t.Fatal("view aliases untrusted caller input")
	}
}

func TestSourceDeclarationRenderersRetainFieldsAndEscapeText(t *testing.T) {
	input := declaredSourceFixture()
	for name, render := range map[string]func(any) (string, int, error){"markdown": BuildMarkdown, "html": BuildHTML} {
		document, exit, err := render(input)
		if err != nil || exit != 0 {
			t.Fatalf("%s: %v", name, err)
		}
		for _, required := range []string{"Source Groups", "Vocabulary", "Declared Scenarios", "Declared Derivations", "RGRP-VIEW", "TERM-VIEW", "SCN-VIEW", "EX-VIEW", "DRV-VIEW", "NCL-VIEW", "Selector start", "Selector end", "Submit Z first", "Inspect A second", "primary &lt;input&gt;", strings.Repeat("a", 40), strings.Repeat("b", 64)} {
			if !strings.Contains(document, required) && !(name == "markdown" && strings.Contains(document, strings.ReplaceAll(required, "-", `\-`))) {
				t.Fatalf("%s omitted %q", name, required)
			}
		}
		if strings.Contains(document, "<input>") || strings.Contains(document, "<script> vocabulary") {
			t.Fatalf("%s admitted raw caller markup", name)
		}
		if strings.Index(document, "Submit Z first") >= strings.Index(document, "Inspect A second") {
			t.Fatal("ordered actions were sorted")
		}
		if name == "html" {
			anchor := browserdoc.FragmentID("source-group:RGRP-VIEW")
			if !strings.Contains(document, `id="`+anchor+`"`) || !strings.Contains(document, `href="#`+anchor+`"`) {
				t.Fatal("source group navigation does not resolve")
			}
		}
	}
}

func TestSourceViewAbsentDeclarationsAreExplicitEmptyArrays(t *testing.T) {
	output, exit, err := BuildJSON(validRequirementSource())
	if err != nil || exit != 0 {
		t.Fatal(err)
	}
	view := output.(map[string]any)
	for _, key := range []string{"vocabulary", "scenarios", "derivations", "nonClaimDefinitions", "sourceNonClaimRefs"} {
		if !reflect.DeepEqual(view[key], []any{}) {
			t.Fatalf("absent %s did not project as an empty array", key)
		}
	}
}
