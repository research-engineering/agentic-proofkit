package requirementsourceadmission

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func definitionFixture() []any {
	return []any{
		map[string]any{"nonClaimId": "NCL-ALPHA", "statement": "No first guarantee."},
		map[string]any{"nonClaimId": "NCL-BETA", "statement": "No second guarantee."},
	}
}

func TestNonClaimDefinitionSupportIsCanonicalScopedAndDetached(t *testing.T) {
	raw := definitionFixture()
	dictionary, err := AdmitNonClaimDefinitions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dictionary.Value(), raw) {
		t.Fatal("dictionary changed complete canonical rows")
	}
	selected, err := dictionary.Select([]string{"NCL-BETA", "NCL-BETA"})
	if err != nil || !reflect.DeepEqual(selected.Value(), []any{raw[1]}) {
		t.Fatal("selection lost identity or duplicated a query union")
	}
	if err := selected.RequireExactRefs([]string{"NCL-BETA"}); err != nil {
		t.Fatal(err)
	}
	if err := dictionary.RequireExactRefs([]string{"NCL-BETA"}); err == nil {
		t.Fatal("unused definition passed minimal support closure")
	}
	if _, err := dictionary.Select([]string{"NC-EXTERNAL"}); err == nil {
		t.Fatal("external ref treated as a local definition")
	}
	if err := dictionary.CheckScope([]string{"Separate direct denial."}, []string{"NCL-ALPHA"}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ direct, refs []string }{
		{[]string{"No first guarantee."}, []string{"NCL-ALPHA"}},
		{nil, []string{"NCL-MISSING"}}, {nil, []string{"NCL-ALPHA", "NCL-ALPHA"}},
		{nil, []string{" NCL-ALPHA"}}, {[]string{" padded denial "}, nil},
		{[]string{"same", "same"}, nil},
	} {
		if err := dictionary.CheckScope(item.direct, item.refs); err == nil {
			t.Fatal("invalid effective denial scope admitted")
		}
	}
	raw[0].(map[string]any)["statement"] = "Changed caller value."
	projected := dictionary.Value()
	projected[0].(map[string]any)["statement"] = "Changed projection."
	if !reflect.DeepEqual(dictionary.Value(), definitionFixture()) {
		t.Fatal("caller or projection mutated dictionary")
	}
	other, err := AdmitNonClaimDefinitions([]any{map[string]any{"nonClaimId": "NCL-ALPHA", "statement": "Other source boundary."}})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(other.Value(), dictionary.Value()[:1]) {
		t.Fatal("two independent source dictionaries were merged")
	}
	empty, err := AdmitNonClaimDefinitions([]any{})
	if err != nil || len(empty.Value()) != 0 || empty.CheckScope(nil, nil) != nil {
		t.Fatal("empty support is not usable for empty refs")
	}
	if _, err := empty.Select([]string{"NCL-ALPHA"}); err == nil {
		t.Fatal("empty support resolved a local ref")
	}
}

func TestNonClaimDefinitionAdmissionRejectsMalformedOrNoncanonicalRows(t *testing.T) {
	for _, raw := range []any{
		nil, map[string]any{}, []any{nil}, []any{map[string]any{}},
		[]any{map[string]any{"nonClaimId": "NCL-ALPHA", "statement": 1}},
		[]any{map[string]any{"nonClaimId": "NCL-ALPHA", "statement": "No guarantee.", "extra": true}},
		[]any{map[string]any{"nonClaimId": "NCL-ALPHA"}},
		[]any{map[string]any{"nonClaimId": "NC-EXTERNAL", "statement": "No guarantee."}},
		[]any{map[string]any{"nonClaimId": " NCL-ALPHA", "statement": "No guarantee."}},
		[]any{map[string]any{"nonClaimId": "NCL-ALPHA", "statement": " No guarantee."}},
		[]any{definitionFixture()[1], definitionFixture()[0]},
		[]any{definitionFixture()[0], definitionFixture()[0]},
		make([]any, requirementsourcemodel.DefaultLimits().MaxDefinitions+1),
	} {
		if _, err := AdmitNonClaimDefinitions(raw); err == nil {
			t.Fatal("malformed or noncanonical dictionary admitted")
		}
	}
	canary := "api_key=" + strings.Repeat("x", 32)
	for _, row := range []any{
		map[string]any{"nonClaimId": "NCL-ALPHA", "statement": canary},
		map[string]any{"nonClaimId": "NCL-ALPHA", "statement": "No guarantee.", canary: true},
	} {
		if _, err := AdmitNonClaimDefinitions([]any{row}); err == nil || strings.Contains(err.Error(), canary) {
			t.Fatal("dictionary disclosed or admitted a secret-shaped value")
		}
	}
}

func TestSourceDefinitionProjectionPreservesIndependentSourceNamespaces(t *testing.T) {
	var dictionaries []NonClaimDefinitions
	var sources []Source
	cases := []struct{ sourceID, statement string }{
		{"source.first", "No first guarantee."}, {"source.second", "No second guarantee."},
	}
	for _, item := range cases {
		input := validSource()
		input["sourceId"] = item.sourceID
		input["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-LOCAL", "statement": item.statement}}
		sourceMember(input, 0)["fields"].(map[string]any)["nonClaimRefs"] = []any{"NCL-LOCAL"}
		admitted, err := Evaluate(input)
		if err != nil || admitted.ExitCode != 0 {
			t.Fatalf("source premise: %v %v", err, admitted.Failures)
		}
		dictionaries = append(dictionaries, admitted.Source.NonClaimDefinitions())
		sources = append(sources, admitted.Source)
		input["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = "Changed."
	}
	for i, item := range cases {
		want := []any{map[string]any{"nonClaimId": "NCL-LOCAL", "statement": item.statement}}
		if sources[i].SourceID() != item.sourceID || !reflect.DeepEqual(dictionaries[i].Value(), want) || !reflect.DeepEqual(sources[i].NonClaimDefinitions().Value(), want) {
			t.Fatal("admitted source or independent namespace changed")
		}
	}
}
