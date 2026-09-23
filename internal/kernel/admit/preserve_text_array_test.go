package admit

import (
	"reflect"
	"strings"
	"testing"
)

func TestPreserveSortedTextArrayMatchesTypedAdmissionWithoutPretrimming(t *testing.T) {
	for _, values := range [][]string{
		{}, {"alpha"}, {"alpha", "beta"}, {"\u00e9"},
		{" alpha"}, {"alpha "}, {"\nalpha"}, {"alpha\n"}, {"\u00a0alpha"},
		{"beta", "alpha"}, {"alpha", "alpha"}, {""}, {" "},
	} {
		for _, allowEmpty := range []bool{false, true} {
			typed, typedErr := PreserveSortedText(values, "values", allowEmpty)
			raw := make([]any, len(values))
			for i, value := range values {
				raw[i] = value
			}
			actual, err := PreserveSortedTextArray(raw, "values", allowEmpty)
			if (typedErr == nil) != (err == nil) || !reflect.DeepEqual(typed, actual) {
				t.Fatalf("array and typed preservation disagree for %#v", values)
			}
			if err == nil && !reflect.DeepEqual(actual, values) {
				t.Fatal("preserving admission rewrote input")
			}
		}
	}
	for _, raw := range []any{nil, "alpha", []any{1}, []any{false}, []any{map[string]any{}}, []any{nil}} {
		if _, err := PreserveSortedTextArray(raw, "values", true); err == nil {
			t.Fatal("non-string-array input admitted")
		}
	}
	normalized, err := NormalizeSortedTextArray([]any{" beta ", " alpha "}, "values", false)
	if err != nil || !reflect.DeepEqual(normalized, []string{"alpha", "beta"}) {
		t.Fatal("normalization semantics changed")
	}
	canary := "api_key=" + strings.Repeat("x", 32)
	if _, err := PreserveSortedTextArray([]any{canary}, "values", false); err == nil || strings.Contains(err.Error(), canary) {
		t.Fatal("secret-shaped value accepted or disclosed")
	}
}
