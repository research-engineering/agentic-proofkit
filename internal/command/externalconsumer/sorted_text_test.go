package externalconsumer

import (
	"slices"
	"testing"
)

func TestSortedTextNormalizesOrderAndRejectsDuplicates(t *testing.T) {
	got, err := sortedText([]any{"z", "a"}, "values")
	if err != nil || !slices.Equal(got, []string{"a", "z"}) {
		t.Fatalf("sortedText = %v, %v", got, err)
	}
	if _, err := sortedText([]any{"a", "a"}, "values"); err == nil || err.Error() != "values must be unique" {
		t.Fatalf("duplicate diagnostic = %v", err)
	}
}
