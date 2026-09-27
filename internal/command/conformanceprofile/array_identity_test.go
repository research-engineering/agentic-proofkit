package conformanceprofile

import (
	"strings"
	"testing"
)

func TestProfileTextArraysPreserveElementBoundaries(t *testing.T) {
	for _, test := range []struct {
		name               string
		manifest, expected []any
		wantError          string
	}{
		{"sorted multiline", []any{"a", "a\na"}, []any{"a", "a\na"}, ""},
		{"unsorted newline collision", []any{"a\na", "a"}, []any{"a", "a\na"}, "sorted and unique"},
		{"different partition", []any{"a", "b\nc"}, []any{"a\nb", "c"}, "nonClaims drift"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validConformanceProfileInput()
			input["manifest"].(map[string]any)["nonClaims"] = test.manifest
			input["policy"].(map[string]any)["expectedManifest"].(map[string]any)["nonClaims"] = test.expected
			result, err := BuildProfile(input, "local")
			if test.wantError == "" {
				if err != nil || result.ExitCode != 0 {
					t.Fatalf("valid multiline array rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("array boundary violation not rejected at its owner: %v", err)
			}
		})
	}
}
