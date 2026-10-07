package pathidentity

import (
	"strings"
	"testing"
)

func BenchmarkPathIdentity(b *testing.B) {
	for _, input := range []struct{ name, path string }{
		{"ascii-lowercase", "proofkit/requirements.v2.json"},
		{"ascii-short", "Proofkit/Requirements.v2.json"},
		{"ascii-deep", strings.Repeat("Directory/", 62) + "FILE.json"},
		{"unicode", "Specs/caf\u00e9/\u1fb3\u030a/FILE.json"},
		{"non-starters", "Specs/A" + strings.Repeat("\u0301", 40) + "/FILE.json"},
	} {
		b.Run(input.name, func(b *testing.B) {
			b.Run("key", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := Key(input.path); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("prefixes", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := Prefixes(input.path); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("overlap", func(b *testing.B) {
				child := input.path + "/child"
				b.ReportAllocs()
				for b.Loop() {
					if _, err := Overlaps(input.path, child); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
