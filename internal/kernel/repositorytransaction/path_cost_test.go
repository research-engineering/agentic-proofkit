package repositorytransaction

import (
	"fmt"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
)

func BenchmarkPortablePathSet(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			paths := make([]string, count)
			for index := range paths {
				paths[index] = fmt.Sprintf("Sources/Package%04d/Internal/Requirements.v2.json", index)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := validatePortablePathSet(paths, pathidentity.CanonicalCaseless); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
