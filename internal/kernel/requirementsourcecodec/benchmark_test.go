package requirementsourcecodec

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func BenchmarkParseCanonicalSource(b *testing.B) {
	model, err := requirementsourcemodel.Normalize(testDraft())
	if err != nil {
		b.Fatal(err)
	}
	payload, err := Format(model)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := Parse(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormatCanonicalSource(b *testing.B) {
	model, err := requirementsourcemodel.Normalize(testDraft())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Format(model); err != nil {
			b.Fatal(err)
		}
	}
}
