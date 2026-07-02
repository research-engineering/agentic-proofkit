package admission

import (
	"bytes"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func FuzzDecodeJSONStableRoundTrip(f *testing.F) {
	for _, seed := range []string{
		`{"b":2,"a":[true,null,"text"]}`,
		`{"nested":{"slash/key":1,"tilde~key":2}}`,
		`[{"id":"first"},{"id":"second"}]`,
		`{"secret":"redacted","duplicate":"first","other":"second"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		value, err := DecodeJSON(strings.NewReader(input), 4096)
		if err != nil {
			return
		}
		encoded, err := stablejson.Marshal(value)
		if err != nil {
			t.Fatalf("accepted JSON must be stable-serializable: %v", err)
		}
		roundTrip, err := DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)+1))
		if err != nil {
			t.Fatalf("stable JSON must decode: %v\n%s", err, encoded)
		}
		encodedAgain, err := stablejson.Marshal(roundTrip)
		if err != nil {
			t.Fatalf("round-tripped JSON must be stable-serializable: %v", err)
		}
		if !bytes.Equal(encoded, encodedAgain) {
			t.Fatalf("stable JSON must be idempotent:\nfirst=%s\nsecond=%s", encoded, encodedAgain)
		}
	})
}

func BenchmarkDecodeJSONRepositoryScale(b *testing.B) {
	var builder strings.Builder
	builder.WriteString(`{"requirements":[`)
	for index := 0; index < 1000; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`{"requirementId":"REQ-`)
		builder.WriteString(strings.Repeat("A", 8))
		builder.WriteString(`","claimLevel":"blocking","proofBindingRefs":["proofkit/requirement-bindings.json"]}`)
	}
	builder.WriteString(`]}`)
	input := builder.String()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeJSON(strings.NewReader(input), int64(len(input)+1)); err != nil {
			b.Fatalf("DecodeJSON failed: %v", err)
		}
	}
}
