package stablejson

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func FuzzMarshalCanonicalJSON(f *testing.F) {
	for _, seed := range []string{
		`{"z":3,"a":1}`,
		`{"items":[{"b":2,"a":1}]}`,
		`["plain",true,null,3]`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		value, err := admission.DecodeJSON(strings.NewReader(input), 4096)
		if err != nil {
			return
		}
		first, err := Marshal(value)
		if err != nil {
			t.Fatalf("Marshal accepted decoded JSON value: %v", err)
		}
		valueAgain, err := admission.DecodeJSON(bytes.NewReader(first), int64(len(first)+1))
		if err != nil {
			t.Fatalf("stable JSON must decode: %v\n%s", err, first)
		}
		second, err := Marshal(valueAgain)
		if err != nil {
			t.Fatalf("Marshal accepted round-tripped JSON value: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("Marshal must be canonical:\nfirst=%s\nsecond=%s", first, second)
		}
	})
}

func BenchmarkStableJSONLargeObject(b *testing.B) {
	values := map[string]any{}
	for index := 0; index < 1000; index++ {
		values[fmt.Sprintf("key-%04d", index)] = []any{"value", true, index}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Marshal(values); err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}
