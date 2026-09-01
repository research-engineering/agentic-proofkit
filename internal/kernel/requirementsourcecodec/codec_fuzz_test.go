package requirementsourcecodec

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func FuzzParseCanonicalRoundTrip(f *testing.F) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(f, modelLimits)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schemaVersion":2,"kind":"proofkit.requirement-source"}`))
	model, err := requirementsourcemodel.NormalizeWithLimits(testDraft(), modelLimits)
	if err == nil {
		payload, formatErr := FormatWithLimits(model, codecLimits, modelLimits)
		if formatErr == nil {
			f.Add(payload)
		}
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		assertCodecFuzzProperties(t, source, codecLimits, modelLimits)
	})
}

func TestFuzzSeedCorpusRoundTrips(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"schemaVersion":2,"kind":"proofkit.requirement-source"}`),
		mustPayload(t),
	}
	for _, seed := range seeds {
		assertCodecFuzzProperties(t, seed, codecLimits, modelLimits)
	}
}

func assertCodecFuzzProperties(t testing.TB, source []byte, codecLimits Limits, modelLimits requirementsourcemodel.Limits) {
	t.Helper()
	first, firstErr := ParseWithLimits(source, codecLimits, modelLimits)
	second, secondErr := ParseWithLimits(source, codecLimits, modelLimits)
	if ErrorCode(firstErr) != ErrorCode(secondErr) {
		t.Fatalf("nondeterministic error code: %q != %q", ErrorCode(firstErr), ErrorCode(secondErr))
	}
	if firstErr != nil || secondErr != nil {
		if firstErr == nil || secondErr == nil || firstErr.Error() != secondErr.Error() {
			t.Fatalf("nondeterministic error: %v != %v", firstErr, secondErr)
		}
		return
	}
	if !projectionsEqual(first.Model, second.Model) {
		t.Fatal("same bytes produced different models")
	}
	canonical, err := FormatWithLimits(first.Model, codecLimits, modelLimits)
	if err != nil {
		t.Fatalf("Format(admitted model) error = %v", err)
	}
	reparsed, err := ParseWithLimits(canonical, codecLimits, modelLimits)
	if err != nil {
		t.Fatalf("Parse(canonical) error = %v", err)
	}
	if !projectionsEqual(first.Model, reparsed.Model) {
		t.Fatal("canonical round trip changed model")
	}
	secondCanonical, err := FormatWithLimits(reparsed.Model, codecLimits, modelLimits)
	if err != nil || !bytes.Equal(canonical, secondCanonical) {
		t.Fatal("canonical formatting is not idempotent")
	}
	assertFuzzSourceMap(t, source, first.SourceMap)
}

func assertFuzzSourceMap(t testing.TB, source []byte, sourceMap SourceMap) {
	t.Helper()
	pointers := sourceMap.Pointers()
	if !sortStringsEqual(pointers, append([]string(nil), pointers...)) {
		t.Fatal("source-map pointers are not sorted")
	}
	for _, pointer := range pointers {
		location, exists := sourceMap.Location(pointer)
		if !exists || !validFuzzSpan(location.ValueSpan, len(source)) {
			t.Fatalf("invalid value span for %q: %#v", pointer, location.ValueSpan)
		}
		if location.KeySpan != nil && !validFuzzSpan(*location.KeySpan, len(source)) {
			t.Fatalf("invalid key span for %q: %#v", pointer, *location.KeySpan)
		}
	}
}

func validFuzzSpan(span ByteSpan, length int) bool {
	return span.Start >= 0 && span.Start <= span.End && span.End <= int64(length)
}

func sortStringsEqual(actual []string, clone []string) bool {
	sortStrings(clone)
	return reflect.DeepEqual(actual, clone)
}
