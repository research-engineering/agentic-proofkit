package requirementsourcecodec

import (
	"bytes"
	"testing"
)

func TestFormatParseRoundTripPreservesEveryProjection(t *testing.T) {
	model := mustModel(t)
	payload, err := Format(model)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	result, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse(Format()) error = %v\npayload:\n%s", err, payload)
	}
	if !projectionsEqual(result.Model, model) {
		t.Fatal("Parse(Format(model)) changed an admitted projection")
	}
}

func TestCanonicalFormatIsIdempotent(t *testing.T) {
	first, err := Format(mustModel(t))
	if err != nil {
		t.Fatalf("first Format() error = %v", err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	second, err := Format(parsed.Model)
	if err != nil {
		t.Fatalf("second Format() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical formatting is not idempotent")
	}
	if len(first) == 0 || first[len(first)-1] != '\n' || bytes.HasSuffix(first, []byte("\n\n")) {
		t.Fatal("canonical payload must end in exactly one LF")
	}
}

func TestFormatPreservesMetadataAbsenceNullAndRecord(t *testing.T) {
	payload, err := Format(mustModel(t))
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !bytes.Contains(payload, []byte(`"deferral":null`)) {
		t.Fatal("present-null deferral was not serialized")
	}
	if !bytes.Contains(payload, []byte(`"reviewCondition":"Review after the codec experiment."`)) {
		t.Fatal("present-record deferral was not serialized")
	}
	if bytes.Contains(payload, []byte(`"profileId":"RPROF-CODEC-BLOCKING","fields":{"ownerId":"proofkit.codec","claimLevel":"blocking","riskClass":"high","nonClaimRefs"`)) {
		t.Fatal("absent profile metadata was materialized")
	}
}

func TestSourceMapReplaysKeyAndValueSpans(t *testing.T) {
	payload, err := Format(mustModel(t))
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	result, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	location, ok := result.SourceMap.Location("/groups/1/members/1/requirementId")
	if !ok || location.KeySpan == nil {
		t.Fatal("source map lacks requirementId key/value spans")
	}
	key := payload[location.KeySpan.Start:location.KeySpan.End]
	value := payload[location.ValueSpan.Start:location.ValueSpan.End]
	if !bytes.Equal(key, []byte(`"requirementId"`)) || !bytes.Equal(value, []byte(`"REQ-CODEC-002"`)) {
		t.Fatalf("source-map replay = key %q value %q", key, value)
	}
	if location.Start.Line <= 0 || location.Start.ScalarColumn <= 0 || location.End.Line <= 0 || location.End.ScalarColumn <= 0 {
		t.Fatal("valid UTF-8 source map lacks scalar coordinates")
	}
}

func TestReturnedSourceMapIsImmutable(t *testing.T) {
	payload, err := Format(mustModel(t))
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	result, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	first, ok := result.SourceMap.Location("/sourceId")
	if !ok || first.KeySpan == nil {
		t.Fatal("sourceId location missing")
	}
	first.KeySpan.Start = -1
	second, ok := result.SourceMap.Location("/sourceId")
	if !ok || second.KeySpan == nil || second.KeySpan.Start < 0 {
		t.Fatal("caller mutation escaped into source-map owner state")
	}
}
