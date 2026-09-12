package requirementsourcecodec

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestRequirementFreeSourceWireRoundTrip(t *testing.T) {
	const source = `{
  "schemaVersion": 2,
  "kind": "proofkit.requirement-source",
  "sourceId": "proofkit.empty.source",
  "specPackagePath": "docs/specs/empty",
  "sourceNonClaims": ["Source admission does not prove coverage."],
  "sourceNonClaimRefs": [],
  "nonClaimDefinitions": [],
  "vocabulary": [],
  "derivations": [],
  "profiles": [],
  "groups": [],
  "scenarios": []
}
`
	result, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse(empty source): %v", err)
	}
	want := requirementsourcemodel.AtomicProjection{
		SourceID: "proofkit.empty.source", SpecPackagePath: "docs/specs/empty",
		SourceNonClaims: []string{"Source admission does not prove coverage."},
		Requirements:    []requirementsourcemodel.AtomicRequirement{}, Scenarios: []requirementsourcemodel.Scenario{},
	}
	if !reflect.DeepEqual(result.Model.Atomic(), want) {
		t.Fatal("wire admission lost source identity, denials or empty requirements")
	}
	location, ok := result.SourceMap.Location("/groups")
	if !ok || source[location.ValueSpan.Start:location.ValueSpan.End] != "[]" {
		t.Fatal("empty groups do not resolve to the actual wire array")
	}
	if _, ok := result.SourceMap.Location("/groups/0"); ok {
		t.Fatal("source map invented a group")
	}
	formatted, err := Format(result.Model)
	if err != nil || !bytes.Equal(formatted, []byte(source)) {
		t.Fatalf("canonical empty source differs from independent wire fixture: %v", err)
	}
	readmitted, err := Parse(formatted)
	if err != nil || !projectionsEqual(readmitted.Model, result.Model) {
		t.Fatalf("empty source failed whole-projection re-admission: %v", err)
	}
	second, err := Format(readmitted.Model)
	if err != nil || !bytes.Equal(second, formatted) {
		t.Fatalf("empty source formatting is not idempotent: %v", err)
	}

	for _, test := range []struct{ name, replacement, code, path string }{
		{"null groups", `"groups": null`, "invalid_null", "/groups"},
		{"wrong groups type", `"groups": {}`, "invalid_type", "/groups"},
		{"empty member group", `"groups": [{"groupId":"RGRP-EMPTY","profileId":"","statementStem":"","sharedPremises":[],"members":[]}]`, "group_member_budget_exceeded", "/groups/0/members"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := bytes.Replace([]byte(source), []byte(`"groups": []`), []byte(test.replacement), 1)
			_, err := Parse(payload)
			diagnostic, ok := err.(*Error)
			if !ok || diagnostic.Diagnostic().Code != test.code || diagnostic.Diagnostic().Path != test.path {
				t.Fatalf("Parse() = %v, want %s at %s", err, test.code, test.path)
			}
		})
	}
}

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

func TestSourceMapIndexesLexicalWireOrderNotNormalizedOrder(t *testing.T) {
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		groups := root["groups"].([]any)
		for left, right := 0, len(groups)-1; left < right; left, right = left+1, right-1 {
			groups[left], groups[right] = groups[right], groups[left]
		}
	})
	result, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	location, ok := result.SourceMap.Location("/groups/0/groupId")
	if !ok {
		t.Fatal("source map lacks lexical first group")
	}
	if got := payload[location.ValueSpan.Start:location.ValueSpan.End]; !bytes.Equal(got, []byte(`"RGRP-CODEC-SUPERSEDED"`)) {
		t.Fatalf("lexical first group = %q", got)
	}
	if result.Model.Layout().Groups[0].GroupID != "RGRP-CODEC-DEFERRED" {
		t.Fatal("model projection did not retain its independent normalized order")
	}
}
