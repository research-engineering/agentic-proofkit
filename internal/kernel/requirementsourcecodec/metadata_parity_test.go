package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestBoundaryMetadataWireRoundTripPreservesExactOwnerValues(t *testing.T) {
	draft := testDraft()
	draft.SourceNonClaims = []string{"Source boundary keeps\nmultiple lines."}
	fields := &draft.Groups[0].Members[0].Fields
	fields.NonClaims = requirementsourcemodel.Own([]string{"Direct boundary keeps\ttabs."})
	fields.ExternalNonClaimRefs = requirementsourcemodel.Own([]string{"NCL-EXTERNAL", "external.native"})
	fields.ProofBindingRefs = requirementsourcemodel.Own([]string{"proofkit/alpha.json", "proofkit/beta.json"})
	model, err := requirementsourcemodel.Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Format(model)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(payload)
	if err != nil || !projectionsEqual(model, parsed.Model) {
		t.Fatalf("metadata round trip failed: %v", err)
	}
	first := parsed.Model.Atomic().Requirements[0]
	for _, check := range []struct{ got, want []string }{
		{parsed.Model.Atomic().SourceNonClaims, draft.SourceNonClaims},
		{first.NonClaims, fields.NonClaims.Value},
		{first.ExternalNonClaimRefs, fields.ExternalNonClaimRefs.Value},
		{first.ProofBindingRefs, fields.ProofBindingRefs.Value},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Fatal("a boundary field changed exact independently authored values")
		}
	}
	for path, expected := range map[string]string{
		"/sourceNonClaims/0":                                draft.SourceNonClaims[0],
		"/groups/1/members/0/fields/nonClaims/0":            fields.NonClaims.Value[0],
		"/groups/1/members/0/fields/externalNonClaimRefs/0": fields.ExternalNonClaimRefs.Value[0],
		"/groups/1/members/0/fields/proofBindingRefs/0":     fields.ProofBindingRefs.Value[0],
	} {
		location, ok := parsed.SourceMap.Location(path)
		if !ok {
			t.Fatalf("missing metadata source-map path %s", path)
		}
		var actual string
		if err := json.Unmarshal(payload[location.ValueSpan.Start:location.ValueSpan.End], &actual); err != nil || actual != expected {
			t.Fatalf("source map replay for %s: %v", path, err)
		}
	}
}

func TestBoundaryMetadataWireRejectsIncompleteOrInvalidFields(t *testing.T) {
	for _, field := range []string{"nonClaims", "externalNonClaimRefs", "proofBindingRefs"} {
		t.Run(field, func(t *testing.T) {
			for _, invalid := range []struct {
				value any
				code  string
				tail  string
			}{
				{nil, "invalid_null", ""},
				{true, "invalid_type", ""},
				{"not an array", "invalid_type", ""},
				{[]any{true}, "invalid_type", "/0"},
			} {
				payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
					group := root["groups"].([]any)[1].(map[string]any)
					member := group["members"].([]any)[0].(map[string]any)
					member["fields"].(map[string]any)[field] = invalid.value
				})
				_, err := Parse(payload)
				assertDiagnostic(t, err, invalid.code, "/groups/1/members/0/fields/"+field+invalid.tail)
			}
			payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
				group := root["groups"].([]any)[1].(map[string]any)
				member := group["members"].([]any)[0].(map[string]any)
				delete(member["fields"].(map[string]any), field)
			})
			_, err := Parse(payload)
			assertDiagnostic(t, err, "metadata_partition_violation", "/groups/1/members/0/fields/"+field)
		})
	}
	missing := mutateRoot(t, mustPayload(t), func(root map[string]any) { delete(root, "sourceNonClaims") })
	_, err := Parse(missing)
	assertDiagnostic(t, err, "missing_field", "/sourceNonClaims")
}

func TestBoundaryMetadataDiagnosticsResolveLexicalOwner(t *testing.T) {
	for _, item := range []struct {
		field string
		value []string
		code  string
		tail  string
	}{
		{"nonClaims", []string{"A direct boundary remains independent.", "A direct boundary remains independent."}, "duplicate_value", ""},
		{"externalNonClaimRefs", []string{"not an identifier"}, "invalid_id", "/0"},
		{"proofBindingRefs", []string{}, "missing_proof_binding", ""},
	} {
		for _, owner := range []string{"member", "profile"} {
			t.Run(item.field+"/"+owner, func(t *testing.T) {
				path := "/groups/1/members/0/fields/" + item.field
				if owner == "profile" {
					path = "/profiles/0/fields/" + item.field
				}
				payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
					group := root["groups"].([]any)[1].(map[string]any)
					members := group["members"].([]any)
					fields := members[0].(map[string]any)["fields"].(map[string]any)
					if owner == "profile" {
						profile := root["profiles"].([]any)[0].(map[string]any)
						profile["fields"].(map[string]any)[item.field] = fields[item.field]
						for _, member := range members {
							delete(member.(map[string]any)["fields"].(map[string]any), item.field)
						}
						fields = profile["fields"].(map[string]any)
					}
					fields[item.field] = item.value
				})
				_, err := Parse(payload)
				assertDiagnostic(t, err, item.code, path+item.tail)
				span := err.(*Error).Diagnostic().Span
				var expected any = item.value
				if item.tail == "/0" {
					expected = item.value[0]
				}
				encoded, encodeErr := json.Marshal(expected)
				if encodeErr != nil || !bytes.Equal(payload[span.Start:span.End], encoded) {
					t.Fatal("diagnostic did not resolve the exact lexical metadata owner value")
				}
			})
		}
	}
}
