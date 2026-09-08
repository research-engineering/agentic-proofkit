package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestEffectiveNonClaimDuplicateSelectsParticipatingReferenceOwner(t *testing.T) {
	for _, owner := range []string{"source", "member", "profile"} {
		for _, mixed := range []bool{false, true} {
			for _, reordered := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/mixed=%t/reordered=%t", owner, mixed, reordered), func(t *testing.T) {
					payload, path, refs := nonClaimDuplicatePayload(t, owner, mixed, reordered, false)
					_, err := Parse(payload)
					assertDiagnostic(t, err, "duplicate_effective_nonclaim", path)
					expected, encodeErr := json.Marshal(refs)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					span := err.(*Error).Diagnostic().Span
					if !bytes.Equal(payload[span.Start:span.End], expected) {
						t.Fatal("diagnostic did not select the exact participating reference array")
					}
					distinct, _, _ := nonClaimDuplicatePayload(t, owner, mixed, reordered, true)
					if _, err := Parse(distinct); err != nil {
						t.Fatalf("distinct statement control was rejected: %v", err)
					}
				})
			}
		}
	}
}

func nonClaimDuplicatePayload(t *testing.T, owner string, mixed, reordered, distinct bool) ([]byte, string, []any) {
	t.Helper()
	const statement = "Named boundary references do not execute witnesses."
	const different = "A separate boundary statement remains independent."
	var refs []any
	groupIndex, memberIndex := 1, 0
	if reordered {
		groupIndex, memberIndex = 0, 1
	}
	path := fmt.Sprintf("/groups/%d/members/%d/fields/nonClaimRefs", groupIndex, memberIndex)
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		groups := root["groups"].([]any)
		members := groups[1].(map[string]any)["members"].([]any)
		fields := members[0].(map[string]any)["fields"].(map[string]any)
		refOwner, directOwner := fields, fields
		refKey, directKey := "nonClaimRefs", "nonClaims"
		if owner == "source" {
			refOwner, directOwner = root, root
			refKey, directKey = "sourceNonClaimRefs", "sourceNonClaims"
			path = "/sourceNonClaimRefs"
		} else if owner == "profile" {
			refOwner = root["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)
			refOwner[refKey] = fields[refKey]
			for _, member := range members {
				delete(member.(map[string]any)["fields"].(map[string]any), refKey)
			}
			path = "/profiles/0/fields/nonClaimRefs"
		}
		refs = append(refOwner[refKey].([]any), "NCL-DUP-A")
		definitions := root["nonClaimDefinitions"].([]any)
		definitions = append(definitions, map[string]any{"nonClaimId": "NCL-DUP-A", "statement": statement})
		directOwner[directKey] = []any{}
		if mixed {
			text := statement
			if distinct {
				text = different
			}
			directOwner[directKey] = []any{text}
		} else {
			text := statement
			if distinct {
				text = different
			}
			definitions = append(definitions, map[string]any{"nonClaimId": "NCL-DUP-B", "statement": text})
			refs = append(refs, "NCL-DUP-B")
		}
		if reordered {
			slices.Reverse(definitions)
			slices.Reverse(refs)
			groups[0], groups[1] = groups[1], groups[0]
			members[0], members[1] = members[1], members[0]
		}
		root["nonClaimDefinitions"] = definitions
		refOwner[refKey] = refs
	})
	return payload, path, refs
}

func TestDottedRequirementDiagnosticsPreserveIdentityAndLexicalOwner(t *testing.T) {
	for _, profileOwned := range []bool{false, true} {
		for _, reordered := range []bool{false, true} {
			t.Run(fmt.Sprintf("profile=%t/reordered=%t", profileOwned, reordered), func(t *testing.T) {
				groupIndex, memberIndex := 1, 0
				if reordered {
					groupIndex, memberIndex = 0, 1
				}
				payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
					groups := root["groups"].([]any)
					group := groups[1].(map[string]any)
					members := group["members"].([]any)
					first := members[0].(map[string]any)
					first["requirementId"] = "REQ-AA.alpha"
					members[1].(map[string]any)["requirementId"] = "REQ-AA.alpha.proofBindingRefs"
					first["fields"].(map[string]any)["proofBindingRefs"] = []any{}
					if profileOwned {
						profile := root["profiles"].([]any)[0].(map[string]any)
						profile["fields"].(map[string]any)["proofBindingRefs"] = []any{}
						for _, member := range members {
							delete(member.(map[string]any)["fields"].(map[string]any), "proofBindingRefs")
						}
					}
					if reordered {
						groups[0], groups[1] = groups[1], groups[0]
						members[0], members[1] = members[1], members[0]
					}
				})
				path := fmt.Sprintf("/groups/%d/members/%d/fields/proofBindingRefs", groupIndex, memberIndex)
				if profileOwned {
					path = "/profiles/0/fields/proofBindingRefs"
				}
				_, err := Parse(payload)
				assertDiagnostic(t, err, "missing_proof_binding", path)
				span := err.(*Error).Diagnostic().Span
				if !bytes.Equal(payload[span.Start:span.End], []byte("[]")) {
					t.Fatal("diagnostic did not select the complete owner value")
				}
				if strings.Contains(err.Error(), "REQ-AA") {
					t.Fatal("diagnostic echoed the dynamic identifier")
				}
			})
		}
	}
}

func TestDottedDefinitionDiagnosticsResolveArrayEntry(t *testing.T) {
	for _, item := range []struct {
		root  string
		code  string
		value map[string]any
	}{
		{"profiles", "vacuous_profile", map[string]any{"profileId": "RPROF-AA.alpha", "fields": map[string]any{"ownerId": "proofkit.extra"}}},
		{"nonClaimDefinitions", "unreferenced_definition", map[string]any{"nonClaimId": "NCL-AA.alpha", "statement": "This statement has an independent owner."}},
		{"vocabulary", "unreferenced_vocabulary", map[string]any{"termId": "TERM-AA.alpha", "kind": "subject", "label": "sample", "definition": "An unused sample term."}},
	} {
		t.Run(item.root, func(t *testing.T) {
			payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
				root[item.root] = append([]any{item.value}, root[item.root].([]any)...)
			})
			_, err := Parse(payload)
			assertDiagnostic(t, err, item.code, "/"+item.root+"/0")
		})
	}
}

func TestInvalidUTF8UsesByteOnlyCoordinates(t *testing.T) {
	payload := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	_, err := Parse(payload)
	assertDiagnostic(t, err, "invalid_utf8", "")
	diagnostic := err.(*Error).Diagnostic()
	if diagnostic.CoordinateState != "byte_only" || diagnostic.Start != nil || diagnostic.End != nil {
		t.Fatalf("invalid UTF-8 coordinates = %#v", diagnostic)
	}
	if diagnostic.Span != (ByteSpan{Start: 6, End: 7}) {
		t.Fatalf("invalid UTF-8 span = %#v", diagnostic.Span)
	}
}

func TestBareCRAndCRLFAdvanceScalarLinesOnce(t *testing.T) {
	for _, item := range []struct {
		name      string
		separator string
	}{
		{name: "bare CR", separator: "\r"},
		{name: "CRLF", separator: "\r\n"},
	} {
		t.Run(item.name, func(t *testing.T) {
			payload := []byte(strings.Join([]string{
				"{", `  "kind":"proofkit.requirement-source",`, `  "schemaVersion":2,`, `  "sourceId":"safe",`, `  "extra":true`, "}",
			}, item.separator))
			_, err := Parse(payload)
			assertDiagnostic(t, err, "unknown_field", "/<unknown>")
			start := err.(*Error).Diagnostic().Start
			if start == nil || start.Line != 5 || start.ScalarColumn != 3 {
				t.Fatalf("diagnostic start = %#v", start)
			}
		})
	}
}

func TestMultipleValueDiagnosticSpansSecondToken(t *testing.T) {
	payload := append(append([]byte(nil), mustPayload(t)...), []byte(" true")...)
	_, err := Parse(payload)
	assertDiagnostic(t, err, "multiple_values", "")
	span := err.(*Error).Diagnostic().Span
	if !bytes.Equal(payload[span.Start:span.End], []byte("true")) {
		t.Fatalf("multiple-value span = %q", payload[span.Start:span.End])
	}
}

func TestValidUnicodeDiagnosticsUseScalarColumns(t *testing.T) {
	payload := []byte("{\n  \"kind\": \"proofkit.requirement-source\",\n  \"schemaVersion\": 2,\n  \"sourceId\": \"\u03bb\",\n  \"extra\": true\n}")
	_, err := Parse(payload)
	assertDiagnostic(t, err, "unknown_field", "/<unknown>")
	diagnostic := err.(*Error).Diagnostic()
	if diagnostic.CoordinateState != "scalar" || diagnostic.Start == nil || diagnostic.End == nil {
		t.Fatalf("valid UTF-8 coordinates = %#v", diagnostic)
	}
	if diagnostic.Start.Line != 5 || diagnostic.Start.ScalarColumn != 3 {
		t.Fatalf("unknown-field start = %#v", diagnostic.Start)
	}
}

func TestShapeDiagnosticSelectionFollowsSourceOrder(t *testing.T) {
	firstUnknown := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		root["zUnknown"] = true
		root["aUnknown"] = true
	})
	firstUnknown = moveFieldFirst(t, firstUnknown, "zUnknown")
	for run := 0; run < 20; run++ {
		_, err := Parse(firstUnknown)
		assertDiagnostic(t, err, "unknown_field", "/<unknown>")
		span := err.(*Error).Diagnostic().Span
		if !bytes.Equal(firstUnknown[span.Start:span.End], []byte(`"zUnknown"`)) {
			t.Fatalf("run %d selected %q", run, firstUnknown[span.Start:span.End])
		}
	}
}

func moveFieldFirst(t *testing.T, payload []byte, field string) []byte {
	t.Helper()
	needle := []byte(`"` + field + `":true`)
	index := bytes.Index(payload, needle)
	if index < 0 {
		t.Fatalf("field %q not found", field)
	}
	end := index + len(needle)
	if end < len(payload) && payload[end] == ',' {
		end++
	} else if index > 0 && payload[index-1] == ',' {
		index--
	}
	fieldBytes := append([]byte(nil), payload[index:end]...)
	fieldBytes = bytes.Trim(fieldBytes, ",")
	remainder := append([]byte(nil), payload[:index]...)
	remainder = append(remainder, payload[end:]...)
	return append(append(append([]byte{'{'}, fieldBytes...), ','), remainder[1:]...)
}
