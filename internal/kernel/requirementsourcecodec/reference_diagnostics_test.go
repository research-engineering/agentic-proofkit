package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestScenarioValueDiagnosticPreservesDynamicKeyRedaction(t *testing.T) {
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		scenario := root["scenarios"].([]any)[0].(map[string]any)
		example := scenario["examples"].([]any)[0].(map[string]any)
		example["values"].(map[string]any)["surface"] = ""
	})
	_, err := Parse(payload)
	assertDiagnostic(t, err, "invalid_text", "/scenarios/0/examples/0/values/<entry>")
	span := err.(*Error).Diagnostic().Span
	if !bytes.Equal(payload[span.Start:span.End], []byte(`""`)) || strings.Contains(err.Error(), "surface") {
		t.Fatal("scenario diagnostic lost its lexical value or exposed the dynamic key")
	}
}

func TestDanglingNonClaimDiagnosticsResolveLexicalOwner(t *testing.T) {
	for _, owner := range []string{"source", "member", "profile", "scenario", "derivation"} {
		for _, reversed := range []bool{false, true} {
			for _, multiline := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reversed=%t/multiline=%t", owner, reversed, multiline), func(t *testing.T) {
					payload, path := danglingNonClaimPayload(t, owner, reversed)
					if multiline {
						var indented bytes.Buffer
						if err := json.Indent(&indented, payload, "", "  "); err != nil {
							t.Fatal(err)
						}
						payload = bytes.ReplaceAll(indented.Bytes(), []byte("\n"), []byte("\r\n"))
					}
					_, err := Parse(payload)
					assertDiagnostic(t, err, "dangling_nonclaim_ref", path)
					diagnostic := err.(*Error).Diagnostic()
					marker := bytes.Index(payload, []byte(`"NCL-ZZ.missing"`))
					if marker < 0 {
						t.Fatal("missing independent reference marker")
					}
					start := bytes.LastIndexByte(payload[:marker], '[')
					end := marker + bytes.IndexByte(payload[marker:], ']') + 1
					if diagnostic.Span != (ByteSpan{Start: int64(start), End: int64(end)}) {
						t.Fatalf("span = %#v, want original reference array [%d,%d)", diagnostic.Span, start, end)
					}
					positions := replayPositions(payload, SourceMap{entries: map[string]Location{path: {ValueSpan: diagnostic.Span}}})
					if diagnostic.CoordinateState != "scalar" || diagnostic.Start == nil || diagnostic.End == nil ||
						*diagnostic.Start != positions[int64(start)] || *diagnostic.End != positions[int64(end)] {
						t.Fatal("diagnostic scalar coordinates do not match original source")
					}
					if strings.Contains(err.Error(), "NCL-") || strings.Contains(diagnostic.Path, "SCN-") || strings.Contains(diagnostic.Path, "DRV-") {
						t.Fatal("diagnostic disclosed caller identity")
					}
					repaired := mutateRoot(t, payload, func(root map[string]any) {
						root["nonClaimDefinitions"] = append(root["nonClaimDefinitions"].([]any), map[string]any{
							"nonClaimId": "NCL-ZZ.missing", "statement": "This added declaration closes the reference only.",
						})
					})
					if _, err := Parse(repaired); err != nil {
						t.Fatalf("resolved reference control: %v", err)
					}
				})
			}
		}
	}
}

func danglingNonClaimPayload(t *testing.T, owner string, reversed bool) ([]byte, string) {
	t.Helper()
	path := "/sourceNonClaimRefs"
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		selected, key := root, "sourceNonClaimRefs"
		groups := root["groups"].([]any)
		members := groups[1].(map[string]any)["members"].([]any)
		switch owner {
		case "member", "profile":
			selected = members[0].(map[string]any)["fields"].(map[string]any)
			key = "nonClaimRefs"
			groupIndex, memberIndex := 1, 0
			if reversed {
				groupIndex = 0
				memberIndex = len(members) - 1
				groups[0], groups[1] = groups[1], groups[0]
				slices.Reverse(members)
			}
			path = fmt.Sprintf("/groups/%d/members/%d/fields/nonClaimRefs", groupIndex, memberIndex)
			if owner == "profile" {
				profile := root["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)
				profile[key] = selected[key]
				for _, member := range members {
					delete(member.(map[string]any)["fields"].(map[string]any), key)
				}
				selected, path = profile, "/profiles/0/fields/nonClaimRefs"
			}
		case "scenario", "derivation":
			collection, idKey, otherID := "scenarios", "scenarioId", "SCN-AA.other"
			if owner == "derivation" {
				collection, idKey, otherID = "derivations", "derivationId", "DRV-AA.other"
			}
			values := root[collection].([]any)
			selected, key = values[0].(map[string]any), "nonClaimRefs"
			selected[idKey] = selected[idKey].(string) + ".owner"
			other := make(map[string]any, len(selected))
			for field, value := range selected {
				other[field] = value
			}
			other[idKey] = otherID
			values = append(values, other)
			index := 0
			if reversed {
				index = 1
				slices.Reverse(values)
			}
			root[collection] = values
			path = fmt.Sprintf("/%s/%d/nonClaimRefs", collection, index)
		}
		refs := append([]any{}, selected[key].([]any)...)
		refs = append(refs, "NCL-ZZ.missing")
		if reversed {
			slices.Reverse(refs)
		}
		selected[key] = refs
	})
	return payload, path
}
