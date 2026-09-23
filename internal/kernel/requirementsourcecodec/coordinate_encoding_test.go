package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestCoordinateEncodingPreservesTheSemanticIntegerDomain(t *testing.T) {
	for _, item := range []struct {
		name, startText, endText string
		start, end               int64
	}{
		{"zero", "0", "1", 0, 1},
		{"small", "1", "2", 1, 2},
		{"safe-boundary", "9007199254740990", "9007199254740991", 9007199254740990, 9007199254740991},
		{"beyond-binary64", "9007199254740992", "9007199254740993", 9007199254740992, 9007199254740993},
		{"int64-boundary", "9223372036854775806", "9223372036854775807", 9223372036854775806, 9223372036854775807},
	} {
		t.Run(item.name, func(t *testing.T) {
			draft := testDraft()
			draft.Derivations[0].Selector = requirementsourcemodel.ByteRange{Start: item.start, End: item.end}
			model, err := requirementsourcemodel.Normalize(draft)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := Format(model)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				SchemaVersion json.RawMessage `json:"schemaVersion"`
				Derivations   []struct {
					Selector map[string]json.RawMessage `json:"selector"`
				} `json:"derivations"`
			}
			if err := json.Unmarshal(payload, &wire); err != nil {
				t.Fatal(err)
			}
			if string(wire.SchemaVersion) != "2" || len(wire.Derivations) != 1 {
				t.Fatal("unrelated wire identity changed")
			}
			parsed, err := Parse(payload)
			if err != nil || !projectionsEqual(model, parsed.Model) {
				t.Fatalf("whole-model round trip: %v", err)
			}
			for key, text := range map[string]string{"start": item.startText, "end": item.endText} {
				want := `"` + text + `"`
				if string(wire.Derivations[0].Selector[key]) != want {
					t.Fatalf("%s coordinate is not exact decimal text", key)
				}
				location, exists := parsed.SourceMap.Location("/derivations/0/selector/" + key)
				if !exists || string(payload[location.ValueSpan.Start:location.ValueSpan.End]) != want {
					t.Fatalf("%s lexical coordinate does not cover the emitted token", key)
				}
			}
		})
	}
}

func TestCoordinateEncodingRejectsNoncanonicalWireValues(t *testing.T) {
	for _, item := range []struct {
		name, code string
		value      any
	}{
		{"number", "invalid_type", json.Number("64")},
		{"null", "invalid_null", nil},
		{"boolean", "invalid_type", true},
		{"empty", "invalid_integer", ""},
		{"fraction", "invalid_integer", "64.0"},
		{"exponent", "invalid_integer", "64e0"},
		{"positive-sign", "invalid_integer", "+64"},
		{"leading-zero", "invalid_integer", "064"},
		{"negative-zero", "invalid_integer", "-0"},
		{"overflow", "invalid_integer", "9223372036854775808"},
		{"underflow", "invalid_integer", "-9223372036854775809"},
		{"unicode-digit", "invalid_integer", "\u0661"},
		{"untrusted-text", "invalid_integer", "untrusted-coordinate"},
	} {
		t.Run(item.name, func(t *testing.T) {
			payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
				root["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)["end"] = item.value
			})
			_, err := Parse(payload)
			assertDiagnostic(t, err, item.code, "/derivations/0/selector/end")
			token, marshalErr := json.Marshal(item.value)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			prefix := []byte(`"selector":{"end":`)
			if bytes.Count(payload, prefix) != 1 {
				t.Fatal("diagnostic occurrence control is ambiguous")
			}
			start := int64(bytes.Index(payload, prefix) + len(prefix))
			want := ByteSpan{Start: start, End: start + int64(len(token))}
			if err.(*Error).Diagnostic().Span != want {
				t.Fatal("diagnostic does not identify the exact invalid coordinate token")
			}
			if bytes.Contains([]byte(err.Error()), []byte("untrusted-coordinate")) {
				t.Fatal("diagnostic disclosed rejected coordinate text")
			}
		})
	}
}

func TestCoordinateRangeMeaningRemainsModelOwned(t *testing.T) {
	for _, end := range []string{"-1", "0"} {
		payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
			root["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)["end"] = end
		})
		_, err := Parse(payload)
		assertDiagnostic(t, err, "invalid_byte_range", "/derivations/0/selector")
	}
}
