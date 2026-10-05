package testevidenceinventory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
)

func TestDiscoveryProjectionAdmitsComposedTextBeforeSuccess(t *testing.T) {
	for _, field := range []string{"draftId", "testId"} {
		for _, id := range []string{"ordinary.id", strings.Repeat("a", 256), "eyJabc" + ".def"} {
			input := validDiscoveryDraft()
			if field == "draftId" {
				input[field] = id
			} else {
				firstDiscoveryTest(input)[field] = id
			}
			record, code, err := BuildDiscoveryDraft(input)
			if strings.HasPrefix(id, "eyJ") {
				if err == nil || code != 1 || record.ReportKind != "" || record.Diagnostics != nil {
					t.Fatalf("unsafe composed %s returned a partial/successful report", field)
				}
				if strings.Contains(err.Error(), id) {
					t.Fatal("error echoed rejected identity")
				}
				continue
			}
			if err != nil || code != 0 {
				t.Fatalf("safe composed %s: code=%d err=%v", field, code, err)
			}
			findings, err := secretjson.Scan(record.JSONValue(), "fixture")
			if err != nil || len(findings) != 0 {
				t.Fatalf("successful report failed independent scan: %v", err)
			}
			candidate := diagnosticValue(record.JSONValue(), "candidateInventory").(map[string]any)
			if candidate["inventoryId"] != input["draftId"].(string)+".candidate_inventory" || candidate["authority"] != discoveryCandidateInventoryAuthority {
				t.Fatal("safe identity or candidate authority changed")
			}
		}
	}
}

func TestSourceSetFalsifierIdentityIsCollectionWide(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		input := multiSourceSetInventory(t).(map[string]any)
		texts := input["sourceTexts"].([]any)
		first := texts[0].(map[string]any)
		second := texts[1].(map[string]any)
		decode := func(text string) map[string]any {
			value, err := admission.DecodeJSON(strings.NewReader(text), int64(len(text)+1))
			if err != nil {
				t.Fatal(err)
			}
			return value.(map[string]any)
		}
		a, b := decode(first["text"].(string)), decode(second["text"].(string))
		entries := func(wrapper map[string]any) []any { return wrapper["inventory"].(map[string]any)["entries"].([]any) }
		if duplicate {
			left := entries(a)[0].(map[string]any)["falsifier"].(map[string]any)
			right := entries(b)[0].(map[string]any)["falsifier"].(map[string]any)
			right["falsifierId"] = left["falsifierId"]
			encoded, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			second["text"] = string(encoded)
			input["sources"].([]any)[1].([]any)[2] = sha256Text(string(encoded))
		}
		if _, err := Evaluate(b); err != nil {
			t.Fatalf("fragment itself must remain admissible: %v", err)
		}
		output, code, err := BuildNormalized(input)
		if duplicate {
			if err == nil || !strings.Contains(err.Error(), "falsifierIds") || code != 1 || output != nil {
				t.Fatalf("duplicate identity was not rejected before projection: code=%d err=%v", code, err)
			}
			if _, _, err := Build(input); err == nil {
				t.Fatal("ordinary report accepted duplicate identity")
			}
			continue
		}
		if err != nil || code != 0 {
			t.Fatalf("distinct identities: code=%d err=%v", code, err)
		}
		encoded, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)+1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AdmitNormalizedProjection(wire, nil, "round trip"); err != nil {
			t.Fatalf("producer output rejected: %v", err)
		}
	}
}
