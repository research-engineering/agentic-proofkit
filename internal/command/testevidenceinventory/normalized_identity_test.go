package testevidenceinventory

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestNormalizedIdentityPreservesProducerConsumerBoundary(t *testing.T) {
	for _, size := range []int{1, 245, 246, 256} {
		input := validInventory(t).(map[string]any)
		id := strings.Repeat("a", size)
		input["inventoryId"] = id
		output, code, err := BuildNormalized(input)
		if err != nil || code != 0 || output["normalizedInventoryId"] != id+".normalized" {
			t.Fatalf("normalized identity at length %d: code=%d err=%v", size, code, err)
		}
		encoded, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)+1))
		if err != nil {
			t.Fatal(err)
		}
		projection, err := AdmitNormalizedProjection(wire, nil, "round trip")
		if err != nil || !reflect.DeepEqual(projection.Envelope, wire) {
			t.Fatalf("normalized wire conservation at length %d: %v", size, err)
		}
	}
}

func TestNormalizedIdentityAdmissionKeepsItsExactDomain(t *testing.T) {
	output, code, err := BuildNormalized(validInventory(t))
	if err != nil || code != 0 {
		t.Fatalf("baseline: code=%d err=%v", code, err)
	}
	for _, test := range []struct {
		name string
		id   any
		pass bool
	}{
		{"ordinary identity", "caller.original", true},
		{"ordinary maximum", strings.Repeat("a", 256), true},
		{"derived maximum", strings.Repeat("a", 256) + ".normalized", true},
		{"null", nil, false},
		{"wrong type", json.Number("1"), false},
		{"empty", "", false},
		{"missing base", ".normalized", false},
		{"unsuffixed overflow", strings.Repeat("a", 257), false},
		{"wrong suffix", strings.Repeat("a", 256) + ".other", false},
		{"base overflow", strings.Repeat("a", 257) + ".normalized", false},
		{"malformed base", strings.Repeat("a", 250) + "." + ".normalized", false},
		{"timestamp base", strings.Repeat("a", 240) + ".20260101.normalized", false},
		{"sensitive derived identity", "eyJ" + strings.Repeat("a", 251) + ".b.normalized", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			output["normalizedInventoryId"] = test.id
			projection, err := AdmitNormalizedProjection(output, nil, "identity")
			if (err == nil) != test.pass {
				t.Fatalf("admission pass=%t err=%v", test.pass, err)
			}
			if test.pass && projection.Envelope["normalizedInventoryId"] != test.id {
				t.Fatal("receiver rewrote an admitted identity")
			}
			if !test.pass && projection.Envelope != nil {
				t.Fatal("failed identity returned a partial envelope")
			}
		})
	}
}

func TestNormalizedIdentityRefusesUnsafeDerivedOutputWithoutChangingFailedReports(t *testing.T) {
	for _, id := range []string{"eyJabc.def", "eyJ" + strings.Repeat("a", 251) + ".b"} {
		input := validInventory(t).(map[string]any)
		input["inventoryId"] = id
		output, code, err := BuildNormalized(input)
		if err == nil || code != 1 || output != nil {
			t.Fatalf("unsafe derived ID produced output: code=%d err=%v", code, err)
		}
		if strings.Contains(err.Error(), id) {
			t.Fatal("derived identity escaped through diagnostics")
		}
		input["entries"].([]any)[0].(map[string]any)["commandRefs"] = []any{}
		output, code, err = BuildNormalized(input)
		if err != nil || code != 1 || output["reportKind"] != ReportKind || output["state"] != "failed" || output["reportId"] != id {
			t.Fatalf("failed-report branch changed: code=%d err=%v", code, err)
		}
		if _, exists := output["normalizedInventoryId"]; exists {
			t.Fatal("failed report acquired a derived identity")
		}
	}
}
