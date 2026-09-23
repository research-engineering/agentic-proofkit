package requirementdiff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOutputAdmissionPreservesRequiredDiffIdentity(t *testing.T) {
	base := contextFixture(t, "The baseline invariant remains explicit.")
	current := contextFixture(t, "The revised invariant remains explicit.")
	output, err := Build(map[string]any{
		"schemaVersion": json.Number("3"), "diffId": "consumer.identity.diff",
		"baseContext": base, "currentContext": current,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshotID := current["snapshotId"].(string)
	for _, version := range []string{"3"} {
		t.Run("v"+version, func(t *testing.T) {
			wire := cloneRequirementRecord(t, output)
			before := stableBytes(t, wire)
			admitted, err := AdmitOutput(wire, snapshotID)
			if err != nil || !bytes.Equal(stableBytes(t, admitted), stableBytes(t, output)) {
				t.Fatalf("authentic output did not re-admit exactly: %v", err)
			}
			if !bytes.Equal(before, stableBytes(t, wire)) {
				t.Fatal("successful admission mutated its input")
			}
			for _, tc := range []struct {
				name    string
				value   any
				missing bool
			}{
				{name: "missing", missing: true},
				{name: "null", value: nil},
				{name: "number", value: json.Number("1")},
				{name: "boolean", value: true},
				{name: "array", value: []any{}},
				{name: "object", value: map[string]any{}},
				{name: "empty", value: ""},
				{name: "invalid", value: "caller-private/id"},
				{name: "padded", value: " consumer.identity.diff "},
				{name: "overlong", value: strings.Repeat("x", 257)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					changed := cloneRequirementRecord(t, wire)
					if tc.missing {
						delete(changed, "diffId")
					} else {
						changed["diffId"] = tc.value
					}
					before := stableBytes(t, changed)
					if _, err := AdmitOutput(changed, snapshotID); err == nil || !strings.Contains(err.Error(), "diffId") {
						t.Fatalf("counterfeit identity did not fail at diffId: %v", err)
					} else if strings.Contains(err.Error(), "caller-private") {
						t.Fatal("identity admission disclosed caller text")
					}
					if !bytes.Equal(before, stableBytes(t, changed)) {
						t.Fatal("failed admission mutated its input")
					}
				})
			}
		})
	}
}
