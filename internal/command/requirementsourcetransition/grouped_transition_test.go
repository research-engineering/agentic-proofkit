package requirementsourcetransition

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTransitionRejectsObsoleteIdentityAndSourcePathOverrides(t *testing.T) {
	for _, field := range []string{"schemaVersion", "overviewPath", "requirementsPath"} {
		t.Run(field, func(t *testing.T) {
			input := validRequirementSourceTransitionInput(false)
			if field == "schemaVersion" {
				input[field] = json.Number("1")
			} else {
				input["next"].(map[string]any)[field] = "docs/specs/proofkit-test/other.json"
			}
			record, code, err := Build(input)
			if err == nil || code != 1 || record.ReportKind != "" {
				t.Fatalf("obsolete %s accepted: %v, %d, %v", field, record, code, err)
			}
		})
	}
}

func TestTransitionPolicyFailureHasNoFabricatedDelta(t *testing.T) {
	input := validRequirementSourceTransitionInput(false)
	firstRequirement(input["next"].(map[string]any))["proofBindingRefs"] = []any{}
	record, code, err := Build(input)
	if err != nil || code != 1 || record.SchemaVersion != 2 {
		t.Fatalf("Build() = %v, %d, %v", record, code, err)
	}
	for _, key := range []string{"addedRequirementCount", "lifecycleChangedRequirementCount", "missingRequirementCount"} {
		value, present := record.Summary[key]
		if !present || value != nil {
			t.Fatalf("unperformed comparison %s = %v (present %v)", key, value, present)
		}
	}
	for _, key := range []string{"previousRequirementCount", "nextRequirementCount"} {
		if record.Summary[key] != 1 {
			t.Fatalf("admitted summary %s = %v", key, record.Summary[key])
		}
	}
	encoded, err := json.Marshal(record.Diagnostics)
	if err != nil || !strings.Contains(string(encoded), "requirements.v2.json") || strings.Contains(string(encoded), "requirements.v1.json") {
		t.Fatalf("derived paths not current: %s, %v", encoded, err)
	}
}
