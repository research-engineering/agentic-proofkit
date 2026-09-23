package deploymentevidenceadmission

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeploymentEvidenceUsesNormalizedSharedSecretPolicy(t *testing.T) {
	for _, value := range []string{"api_\u200bkey=synthetic-fixture-value", `"password": "synthetic-fixture-value"`} {
		input := validDeploymentEvidenceInput()
		input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note", "payload": map[string]any{"note": value}}}
		record, exit, err := Build(input)
		if err != nil || exit != 1 || record.State != "failed" {
			t.Fatalf("normalized secret evidence accepted: exit=%d state=%s error=%v", exit, record.State, err)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "synthetic-fixture-value") {
			t.Fatal("report disclosed synthetic evidence content")
		}
	}
}
