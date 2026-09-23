package requirementbinding

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

func TestWitnessProjectionDetachesVocabulary(t *testing.T) {
	raw := map[string]any{
		"artifactKinds": []any{}, "credentialClasses": []any{"none"},
		"environmentClasses": []any{"local-go"}, "parallelGroups": []any{"local"},
		"maxTimeoutMs": json.Number("1000"), "nonCacheableCredentialClasses": nil,
		"environmentClassPolicies": []any{map[string]any{
			"environmentClass": "local-go", "networkPolicies": []any{"none"},
			"credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"},
		}},
	}
	want := cloneBindingShapeInput(t, raw)
	projection, err := BuildWitnessPlanInput(validRequirementBindingInput(), raw)
	if err != nil {
		t.Fatal(err)
	}
	owned := projection["vocabulary"].(map[string]any)
	if !reflect.DeepEqual(owned, want) {
		t.Fatal("vocabulary projection changed wire values or optional field presence")
	}
	raw["maxTimeoutMs"] = json.Number("1")
	raw["environmentClassPolicies"].([]any)[0].(map[string]any)["networkPolicies"].([]any)[0] = "external"
	if !reflect.DeepEqual(owned, want) {
		t.Fatal("caller mutation changed admitted vocabulary projection")
	}
	vocabulary, err := witnesscommand.AdmitVocabulary(owned)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range projection["commands"].([]any) {
		if _, err := witnesscommand.AdmitWithVocabulary(command, vocabulary); err != nil {
			t.Fatal("projection is no longer valid for downstream owner", err)
		}
	}
	owned["environmentClasses"].([]any)[0] = "other"
	owned["environmentClassPolicies"].([]any)[0].(map[string]any)["credentialClasses"].([]any)[0] = "other"
	if raw["environmentClasses"].([]any)[0] != "local-go" ||
		raw["environmentClassPolicies"].([]any)[0].(map[string]any)["credentialClasses"].([]any)[0] != "none" {
		t.Fatal("projection mutation reached caller vocabulary")
	}
}
