package witnesscommand

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestVocabularySnapshotPreservesOptionalWireAndNativeDefaults(t *testing.T) {
	for _, optional := range []map[string]any{
		{},
		{"environmentClassPolicies": nil, "parallelGroups": nil, "nonCacheableCredentialClasses": nil, "maxTimeoutMs": nil},
		{"environmentClassPolicies": []any{}, "parallelGroups": []any{}, "nonCacheableCredentialClasses": []any{}, "maxTimeoutMs": json.Number("1000")},
		{"maxTimeoutMs": json.Number("+1000")},
	} {
		raw := map[string]any{"artifactKinds": []any{}, "credentialClasses": []any{}, "environmentClasses": []any{}}
		for key, value := range optional {
			raw[key] = value
		}
		native, wire, err := AdmitVocabularySnapshot(raw)
		if err != nil || !reflect.DeepEqual(wire, raw) {
			t.Fatalf("optional presence or numeric spelling changed: %v", err)
		}
		want := 3600000
		if raw["maxTimeoutMs"] != nil {
			want = 1000
		}
		if native.MaxTimeoutMs != want || len(native.EnvironmentClassPolicies) != 0 || len(native.ParallelGroups) != 0 {
			t.Fatal("native defaults changed")
		}
	}
}

func TestVocabularySnapshotDetachesAllContainerLevels(t *testing.T) {
	raw := map[string]any{
		"artifactKinds": []any{"report"}, "credentialClasses": []any{"none"},
		"environmentClasses": []any{"local"}, "parallelGroups": []any{"one"},
		"environmentClassPolicies": []any{map[string]any{
			"environmentClass": "local", "networkPolicies": []any{"none"},
			"credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"},
		}},
	}
	native, wire, err := AdmitVocabularySnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw["artifactKinds"].([]any)[0] = "changed"
	raw["environmentClassPolicies"].([]any)[0].(map[string]any)["networkPolicies"].([]any)[0] = "external"
	if wire["artifactKinds"].([]any)[0] != "report" || native.ArtifactKinds[0] != "report" || native.EnvironmentClassPolicies[0].NetworkPolicies[0] != "none" ||
		wire["environmentClassPolicies"].([]any)[0].(map[string]any)["networkPolicies"].([]any)[0] != "none" {
		t.Fatal("caller changed owned wire or native policy")
	}
	delete(wire, "artifactKinds")
	wire["parallelGroups"].([]any)[0] = "changed"
	wire["environmentClassPolicies"].([]any)[0].(map[string]any)["cachePolicies"].([]any)[0] = "read-only"
	if raw["artifactKinds"] == nil || raw["parallelGroups"].([]any)[0] != "one" || native.ParallelGroups[0] != "one" ||
		native.EnvironmentClassPolicies[0].CachePolicies[0] != "disabled" ||
		raw["environmentClassPolicies"].([]any)[0].(map[string]any)["cachePolicies"].([]any)[0] != "disabled" {
		t.Fatal("wire mutation changed caller or admitted native policy")
	}
}

func TestVocabularySnapshotRetainsNativeNumericAndPolicyRejections(t *testing.T) {
	for _, value := range []any{0, 1.0, "1000", true, json.Number("0"), json.Number("-1"), json.Number("1.0"), json.Number("1e3"), json.Number("9223372036854775808")} {
		raw := map[string]any{"artifactKinds": []any{}, "credentialClasses": []any{}, "environmentClasses": []any{}, "maxTimeoutMs": value}
		if _, wire, err := AdmitVocabularySnapshot(raw); err == nil || wire != nil {
			t.Fatal("invalid numeric policy produced an admitted snapshot")
		}
	}
	for _, value := range []any{true, []any{nil}, []any{map[string]any{}}, []any{map[string]any{
		"environmentClass": "missing", "networkPolicies": []any{"none"}, "credentialClasses": []any{}, "cachePolicies": []any{"disabled"},
	}}} {
		raw := map[string]any{"artifactKinds": []any{}, "credentialClasses": []any{}, "environmentClasses": []any{}, "environmentClassPolicies": value}
		if _, wire, err := AdmitVocabularySnapshot(raw); err == nil || wire != nil {
			t.Fatal("invalid environment policy produced an admitted snapshot")
		}
	}
}
