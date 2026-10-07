package requirementcoverageview

import (
	"strings"
	"testing"
)

func TestCompactWitnessReferencesSurviveOutputReadmission(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	input["requirementProofBinding"] = nil
	input["compactProofContract"] = validCompactCoverageContract()
	input["localEnvironmentPolicy"] = map[string]any{
		"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"},
	}
	entry := inventoryEntry(input)
	entry["witnessRefs"] = []any{}
	initial, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	row := initial.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)
	routes := row["declaredWitnessRoutes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("expected both compact witness roles, got %d", len(routes))
	}
	for _, raw := range routes {
		route := raw.(map[string]any)
		id := route["witnessRouteId"].(string)
		t.Run(route["role"].(string), func(t *testing.T) {
			entry["witnessRefs"] = []any{id}
			value, _, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("declared route refused by its output owner: %v", err)
			}
			record := value.(map[string]any)
			if _, err := AdmitOutput(record); err != nil {
				t.Fatal(err)
			}
			for _, failure := range stringArray(record["failures"]) {
				if strings.HasPrefix(failure, "unknown_command_or_witness_ref:") && strings.HasSuffix(failure, ":"+id) {
					t.Fatal("a retained route was classified as unknown")
				}
			}
			projected := record["requirementCoverage"].([]any)[0].(map[string]any)["tests"].([]any)[0].(map[string]any)
			projected["witnessRefs"] = []any{id + " "}
			if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "witnessRefs must retain canonical wire values") {
				t.Fatalf("noncanonical retained reference was not rejected at its field boundary: %v", err)
			}
		})
	}
	entry["witnessRefs"] = []any{"foreign.witness"}
	value, _, err := BuildJSON(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	record := value.(map[string]any)
	diagnostic := "unknown_command_or_witness_ref:" + entry["testId"].(string) + ":foreign.witness"
	found := false
	for _, failure := range stringArray(record["failures"]) {
		found = found || failure == diagnostic
	}
	if !found || record["state"] != "failed" {
		t.Fatal("foreign witness reference did not remain a failed diagnostic")
	}
	if _, err := AdmitOutput(record); err != nil {
		t.Fatal(err)
	}
}
