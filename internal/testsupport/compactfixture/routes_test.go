package compactfixture

import (
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

func TestRoutesValuesAreCanonicalAndAliasFree(t *testing.T) {
	routes := MustRoutes(compactproofcontract.BindingIdentity{
		RequirementID: "REQ-TEST-001",
		ScenarioID:    "test.surface::scenario",
		SurfaceID:     "test.surface",
	}, "internal/test.go::TestPositive", "internal/test.go::TestFalsification")
	first := routes.Values([]string{"local-go"}, []string{"go test ./..."})
	if len(first) != 2 {
		t.Fatalf("route count=%d want 2", len(first))
	}
	left := first[0].(map[string]any)
	right := first[1].(map[string]any)
	if left["witnessRouteId"].(string) >= right["witnessRouteId"].(string) {
		t.Fatalf("routes are not sorted by witnessRouteId: %v", first)
	}
	byRole := map[string]map[string]any{left["role"].(string): left, right["role"].(string): right}
	if byRole[compactproofcontract.PositiveWitnessRole]["witnessRouteId"] != routes.PositiveRouteID || byRole[compactproofcontract.PositiveWitnessRole]["resolutionOrderIndex"] != json.Number("0") {
		t.Fatalf("positive route drifted: %v", byRole[compactproofcontract.PositiveWitnessRole])
	}
	if byRole[compactproofcontract.FalsificationWitnessRole]["witnessRouteId"] != routes.FalsificationRouteID || byRole[compactproofcontract.FalsificationWitnessRole]["resolutionOrderIndex"] != json.Number("1") {
		t.Fatalf("falsification route drifted: %v", byRole[compactproofcontract.FalsificationWitnessRole])
	}
	left["environmentClasses"].([]any)[0] = "mutated"
	second := routes.Values([]string{"local-go"}, []string{"go test ./..."})
	if second[0].(map[string]any)["environmentClasses"].([]any)[0] != "local-go" {
		t.Fatal("route fixture values alias a prior projection")
	}
}
