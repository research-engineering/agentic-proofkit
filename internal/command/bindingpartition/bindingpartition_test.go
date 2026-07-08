package bindingpartition

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildRejectsCrossSurfaceRouteReferenceWithoutDelegation(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.007367819136484564623482005833685691497213272711615520825513165365000892708767")
	record, exitCode, err := Build(validBindingPartitionInput(false))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", exitCode, record.State)
	}

	record, exitCode, err = Build(validBindingPartitionInput(true))
	if err != nil {
		t.Fatalf("Build() cross-surface reference error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "crosses owner or surface without exact delegation") {
		t.Fatalf("Build() accepted undelegated cross-surface proof route: exitCode=%d record=%s", exitCode, string(encoded))
	}
}

func validBindingPartitionInput(includeCrossSurfaceReference bool) map[string]any {
	routeReferences := []any{}
	if includeCrossSurfaceReference {
		routeReferences = append(routeReferences, map[string]any{
			"referenceId":       "proofkit.test.reference",
			"referrerOwnerId":   "owner.secondary",
			"referrerSurfaceId": "surface.secondary",
			"proofRouteRef":     "route.primary",
			"delegationRefs":    []any{},
		})
	}
	return map[string]any{
		"schemaVersion":  json.Number("1"),
		"partitionId":    "proofkit.test.partition",
		"proofRouteRefs": []any{"route.primary"},
		"nonClaims":      []any{"Binding partition test input does not approve merge."},
		"bindingSurfaces": []any{
			map[string]any{"surfaceId": "surface.primary", "ownerId": "owner.primary", "selectorRefs": []any{"selector.primary"}},
			map[string]any{"surfaceId": "surface.secondary", "ownerId": "owner.secondary", "selectorRefs": []any{"selector.secondary"}},
		},
		"routeOwners": []any{
			map[string]any{
				"proofRouteRef":   "route.primary",
				"ownerId":         "owner.primary",
				"surfaceId":       "surface.primary",
				"selectorRefs":    []any{"selector.primary"},
				"cohesionGroupId": "group.primary",
			},
		},
		"routeReferences":   routeReferences,
		"delegations":       []any{},
		"surfaceThresholds": []any{},
	}
}
