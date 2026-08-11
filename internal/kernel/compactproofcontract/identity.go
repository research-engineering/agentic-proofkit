package compactproofcontract

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const (
	PositiveWitnessRole      = "positive"
	FalsificationWitnessRole = "falsification"

	bindingRecordDomain = "proofkit.compact.binding-record.v2"
	witnessRouteDomain  = "proofkit.compact.witness-route.v2"
)

type BindingIdentity struct {
	RequirementID string
	ScenarioID    string
	SurfaceID     string
}

type WitnessRoute struct {
	BindingRecordID    string
	EnvironmentClasses []string
	Identity           BindingIdentity
	ResolutionOrder    int
	Role               string
	RouteID            string
	Selector           string
	VerifyCommands     []string
}

func (binding Binding) Identity() BindingIdentity {
	return BindingIdentity{
		RequirementID: binding.requirementID,
		ScenarioID:    binding.scenarioID,
		SurfaceID:     binding.surfaceID,
	}
}

func BindingRecordID(identity BindingIdentity) (string, error) {
	requirementID, err := admit.RuleID(identity.RequirementID, "compact requirement proof binding identity requirementId")
	if err != nil {
		return "", err
	}
	surfaceID, err := admit.RuleID(identity.SurfaceID, "compact requirement proof binding identity surfaceId")
	if err != nil {
		return "", err
	}
	scenarioID, scenarioSurfaceID, err := AdmitScenarioID(identity.ScenarioID, "compact requirement proof binding identity scenarioId")
	if err != nil {
		return "", err
	}
	if scenarioSurfaceID != surfaceID {
		return "", fmt.Errorf("compact requirement proof binding identity scenarioId must be scoped under surfaceId %s", surfaceID)
	}
	return digest.StableJSONSHA256Ref(map[string]any{
		"domain":        bindingRecordDomain,
		"requirementId": requirementID,
		"scenarioId":    scenarioID,
		"surfaceId":     surfaceID,
	})
}

func WitnessRouteID(bindingRecordID, role, selector string) (string, error) {
	bindingRecordID, err := admit.SHA256Ref(bindingRecordID, "compact requirement proof witness route bindingRecordId")
	if err != nil {
		return "", err
	}
	if role != PositiveWitnessRole && role != FalsificationWitnessRole {
		return "", fmt.Errorf("compact requirement proof witness role must be positive or falsification")
	}
	selector, err = AdmitWitnessSelector(selector, "compact requirement proof witness route selector")
	if err != nil {
		return "", err
	}
	return digest.StableJSONSHA256Ref(map[string]any{
		"bindingRecordId": bindingRecordID,
		"domain":          witnessRouteDomain,
		"role":            role,
		"selector":        selector,
	})
}

func (binding Binding) WitnessRoutes() ([]WitnessRoute, error) {
	routes := make([]WitnessRoute, 0, 2)
	for _, item := range []struct {
		Role    string
		RouteID string
		Witness Witness
	}{
		{Role: FalsificationWitnessRole, RouteID: binding.falsificationWitnessRouteID, Witness: binding.falsificationWitness},
		{Role: PositiveWitnessRole, RouteID: binding.positiveWitnessRouteID, Witness: binding.positiveWitness},
	} {
		routes = append(routes, WitnessRoute{
			BindingRecordID:    binding.recordID,
			EnvironmentClasses: append([]string{}, item.Witness.environmentClasses...),
			Identity:           binding.Identity(),
			ResolutionOrder:    item.Witness.resolutionOrderIndex,
			Role:               item.Role,
			RouteID:            item.RouteID,
			Selector:           item.Witness.selector,
			VerifyCommands:     append([]string{}, item.Witness.verifyCommands...),
		})
	}
	return routes, nil
}
