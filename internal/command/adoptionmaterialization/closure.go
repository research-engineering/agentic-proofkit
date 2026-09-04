package adoptionmaterialization

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

func validateClosure(request Request) error {
	pathUses := []pathUse{
		{Path: ProjectManifestPath, Role: roleManifestTarget, Target: true},
		{Path: request.BindingPath, Role: roleBindingTarget, Target: true},
		{Path: request.InventoryPath, Role: roleInventoryTarget, Target: true},
	}
	sourceIDs := map[string]struct{}{}
	requirements := map[string]requirementsourceadmission.Requirement{}
	requirementPaths := map[string]string{}
	for _, source := range request.Sources {
		if _, exists := sourceIDs[source.SourceID]; exists {
			return fmt.Errorf("adoption materialization requirement sourceIds must be unique")
		}
		sourceIDs[source.SourceID] = struct{}{}
		pathUses = append(pathUses,
			pathUse{Path: source.RequirementsPath, Role: roleRequirementSource, Target: true},
			pathUse{Path: source.OverviewPath, Role: roleOverviewReference},
		)
		for _, requirement := range source.Requirements {
			if _, exists := requirements[requirement.RequirementID]; exists {
				return fmt.Errorf("adoption materialization requirementIds must be unique across sources")
			}
			for _, proofRef := range requirement.ProofBindingRefs {
				if proofRef != request.BindingPath {
					return fmt.Errorf("adoption materialization requirement proofBindingRefs must resolve to the materialized binding path")
				}
			}
			requirements[requirement.RequirementID] = requirement
			requirementPaths[requirement.RequirementID] = source.RequirementsPath
		}
	}
	if len(request.Binding.Requirements) != len(requirements) {
		return fmt.Errorf("adoption materialization binding requirement set must equal the source requirement set")
	}
	for _, bindingRequirement := range request.Binding.Requirements {
		sourceRequirement, ok := requirements[bindingRequirement.RequirementID]
		if !ok || !sameRequirementProjection(sourceRequirement, bindingRequirement, requirementPaths[bindingRequirement.RequirementID]) {
			return fmt.Errorf("adoption materialization binding requirement projection does not match its source owner")
		}
		pathUses = append(pathUses, pathUse{Path: bindingRequirement.SpecPath, Role: roleRequirementSpecRef})
	}
	for _, binding := range request.Binding.Bindings {
		pathUses = append(pathUses, pathUse{Path: binding.WitnessPath, Role: roleWitnessSourceReference})
	}
	for _, entry := range request.Inventory.Entries {
		pathUses = append(pathUses, pathUse{Path: entry.SourcePath, Role: roleTestSourceReference})
	}
	if err := validatePathRoles(pathUses); err != nil {
		return err
	}
	return validateInventoryReferences(request, requirements)
}

func sameRequirementProjection(source requirementsourceadmission.Requirement, binding requirementbinding.Requirement, specPath string) bool {
	return source.RequirementID == binding.RequirementID &&
		source.OwnerID == binding.OwnerID &&
		source.ClaimLevel == binding.ClaimLevel &&
		specPath == binding.SpecPath &&
		slices.Equal(source.NonClaims, binding.NonClaims)
}

func validateInventoryReferences(request Request, requirements map[string]requirementsourceadmission.Requirement) error {
	routes := newBindingRouteIndex(request.Binding.Bindings)
	for _, entry := range request.Inventory.Entries {
		requirementRefs := stringSet(entry.RequirementRefs)
		witnessRefs := stringSet(entry.WitnessRefs)
		commandRefs := stringSet(entry.CommandRefs)
		for _, requirementID := range entry.RequirementRefs {
			if _, ok := requirements[requirementID]; !ok {
				return fmt.Errorf("adoption materialization test inventory references an unknown requirement")
			}
			if !routes.hasRequirementRoute(requirementID, witnessRefs, commandRefs, entry.SourcePath) {
				return fmt.Errorf("adoption materialization test inventory requirement reference is not connected to its witness route")
			}
		}
		for _, witnessID := range entry.WitnessRefs {
			if !routes.hasWitnessRoute(witnessID, requirementRefs, commandRefs, entry.SourcePath) {
				return fmt.Errorf("adoption materialization test inventory witness reference is not connected to its requirement route")
			}
		}
		for _, commandID := range entry.CommandRefs {
			if !routes.hasCommandRoute(commandID, requirementRefs, witnessRefs, entry.SourcePath) {
				return fmt.Errorf("adoption materialization test inventory command reference is not connected to its requirement route")
			}
		}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

type bindingRouteIndex struct {
	byCommand     map[string][]requirementbinding.Binding
	byRequirement map[string][]requirementbinding.Binding
	byWitness     map[string][]requirementbinding.Binding
}

func newBindingRouteIndex(bindings []requirementbinding.Binding) bindingRouteIndex {
	index := bindingRouteIndex{
		byCommand:     map[string][]requirementbinding.Binding{},
		byRequirement: map[string][]requirementbinding.Binding{},
		byWitness:     map[string][]requirementbinding.Binding{},
	}
	for _, binding := range bindings {
		index.byRequirement[binding.RequirementID] = append(index.byRequirement[binding.RequirementID], binding)
		index.byWitness[binding.WitnessID] = append(index.byWitness[binding.WitnessID], binding)
		for _, commandID := range binding.CommandIDs {
			index.byCommand[commandID] = append(index.byCommand[commandID], binding)
		}
	}
	return index
}

func (index bindingRouteIndex) hasRequirementRoute(requirementID string, witnessRefs, commandRefs map[string]struct{}, sourcePath string) bool {
	return bindingsContainRoute(index.byRequirement[requirementID], nil, witnessRefs, commandRefs, sourcePath)
}

func (index bindingRouteIndex) hasWitnessRoute(witnessID string, requirementRefs, commandRefs map[string]struct{}, sourcePath string) bool {
	return bindingsContainRoute(index.byWitness[witnessID], requirementRefs, stringSet([]string{witnessID}), commandRefs, sourcePath)
}

func (index bindingRouteIndex) hasCommandRoute(commandID string, requirementRefs, witnessRefs map[string]struct{}, sourcePath string) bool {
	return bindingsContainRoute(index.byCommand[commandID], requirementRefs, witnessRefs, nil, sourcePath)
}

func bindingsContainRoute(bindings []requirementbinding.Binding, requirementRefs, witnessRefs, commandRefs map[string]struct{}, sourcePath string) bool {
	for _, binding := range bindings {
		if len(requirementRefs) > 0 {
			if _, ok := requirementRefs[binding.RequirementID]; !ok {
				continue
			}
		}
		if len(witnessRefs) > 0 {
			if _, ok := witnessRefs[binding.WitnessID]; !ok {
				continue
			}
		}
		if len(commandRefs) > 0 && !bindingContainsCommand(binding, commandRefs) {
			continue
		}
		if len(witnessRefs) > 0 && sourcePath != "" && binding.WitnessPath != sourcePath {
			continue
		}
		return true
	}
	return false
}

func bindingContainsCommand(binding requirementbinding.Binding, commandRefs map[string]struct{}) bool {
	for _, commandID := range binding.CommandIDs {
		if _, ok := commandRefs[commandID]; ok {
			return true
		}
	}
	return false
}
