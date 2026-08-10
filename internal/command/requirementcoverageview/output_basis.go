package requirementcoverageview

import (
	"fmt"
	"slices"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

var coverageBasisKeys = []string{
	"fullRepositoryOutOfScopeSourceRequirements", "ownerIds", "testInventoryDigest",
}

var sourceRequirementOwnerKeys = []string{"ownerId", "requirementId"}

type admittedCoverageBasis struct {
	ownerSet           map[string]struct{}
	ownerScopeFailures []string
}

func buildCoverageBasis(input compositeInput, entries []testevidenceinventory.Entry) (map[string]any, error) {
	ownerSet := mapSet(input.CoverageUniverse.OwnerIDs)
	outOfScope := []any{}
	if input.CoverageUniverse.CompletenessDeclaration == "full_repository" {
		requirements := slices.Clone(input.Source.Requirements)
		sort.Slice(requirements, func(left, right int) bool {
			return requirements[left].RequirementID < requirements[right].RequirementID
		})
		for _, requirement := range requirements {
			if inOwnerScope(requirement.OwnerID, ownerSet) {
				continue
			}
			outOfScope = append(outOfScope, map[string]any{
				"ownerId": requirement.OwnerID, "requirementId": requirement.RequirementID,
			})
		}
	}
	var inventoryDigest any
	if input.Inventory != nil {
		value, err := testInventoryProjectionDigest(entries)
		if err != nil {
			return nil, err
		}
		inventoryDigest = value
	}
	return map[string]any{
		"fullRepositoryOutOfScopeSourceRequirements": outOfScope,
		"ownerIds":            admit.StringSliceToAny(input.CoverageUniverse.OwnerIDs),
		"testInventoryDigest": inventoryDigest,
	}, nil
}

func admitCoverageBasis(raw any, inventoryMissing bool, completenessDeclaration string, entries []testevidenceinventory.Entry) (admittedCoverageBasis, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedCoverageBasis{}, fmt.Errorf("requirement coverage output coverageBasis must be an object")
	}
	if err := admit.KnownKeys(record, coverageBasisKeys, "requirement coverage output coverageBasis"); err != nil {
		return admittedCoverageBasis{}, err
	}
	for _, key := range coverageBasisKeys {
		if _, ok := record[key]; !ok {
			return admittedCoverageBasis{}, fmt.Errorf("requirement coverage output coverageBasis is missing required field %s", key)
		}
	}
	ownerIDs, err := admit.PreserveSortedTextArray(record["ownerIds"], "requirement coverage output coverageBasis ownerIds", false)
	if err != nil {
		return admittedCoverageBasis{}, err
	}
	for index, ownerID := range ownerIDs {
		if _, err := admit.RuleID(ownerID, fmt.Sprintf("requirement coverage output coverageBasis ownerIds[%d]", index)); err != nil {
			return admittedCoverageBasis{}, err
		}
	}
	ownerSet := mapSet(ownerIDs)
	outOfScope, err := admitOutOfScopeSourceRequirements(record["fullRepositoryOutOfScopeSourceRequirements"], ownerSet, completenessDeclaration)
	if err != nil {
		return admittedCoverageBasis{}, err
	}
	if inventoryMissing {
		if record["testInventoryDigest"] != nil {
			return admittedCoverageBasis{}, fmt.Errorf("requirement coverage output coverageBasis testInventoryDigest must be null without testInventoryId")
		}
	} else {
		actual, err := admit.SHA256Ref(record["testInventoryDigest"], "requirement coverage output coverageBasis testInventoryDigest")
		if err != nil {
			return admittedCoverageBasis{}, err
		}
		if err := requireCanonicalWireString(record["testInventoryDigest"], actual, "requirement coverage output coverageBasis testInventoryDigest"); err != nil {
			return admittedCoverageBasis{}, err
		}
		expected, err := testInventoryProjectionDigest(entries)
		if err != nil {
			return admittedCoverageBasis{}, err
		}
		if actual != expected {
			return admittedCoverageBasis{}, fmt.Errorf("requirement coverage output coverageBasis testInventoryDigest does not match retained test projections")
		}
	}
	failures := make([]string, 0, len(outOfScope)+len(entries))
	for _, requirement := range outOfScope {
		failures = append(failures, "full_repository_source_requirement_outside_owner_scope:"+requirement.requirementID)
	}
	for _, entry := range entries {
		if _, ok := ownerSet[entry.OwnerID]; !ok {
			failures = append(failures, "inventory_entry_owner_outside_scope:"+entry.TestID+":"+entry.OwnerID)
		}
	}
	return admittedCoverageBasis{ownerSet: ownerSet, ownerScopeFailures: sortedUnique(failures)}, nil
}

type sourceRequirementOwner struct {
	ownerID       string
	requirementID string
}

func admitOutOfScopeSourceRequirements(raw any, ownerSet map[string]struct{}, completenessDeclaration string) ([]sourceRequirementOwner, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement coverage output coverageBasis fullRepositoryOutOfScopeSourceRequirements must be an array")
	}
	if completenessDeclaration != "full_repository" && len(values) != 0 {
		return nil, fmt.Errorf("requirement coverage output coverageBasis must not retain full-repository omissions outside full_repository scope")
	}
	result := make([]sourceRequirementOwner, 0, len(values))
	previousID := ""
	for index, rawValue := range values {
		record, ok := rawValue.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement coverage output coverageBasis fullRepositoryOutOfScopeSourceRequirements[%d] must be an object", index)
		}
		context := fmt.Sprintf("requirement coverage output coverageBasis fullRepositoryOutOfScopeSourceRequirements[%d]", index)
		if err := admit.KnownKeys(record, sourceRequirementOwnerKeys, context); err != nil {
			return nil, err
		}
		for _, key := range sourceRequirementOwnerKeys {
			if _, ok := record[key]; !ok {
				return nil, fmt.Errorf("%s is missing required field %s", context, key)
			}
		}
		requirementID, err := admit.RuleID(record["requirementId"], context+" requirementId")
		if err != nil {
			return nil, err
		}
		if previousID != "" && previousID >= requirementID {
			return nil, fmt.Errorf("requirement coverage output coverageBasis fullRepositoryOutOfScopeSourceRequirements must be sorted and unique by requirementId")
		}
		previousID = requirementID
		ownerID, err := admit.RuleID(record["ownerId"], context+" ownerId")
		if err != nil {
			return nil, err
		}
		if _, inScope := ownerSet[ownerID]; inScope {
			return nil, fmt.Errorf("%s ownerId must be outside coverageBasis ownerIds", context)
		}
		result = append(result, sourceRequirementOwner{ownerID: ownerID, requirementID: requirementID})
	}
	return result, nil
}

func testInventoryProjectionDigest(entries []testevidenceinventory.Entry) (string, error) {
	ordered := slices.Clone(entries)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].TestID < ordered[right].TestID })
	return digest.StableJSONSHA256Ref(testEntriesToAny(ordered))
}
