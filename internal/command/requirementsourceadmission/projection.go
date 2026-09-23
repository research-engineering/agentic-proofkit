package requirementsourceadmission

import (
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
)

type ComparisonField struct {
	Class string
	Name  string
	Value any
}

func AdmitRequirementID(raw any, context string) (string, error) {
	return requirementID(raw, context)
}

func AdmitClaimLevel(raw any, context string) (string, error) {
	return enum(raw, claimLevelSet, claimLevels, context)
}

func AdmitLifecycleState(raw any, context string) (string, error) {
	return enum(raw, lifecycleStateSet, lifecycleStates, context)
}

func AdmitInvariantText(raw any, context string) (string, error) {
	return invariantText(raw, context)
}

func SourceValue(source Source) (map[string]any, error) {
	if !source.admitted {
		return nil, fmt.Errorf("requirement source has no admitted model")
	}
	return requirementsourcecodec.Value(source.model)
}

func SourceBytes(source Source) ([]byte, error) {
	if !source.admitted {
		return nil, fmt.Errorf("requirement source has no admitted model")
	}
	return requirementsourcecodec.Format(source.model)
}

func RequirementValue(requirement Requirement) map[string]any {
	record := map[string]any{
		"claimLevel":           requirement.ClaimLevel,
		"invariant":            requirement.Invariant,
		"lifecycle":            lifecycleValue(requirement.Lifecycle),
		"nonClaimRefs":         stringValues(requirement.NonClaimRefs),
		"externalNonClaimRefs": stringValues(requirement.ExternalNonClaimRefs),
		"sharedPremises":       stringValues(requirement.SharedPremises),
		"nonClaims":            stringValues(requirement.NonClaims),
		"ownerId":              requirement.OwnerID,
		"proofBindingRefs":     stringValues(requirement.ProofBindingRefs),
		"requirementId":        requirement.RequirementID,
		"riskClass":            requirement.RiskClass,
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  requirement.UpdatePolicy.RequiresImpactDeclaration,
			"requiresProofBindingReview": requirement.UpdatePolicy.RequiresProofBindingReview,
			"reviewOwnerId":              requirement.UpdatePolicy.ReviewOwnerID,
		},
	}
	if requirement.Deferral != nil {
		record["deferral"] = map[string]any{
			"evidenceRefs":    stringValues(requirement.Deferral.EvidenceRefs),
			"expiryRef":       requirement.Deferral.ExpiryRef,
			"mergePolicy":     requirement.Deferral.MergePolicy,
			"ownerId":         requirement.Deferral.OwnerID,
			"reviewCondition": requirement.Deferral.ReviewCondition,
			"riskAcceptedBy":  requirement.Deferral.RiskAcceptedBy,
		}
	}
	return record
}

// ComparisonFields is the requirement owner's exhaustive review projection.
// Adding a review-significant field requires changing this owner-local list.
func ComparisonFields(requirement Requirement) []ComparisonField {
	value := RequirementValue(requirement)
	return []ComparisonField{
		{Name: "claimLevel", Class: "scalar", Value: value["claimLevel"]},
		{Name: "deferral", Class: "map", Value: value["deferral"]},
		{Name: "externalNonClaimRefs", Class: "set", Value: value["externalNonClaimRefs"]},
		{Name: "invariant", Class: "scalar", Value: value["invariant"]},
		{Name: "lifecycle", Class: "map", Value: value["lifecycle"]},
		{Name: "nonClaimRefs", Class: "set", Value: value["nonClaimRefs"]},
		{Name: "nonClaims", Class: "set", Value: value["nonClaims"]},
		{Name: "ownerId", Class: "scalar", Value: value["ownerId"]},
		{Name: "proofBindingRefs", Class: "set", Value: value["proofBindingRefs"]},
		{Name: "riskClass", Class: "scalar", Value: value["riskClass"]},
		{Name: "sharedPremises", Class: "set", Value: value["sharedPremises"]},
		{Name: "updatePolicy", Class: "map", Value: value["updatePolicy"]},
	}
}

func lifecycleValue(lifecycle Lifecycle) map[string]any {
	return map[string]any{
		"evidenceRefs":              stringValues(lifecycle.EvidenceRefs),
		"replacementRequirementIds": stringValues(lifecycle.ReplacementRequirementIDs),
		"state":                     lifecycle.State,
	}
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
