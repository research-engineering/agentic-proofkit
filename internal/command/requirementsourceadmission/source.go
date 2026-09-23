package requirementsourceadmission

import "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"

func OverviewPath(specPackagePath string) string { return specPackagePath + "/overview.md" }

func RequirementsPath(specPackagePath string) string {
	return specPackagePath + "/requirements.v2.json"
}

func (source Source) SourceID() string { return source.model.SourceID() }

func (source Source) SpecPackagePath() string { return source.model.SpecPackagePath() }

func (source Source) OverviewPath() string {
	if !source.admitted {
		return ""
	}
	return OverviewPath(source.SpecPackagePath())
}

func (source Source) RequirementsPath() string {
	if !source.admitted {
		return ""
	}
	return RequirementsPath(source.SpecPackagePath())
}

func (source Source) RequirementCount() int { return source.model.RequirementCount() }

func (source Source) NonClaims() []string { return source.model.ResolvedSourceNonClaims() }

func (source Source) Model() (requirementsourcemodel.Model, bool) {
	return source.model, source.admitted
}

// Requirements returns a detached review projection, not an editable Source.
func (source Source) Requirements() []Requirement {
	values := source.model.Requirements()
	result := make([]Requirement, len(values))
	for index, value := range values {
		var deferral *Deferral
		if v := value.Deferral; v != nil {
			deferral = &Deferral{EvidenceRefs: v.EvidenceRefs, ExpiryRef: v.ExpiryRef, MergePolicy: v.MergePolicy,
				OwnerID: v.OwnerID, ReviewCondition: v.ReviewCondition, RiskAcceptedBy: v.RiskAcceptedBy}
		}
		result[index] = Requirement{
			ClaimLevel: string(value.ClaimLevel), Deferral: deferral, Invariant: value.Invariant,
			Lifecycle:    Lifecycle{EvidenceRefs: value.Lifecycle.EvidenceRefs, ReplacementRequirementIDs: value.Lifecycle.ReplacementRequirementIDs, State: string(value.Lifecycle.State)},
			NonClaimRefs: value.NonClaimRefs, NonClaims: value.NonClaims, ExternalNonClaimRefs: value.ExternalNonClaimRefs,
			SharedPremises: value.SharedPremises, OwnerID: value.OwnerID, ProofBindingRefs: value.ProofBindingRefs,
			RequirementID: value.RequirementID, RiskClass: string(value.RiskClass),
			UpdatePolicy: UpdatePolicy{RequiresImpactDeclaration: value.UpdatePolicy.RequiresImpactDeclaration,
				RequiresProofBindingReview: value.UpdatePolicy.RequiresProofBindingReview, ReviewOwnerID: value.UpdatePolicy.ReviewOwnerID},
		}
	}
	return result
}
