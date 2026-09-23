package requirementsourcemodel

import "sort"

// Assessment separates a structurally admitted source from a usable model.
// Its zero value and policy-failed results never expose a model.
type Assessment struct {
	model      Model
	summary    AssessmentSummary
	violations []PolicyViolation
	admitted   bool
}

type AssessmentSummary struct {
	SourceID                 string
	SpecPackagePath          string
	NonClaims                []string
	RequirementCount         int
	ActiveRequirementCount   int
	BlockingRequirementCount int
	DeferredRequirementCount int
}

type PolicyViolation struct {
	Code                 string
	Path                 string
	RequirementID        string
	RelatedRequirementID string
}

// Assess borrows draft until return, like Normalize. Structural errors return
// no assessment; policy failures return only admitted report operands.
func Assess(draft Draft) (Assessment, error) {
	return AssessWithLimits(draft, DefaultLimits())
}

func AssessWithLimits(draft Draft, limits Limits) (Assessment, error) {
	return normalizeSource(draft, limits, true)
}

func (assessment Assessment) Model() (Model, bool) {
	if !assessment.admitted || len(assessment.violations) != 0 {
		return Model{}, false
	}
	return assessment.model, true
}

func (assessment Assessment) Summary() (AssessmentSummary, bool) {
	if !assessment.admitted {
		return AssessmentSummary{}, false
	}
	result := assessment.summary
	result.NonClaims = cloneStrings(result.NonClaims)
	return result, true
}

func (assessment Assessment) Violations() []PolicyViolation {
	return append([]PolicyViolation{}, assessment.violations...)
}

func sourceAssessment(model Model, violations []PolicyViolation) Assessment {
	atomic := model.atomic
	summary := AssessmentSummary{
		SourceID: atomic.SourceID, SpecPackagePath: atomic.SpecPackagePath,
		NonClaims: model.ResolvedSourceNonClaims(), RequirementCount: len(atomic.Requirements),
	}
	for _, requirement := range atomic.Requirements {
		if requirement.Lifecycle.State == LifecycleActive {
			summary.ActiveRequirementCount++
		}
		if requirement.ClaimLevel == ClaimBlocking {
			summary.BlockingRequirementCount++
		}
		if requirement.ClaimLevel == ClaimDeferred {
			summary.DeferredRequirementCount++
		}
	}
	result := Assessment{summary: summary, violations: violations, admitted: true}
	if len(violations) == 0 {
		result.model = model
	}
	return result
}

// ResolvedSourceNonClaims is a detached report projection. Atomic preserves
// the distinct direct declarations, reference IDs and definition owners.
func (model Model) ResolvedSourceNonClaims() []string {
	atomic := model.atomic
	result := cloneStrings(atomic.SourceNonClaims)
	definitions := make(map[string]string, len(atomic.NonClaimDefinitions))
	for _, definition := range atomic.NonClaimDefinitions {
		definitions[definition.NonClaimID] = definition.Statement
	}
	for _, ref := range atomic.SourceNonClaimRefs {
		result = append(result, definitions[ref])
	}
	sort.Strings(result)
	return result
}
