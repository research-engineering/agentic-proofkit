package requirementauthoringplan

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

// The candidate is already child-admitted. This owner checks review coverage,
// not group inference, source reconstruction or lifecycle transition legality.
func compareCandidateSource(input input) ([]candidateUpdate, []string, []string) {
	updates := append([]candidateUpdate{}, input.CandidateUpdates...)
	if input.CandidateRequirementResult.ExitCode != 0 {
		return updates, []string{}, []string{}
	}
	before := requirementIndex(input.CurrentRequirementState)
	after := requirementIndex(input.CandidateRequirementResult.Source)
	changed := map[string]bool{}
	failures := []string{}
	for id, requirement := range after {
		previous, exists := before[id]
		if !exists || authoringRequirementChanged(previous, requirement) {
			changed[id] = true
		}
	}
	for id := range before {
		if _, exists := after[id]; !exists {
			failures = append(failures, fmt.Sprintf("candidate source must retain requirement id: %s", id))
		}
	}
	for index := range updates {
		update := &updates[index]
		next, exists := after[update.RequirementID]
		if !exists {
			failures = append(failures, fmt.Sprintf("candidate update must resolve in the candidate source: %s", update.RequirementID))
			continue
		}
		update.CandidateRequirement = requirementsourceadmission.RequirementValue(next)
		if !changed[update.RequirementID] {
			failures = append(failures, fmt.Sprintf("candidate update must identify a changed requirement: %s", update.RequirementID))
		}
		delete(changed, update.RequirementID)
		_, existed := before[update.RequirementID]
		expectedState := "active"
		if update.Operation == "deprecate" {
			expectedState = "deprecated"
		}
		if update.Operation == "supersede" {
			expectedState = "superseded"
		}
		if update.Operation == "add" && existed {
			failures = append(failures, fmt.Sprintf("add candidate must target a new requirement id: %s", update.RequirementID))
		} else if update.Operation != "add" && !existed {
			failures = append(failures, fmt.Sprintf("%s candidate must target an existing requirement id: %s", update.Operation, update.RequirementID))
		}
		if next.Lifecycle.State != expectedState {
			failures = append(failures, fmt.Sprintf("%s candidate must target %s lifecycle: %s", update.Operation, expectedState, update.RequirementID))
		}
	}
	for id := range changed {
		failures = append(failures, fmt.Sprintf("candidate changed requirement must have an explicit update row: %s", id))
	}
	planes := changedSourcePlanes(input.CurrentRequirementState, input.CandidateRequirementResult.Source)
	if len(updates) == 0 && len(changed) == 0 && len(planes) == 0 && len(failures) == 0 {
		failures = append(failures, "candidate source must contain an actual owner change")
	}
	sort.Strings(failures)
	return updates, planes, failures
}

func authoringRequirementChanged(previous, next requirementsourceadmission.Requirement) bool {
	if previous.Lifecycle.State != next.Lifecycle.State || previous.Lifecycle.State != "removed" && previous.Lifecycle.State != "superseded" {
		return !reflect.DeepEqual(previous, next)
	}
	before := requirementsourceadmission.RequirementValue(previous)
	after := requirementsourceadmission.RequirementValue(next)
	delete(before, "sourceReviewDigest")
	delete(after, "sourceReviewDigest")
	return !reflect.DeepEqual(before, after)
}

func requirementIndex(source requirementsourceadmission.Source) map[string]requirementsourceadmission.Requirement {
	index := make(map[string]requirementsourceadmission.Requirement, source.RequirementCount())
	for _, requirement := range source.Requirements() {
		index[requirement.RequirementID] = requirement
	}
	return index
}

func changedSourcePlanes(previous, next requirementsourceadmission.Source) []string {
	before, beforeOK := previous.Model()
	after, afterOK := next.Model()
	if !beforeOK || !afterOK {
		return []string{}
	}
	a, b := before.Atomic(), after.Atomic()
	r, s := before.References(), after.References()
	checks := []struct {
		name  string
		equal bool
	}{
		{"source_identity", a.SourceID == b.SourceID && a.SpecPackagePath == b.SpecPackagePath},
		{"source_nonclaims", reflect.DeepEqual(a.SourceNonClaims, b.SourceNonClaims) && reflect.DeepEqual(a.SourceNonClaimRefs, b.SourceNonClaimRefs)},
		{"nonclaim_definitions", reflect.DeepEqual(a.NonClaimDefinitions, b.NonClaimDefinitions)},
		{"vocabulary", reflect.DeepEqual(a.Vocabulary, b.Vocabulary)},
		{"scenarios", reflect.DeepEqual(a.Scenarios, b.Scenarios)},
		{"layout", reflect.DeepEqual(before.Layout(), after.Layout())},
		{"derivations", reflect.DeepEqual(r.Derivations, s.Derivations)},
		{"references", reflect.DeepEqual(r.Edges, s.Edges)},
	}
	planes := []string{}
	for _, check := range checks {
		if !check.equal {
			planes = append(planes, check.name)
		}
	}
	sort.Strings(planes)
	return planes
}
