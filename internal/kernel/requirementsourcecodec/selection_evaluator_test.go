package requirementsourcecodec

import (
	"sort"
	"testing"
)

func selectJSONLayout(record codecSelection) string {
	maximumAccuracy := 0
	jsonIDs := stringSet(record.Roles.JSONLayouts)
	for _, observation := range record.ScreenObservations {
		if _, exists := jsonIDs[observation.CandidateID]; exists && observation.ReviewAccuracyBasisPoints != nil && *observation.ReviewAccuracyBasisPoints > maximumAccuracy {
			maximumAccuracy = *observation.ReviewAccuracyBasisPoints
		}
	}
	eligible := []screenObservation{}
	for _, observation := range record.ScreenObservations {
		_, isJSON := jsonIDs[observation.CandidateID]
		if isJSON && observation.FieldClosure == "passed" && observation.ReviewAccuracyBasisPoints != nil && *observation.ReviewAccuracyBasisPoints == maximumAccuracy && observation.InvalidMutationFalseAccepts != nil && *observation.InvalidMutationFalseAccepts == 0 && observation.EditLocality {
			eligible = append(eligible, observation)
		}
	}
	sort.Slice(eligible, func(left, right int) bool {
		leftKey := []int{eligible[left].WeightedTokensO200kBase, eligible[left].WeightedCanonicalBytes, eligible[left].ChangedBytes, eligible[left].ChangedLines}
		rightKey := []int{eligible[right].WeightedTokensO200kBase, eligible[right].WeightedCanonicalBytes, eligible[right].ChangedBytes, eligible[right].ChangedLines}
		for index := range leftKey {
			if leftKey[index] != rightKey[index] {
				return leftKey[index] < rightKey[index]
			}
		}
		return eligible[left].CandidateID < eligible[right].CandidateID
	})
	if len(eligible) == 0 {
		return ""
	}
	return eligible[0].CandidateID
}

func challengerEligible(record codecSelection) bool {
	selectedJSON := selectJSONLayout(record)
	if selectedJSON == "" || len(record.Roles.RestrictedTextChallengers) != 1 {
		return false
	}
	baseline, baselineExists := observationByID(record.ScreenObservations, selectedJSON)
	challenger, challengerExists := observationByID(record.ScreenObservations, record.Roles.RestrictedTextChallengers[0])
	if !baselineExists || !challengerExists {
		return false
	}
	policy := record.ReplacementPolicy
	return challenger.FieldClosure == "passed" &&
		challenger.ReviewAccuracyBasisPoints != nil && *challenger.ReviewAccuracyBasisPoints >= policy.MinimumReviewAccuracyBasisPoints &&
		challenger.InvalidMutationFalseAccepts != nil && *challenger.InvalidMutationFalseAccepts <= policy.MaximumInvalidMutationFalseAccepts &&
		challenger.EditLocality &&
		materiallyBetter(baseline.WeightedCanonicalBytes, challenger.WeightedCanonicalBytes, policy.MinimumByteImprovementBasisPoints) &&
		materiallyBetter(baseline.WeightedTokensO200kBase, challenger.WeightedTokensO200kBase, policy.MinimumTokenImprovementBasisPoints) &&
		challenger.AggregateDiffState == "passed" && challenger.PerEditDiffState == "passed" &&
		challenger.ParseTimeState == "passed" && challenger.FormatTimeState == "passed" &&
		challenger.LowerCostDominanceState == "passed" &&
		withinRatio(baseline.ProjectedProductionLOC, challenger.ProjectedProductionLOC, policy.MaximumProjectedProductionCostBasisPoints) &&
		withinRatio(baseline.ProjectedProductionBranches, challenger.ProjectedProductionBranches, policy.MaximumProjectedProductionCostBasisPoints)
}

func observationByID(observations []screenObservation, candidateID string) (screenObservation, bool) {
	for _, observation := range observations {
		if observation.CandidateID == candidateID {
			return observation, true
		}
	}
	return screenObservation{}, false
}

func materiallyBetter(baseline int, candidate int, minimumBasisPoints int) bool {
	if baseline <= 0 || candidate < 0 || candidate >= baseline || minimumBasisPoints < 0 {
		return false
	}
	return int64(baseline-candidate)*10000 >= int64(baseline)*int64(minimumBasisPoints)
}

func withinRatio(baseline int, candidate int, maximumBasisPoints int) bool {
	if baseline <= 0 || candidate < 0 || maximumBasisPoints < 0 {
		return false
	}
	return int64(candidate)*10000 <= int64(baseline)*int64(maximumBasisPoints)
}

func TestChallengerEligibilityRequiresEveryReplacementPredicate(t *testing.T) {
	eligible := eligibleChallengerRecord(t)
	if !challengerEligible(eligible) {
		t.Fatal("complete strict replacement was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*codecSelection)
	}{
		{name: "accepted grouped JSON", mutate: func(value *codecSelection) {
			mutateObservation(value, "json-hybrid-v1", func(item *screenObservation) { item.EditLocality = false })
		}},
		{name: "unique challenger", mutate: func(value *codecSelection) {
			value.Roles.RestrictedTextChallengers = append(value.Roles.RestrictedTextChallengers, "proofkit-source-text-v2")
		}},
		{name: "challenger observation", mutate: func(value *codecSelection) { value.Roles.RestrictedTextChallengers[0] = "proofkit-source-text-missing" }},
		{name: "field closure", mutate: challengerMutation(func(item *screenObservation) { item.FieldClosure = "failed" })},
		{name: "review present", mutate: challengerMutation(func(item *screenObservation) { item.ReviewAccuracyBasisPoints = nil })},
		{name: "review threshold", mutate: challengerMutation(func(item *screenObservation) { item.ReviewAccuracyBasisPoints = integerPointer(9999) })},
		{name: "invalid-mutation result", mutate: challengerMutation(func(item *screenObservation) { item.InvalidMutationFalseAccepts = nil })},
		{name: "invalid-mutation threshold", mutate: challengerMutation(func(item *screenObservation) { item.InvalidMutationFalseAccepts = integerPointer(1) })},
		{name: "edit locality", mutate: challengerMutation(func(item *screenObservation) { item.EditLocality = false })},
		{name: "material byte improvement", mutate: challengerMutation(func(item *screenObservation) { item.WeightedCanonicalBytes = 2605964 })},
		{name: "material token improvement", mutate: challengerMutation(func(item *screenObservation) { item.WeightedTokensO200kBase = 698724 })},
		{name: "aggregate diff", mutate: challengerMutation(func(item *screenObservation) { item.AggregateDiffState = "failed" })},
		{name: "per-edit diff", mutate: challengerMutation(func(item *screenObservation) { item.PerEditDiffState = "failed" })},
		{name: "parse time", mutate: challengerMutation(func(item *screenObservation) { item.ParseTimeState = "missing" })},
		{name: "format time", mutate: challengerMutation(func(item *screenObservation) { item.FormatTimeState = "missing" })},
		{name: "lower-cost dominance", mutate: challengerMutation(func(item *screenObservation) { item.LowerCostDominanceState = "failed" })},
		{name: "production LOC", mutate: challengerMutation(func(item *screenObservation) { item.ProjectedProductionLOC = 803 })},
		{name: "production branches", mutate: challengerMutation(func(item *screenObservation) { item.ProjectedProductionBranches = 70 })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := eligibleChallengerRecord(t)
			test.mutate(&record)
			if challengerEligible(record) {
				t.Fatal("incomplete replacement predicate was accepted")
			}
		})
	}
}

func eligibleChallengerRecord(t *testing.T) codecSelection {
	t.Helper()
	record := readCodecSelection(t)
	record.ScreenObservations = append([]screenObservation(nil), record.ScreenObservations...)
	record.Roles.RestrictedTextChallengers = append([]string(nil), record.Roles.RestrictedTextChallengers...)
	mutateObservation(&record, "proofkit-source-text-v1", func(item *screenObservation) {
		item.FieldClosure = "passed"
		item.ReviewAccuracyBasisPoints = integerPointer(10000)
		item.InvalidMutationFalseAccepts = integerPointer(0)
		item.EditLocality = true
		item.WeightedCanonicalBytes = 2_300_000
		item.WeightedTokensO200kBase = 620_000
		item.ProjectedProductionLOC = 600
		item.ProjectedProductionBranches = 60
		item.AggregateDiffState = "passed"
		item.PerEditDiffState = "passed"
		item.ParseTimeState = "passed"
		item.FormatTimeState = "passed"
		item.LowerCostDominanceState = "passed"
	})
	return record
}

func challengerMutation(mutate func(*screenObservation)) func(*codecSelection) {
	return func(value *codecSelection) {
		mutateObservation(value, "proofkit-source-text-v1", mutate)
	}
}

func mutateObservation(record *codecSelection, candidateID string, mutate func(*screenObservation)) {
	for index := range record.ScreenObservations {
		if record.ScreenObservations[index].CandidateID == candidateID {
			mutate(&record.ScreenObservations[index])
			return
		}
	}
}

func integerPointer(value int) *int {
	return &value
}
