package requirementsourcecodec

import (
	"reflect"
	"sort"
	"testing"
)

var selectionMetricSemantics = []selectionMetric{
	{MetricID: "aggregate_diff_regression_basis_points", Stage: "replacement", Role: "hard", Direction: "minimize", Baseline: "selected-json-layout", Aggregation: "maximum-aggregate-diff-regression", Requirement: "at-most-policy-threshold", Missing: "reject", MaterialThreshold: 500},
	{MetricID: "changed_bytes", Stage: "screen", Role: "primary", Direction: "minimize", Baseline: "eligible-json-layouts", Aggregation: "sum-over-frozen-edits", Requirement: "lexicographic-minimum", Missing: "reject", MaterialThreshold: 0},
	{MetricID: "changed_lines", Stage: "screen", Role: "primary", Direction: "minimize", Baseline: "eligible-json-layouts", Aggregation: "sum-over-frozen-edits", Requirement: "lexicographic-minimum", Missing: "reject", MaterialThreshold: 0},
	{MetricID: "edit_locality", Stage: "screen", Role: "hard", Direction: "equal", Baseline: "affected-entity-registry", Aggregation: "all-frozen-edits", Requirement: "true", Missing: "fail", MaterialThreshold: 0},
	{MetricID: "field_closure", Stage: "screen", Role: "hard", Direction: "equal", Baseline: "codec-field-manifest-v1", Aggregation: "all-fields", Requirement: "passed", Missing: "fail", MaterialThreshold: 0},
	{MetricID: "format_time_state", Stage: "replacement", Role: "hard", Direction: "equal", Baseline: "selected-grouped-json-v1", Aggregation: "paired-randomized-confidence-bound", Requirement: "passed", Missing: "reject", MaterialThreshold: 0},
	{MetricID: "invalid_mutation_false_accepts", Stage: "screen", Role: "hard", Direction: "minimize", Baseline: "frozen-invalid-review-task", Aggregation: "sum", Requirement: "zero", Missing: "fail", MaterialThreshold: 0},
	{MetricID: "lower_cost_dominance_state", Stage: "replacement", Role: "hard", Direction: "equal", Baseline: "eligible-lower-cost-comparators", Aggregation: "all-primary-metrics", Requirement: "passed", Missing: "reject", MaterialThreshold: 0},
	{MetricID: "parse_time_state", Stage: "replacement", Role: "hard", Direction: "equal", Baseline: "selected-grouped-json-v1", Aggregation: "paired-randomized-confidence-bound", Requirement: "passed", Missing: "reject", MaterialThreshold: 0},
	{MetricID: "per_edit_diff_regression_basis_points", Stage: "replacement", Role: "hard", Direction: "minimize", Baseline: "selected-json-layout", Aggregation: "maximum-per-edit-class-diff-regression", Requirement: "at-most-policy-threshold", Missing: "reject", MaterialThreshold: 1500},
	{MetricID: "projected_production_branches", Stage: "replacement", Role: "hard", Direction: "minimize", Baseline: "selected-json-layout", Aggregation: "estimate", Requirement: "at-most-policy-ratio", Missing: "reject", MaterialThreshold: 15000},
	{MetricID: "projected_production_loc", Stage: "replacement", Role: "hard", Direction: "minimize", Baseline: "selected-json-layout", Aggregation: "estimate", Requirement: "at-most-policy-ratio", Missing: "reject", MaterialThreshold: 15000},
	{MetricID: "review_accuracy_basis_points", Stage: "screen", Role: "hard", Direction: "maximize", Baseline: "maximum-observed-json-layout", Aggregation: "exact-gold-answers", Requirement: "equal-to-maximum", Missing: "fail", MaterialThreshold: 0},
	{MetricID: "weighted_canonical_bytes", Stage: "screen", Role: "primary", Direction: "minimize", Baseline: "eligible-json-layouts", Aggregation: "weighted-sum", Requirement: "lexicographic-minimum", Missing: "reject", MaterialThreshold: 0},
	{MetricID: "weighted_tokens_o200k_base", Stage: "screen", Role: "primary", Direction: "minimize", Baseline: "eligible-json-layouts", Aggregation: "weighted-sum", Requirement: "lexicographic-minimum", Missing: "reject", MaterialThreshold: 0},
}

func admittedSelectionMetricRegistry(metrics []selectionMetric) (map[string]selectionMetric, bool) {
	if !reflect.DeepEqual(metrics, selectionMetricSemantics) {
		return nil, false
	}
	result := make(map[string]selectionMetric, len(metrics))
	for _, metric := range metrics {
		result[metric.MetricID] = metric
	}
	return result, true
}

func selectJSONLayout(record codecSelection) string {
	eligibility, eligibilityOK := jsonLayoutEligibility(record)
	if !eligibilityOK {
		return ""
	}
	eligibleRows := []screenObservation{}
	for _, observation := range record.ScreenObservations {
		if eligibility[observation.CandidateID] {
			eligibleRows = append(eligibleRows, observation)
		}
	}
	sort.Slice(eligibleRows, func(left, right int) bool {
		for _, metricID := range record.JSONLayoutOrder {
			if metricID == "candidate_id" {
				return eligibleRows[left].CandidateID < eligibleRows[right].CandidateID
			}
			leftValue := layoutMetricValue(eligibleRows[left], metricID)
			rightValue := layoutMetricValue(eligibleRows[right], metricID)
			if leftValue != rightValue {
				return leftValue < rightValue
			}
		}
		return false
	})
	if len(eligibleRows) == 0 {
		return ""
	}
	return eligibleRows[0].CandidateID
}

func jsonLayoutEligibility(record codecSelection) (map[string]bool, bool) {
	metrics, ok := admittedSelectionMetricRegistry(record.MetricRegistry)
	if !ok || !jsonLayoutOrderIsAdmitted(record.JSONLayoutOrder, metrics) {
		return nil, false
	}
	maximumAccuracy := 0
	jsonIDs := stringSet(record.Roles.JSONLayouts)
	for _, observation := range record.ScreenObservations {
		if _, exists := jsonIDs[observation.CandidateID]; exists && observation.ReviewAccuracyBasisPoints != nil && *observation.ReviewAccuracyBasisPoints > maximumAccuracy {
			maximumAccuracy = *observation.ReviewAccuracyBasisPoints
		}
	}
	result := make(map[string]bool, len(record.Roles.JSONLayouts))
	for _, candidateID := range record.Roles.JSONLayouts {
		observation, exists := observationByID(record.ScreenObservations, candidateID)
		if !exists {
			return nil, false
		}
		result[candidateID] = jsonLayoutPassesHardMetrics(observation, maximumAccuracy, metrics)
	}
	return result, true
}

func challengerEligible(record codecSelection) bool {
	metrics, ok := admittedSelectionMetricRegistry(record.MetricRegistry)
	if !ok {
		return false
	}
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
	return challengerPassesScreenMetrics(challenger, policy, metrics) &&
		materiallyBetter(baseline.WeightedCanonicalBytes, challenger.WeightedCanonicalBytes, policy.MinimumByteImprovementBasisPoints) &&
		materiallyBetter(baseline.WeightedTokensO200kBase, challenger.WeightedTokensO200kBase, policy.MinimumTokenImprovementBasisPoints) &&
		challengerPassesReplacementMetrics(baseline, challenger, policy, metrics)
}

func jsonLayoutOrderIsAdmitted(order []string, metrics map[string]selectionMetric) bool {
	for _, metricID := range order {
		if metricID == "candidate_id" {
			continue
		}
		metric, exists := metrics[metricID]
		if !exists || metric.Stage != "screen" || metric.Role != "primary" || metric.Direction != "minimize" || metric.Requirement != "lexicographic-minimum" {
			return false
		}
	}
	return reflect.DeepEqual(order, []string{"weighted_tokens_o200k_base", "weighted_canonical_bytes", "changed_bytes", "changed_lines", "candidate_id"})
}

func jsonLayoutPassesHardMetrics(observation screenObservation, maximumAccuracy int, metrics map[string]selectionMetric) bool {
	for _, metric := range metrics {
		if metric.Stage != "screen" || metric.Role != "hard" {
			continue
		}
		switch metric.MetricID {
		case "field_closure":
			if observation.FieldClosure != metric.Requirement {
				return false
			}
		case "review_accuracy_basis_points":
			if observation.ReviewAccuracyBasisPoints == nil || *observation.ReviewAccuracyBasisPoints != maximumAccuracy {
				return false
			}
		case "invalid_mutation_false_accepts":
			if observation.InvalidMutationFalseAccepts == nil || *observation.InvalidMutationFalseAccepts != metric.MaterialThreshold {
				return false
			}
		case "edit_locality":
			if !observation.EditLocality {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func challengerPassesScreenMetrics(observation screenObservation, policy replacementPolicy, metrics map[string]selectionMetric) bool {
	for _, metric := range metrics {
		if metric.Stage != "screen" || metric.Role != "hard" {
			continue
		}
		switch metric.MetricID {
		case "field_closure":
			if observation.FieldClosure != metric.Requirement {
				return false
			}
		case "review_accuracy_basis_points":
			if observation.ReviewAccuracyBasisPoints == nil || *observation.ReviewAccuracyBasisPoints < policy.MinimumReviewAccuracyBasisPoints {
				return false
			}
		case "invalid_mutation_false_accepts":
			if observation.InvalidMutationFalseAccepts == nil || *observation.InvalidMutationFalseAccepts > policy.MaximumInvalidMutationFalseAccepts {
				return false
			}
		case "edit_locality":
			if !observation.EditLocality {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func challengerPassesReplacementMetrics(baseline screenObservation, challenger screenObservation, policy replacementPolicy, metrics map[string]selectionMetric) bool {
	for _, metric := range metrics {
		if metric.Stage != "replacement" || metric.Role != "hard" {
			continue
		}
		passed := false
		switch metric.MetricID {
		case "aggregate_diff_regression_basis_points":
			passed = challenger.AggregateDiffRegressionBasisPoints != nil && *challenger.AggregateDiffRegressionBasisPoints <= policy.MaximumAggregateDiffRegressionBasisPoints
		case "per_edit_diff_regression_basis_points":
			passed = challenger.PerEditDiffRegressionBasisPoints != nil && *challenger.PerEditDiffRegressionBasisPoints <= policy.MaximumPerEditDiffRegressionBasisPoints
		case "parse_time_state":
			passed = challenger.ParseTimeState == metric.Requirement
		case "format_time_state":
			passed = challenger.FormatTimeState == metric.Requirement
		case "lower_cost_dominance_state":
			passed = challenger.LowerCostDominanceState == metric.Requirement
		case "projected_production_loc":
			passed = withinRatio(baseline.ProjectedProductionLOC, challenger.ProjectedProductionLOC, policy.MaximumProjectedProductionCostBasisPoints)
		case "projected_production_branches":
			passed = withinRatio(baseline.ProjectedProductionBranches, challenger.ProjectedProductionBranches, policy.MaximumProjectedProductionCostBasisPoints)
		default:
			return false
		}
		if !passed {
			return false
		}
	}
	return true
}

func layoutMetricValue(value screenObservation, metricID string) int {
	switch metricID {
	case "weighted_tokens_o200k_base":
		return value.WeightedTokensO200kBase
	case "weighted_canonical_bytes":
		return value.WeightedCanonicalBytes
	case "changed_bytes":
		return value.ChangedBytes
	case "changed_lines":
		return value.ChangedLines
	default:
		panic("unknown JSON layout metric")
	}
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
		{name: "aggregate diff present", mutate: challengerMutation(func(item *screenObservation) { item.AggregateDiffRegressionBasisPoints = nil })},
		{name: "aggregate diff threshold", mutate: challengerMutation(func(item *screenObservation) { item.AggregateDiffRegressionBasisPoints = integerPointer(501) })},
		{name: "per-edit diff present", mutate: challengerMutation(func(item *screenObservation) { item.PerEditDiffRegressionBasisPoints = nil })},
		{name: "per-edit diff threshold", mutate: challengerMutation(func(item *screenObservation) { item.PerEditDiffRegressionBasisPoints = integerPointer(1501) })},
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

func TestSelectionMetricRegistrySemanticsDriveEvaluator(t *testing.T) {
	record := readCodecSelection(t)
	if selectJSONLayout(record) == "" {
		t.Fatal("admitted metric registry did not produce a JSON selection")
	}

	roleDrift := record
	roleDrift.MetricRegistry = append([]selectionMetric(nil), record.MetricRegistry...)
	for index := range roleDrift.MetricRegistry {
		if roleDrift.MetricRegistry[index].MetricID == "review_accuracy_basis_points" {
			roleDrift.MetricRegistry[index].Role = "report-only"
		}
	}
	if selectJSONLayout(roleDrift) != "" || challengerEligible(roleDrift) {
		t.Fatal("evaluator accepted a registry that downgraded a hard metric")
	}

	missingMetric := record
	missingMetric.MetricRegistry = append([]selectionMetric(nil), record.MetricRegistry[:len(record.MetricRegistry)-1]...)
	if selectJSONLayout(missingMetric) != "" || challengerEligible(missingMetric) {
		t.Fatal("evaluator accepted an incomplete metric registry")
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
		item.AggregateDiffRegressionBasisPoints = integerPointer(0)
		item.PerEditDiffRegressionBasisPoints = integerPointer(0)
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
