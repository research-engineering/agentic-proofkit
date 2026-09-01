package requirementsourcecodec

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type screenDecisionEvidence struct {
	SchemaVersion        int                        `json:"schemaVersion"`
	Kind                 string                     `json:"kind"`
	ManifestSHA256       string                     `json:"manifestSha256"`
	ObservationSHA256    string                     `json:"observationSha256"`
	OpeningSHA256        string                     `json:"openingSha256"`
	ReviewResultsSHA256  string                     `json:"reviewResultsSha256"`
	TokenReportSHA256    map[string]string          `json:"tokenReportSha256"`
	ValidationSHA256     string                     `json:"validationSha256"`
	State                string                     `json:"state"`
	SelectedJSONLayout   string                     `json:"selectedJsonLayout"`
	SelectedChallenger   *string                    `json:"selectedChallenger"`
	Candidates           []screenDecisionCandidate  `json:"candidates"`
	JSONEligibility      map[string]bool            `json:"jsonEligibility"`
	ChallengerPredicates screenChallengerPredicates `json:"challengerPredicates"`
	StageECandidates     []string                   `json:"stageECandidates"`
}

type screenDecisionCandidate struct {
	CandidateID             string                  `json:"candidateId"`
	WeightedCanonicalBytes  int                     `json:"weightedCanonicalBytes"`
	WeightedTokensO200kBase int                     `json:"weightedTokensO200kBase"`
	ChangedLines            int                     `json:"changedLines"`
	ChangedBytes            int                     `json:"changedBytes"`
	EditLocality            bool                    `json:"editLocality"`
	EditRows                []screenDecisionEditRow `json:"editRows"`
	JSONFieldClosure        string                  `json:"jsonFieldClosure"`
	Review                  *screenDecisionReview   `json:"review"`
	ProjectedProduction     projectedProduction     `json:"projectedProduction"`
}

type screenDecisionEditRow struct {
	EditID             string   `json:"editId"`
	ChangedLines       int      `json:"changedLines"`
	ChangedBytes       int      `json:"changedBytes"`
	LocalityViolations []string `json:"localityViolations"`
}

type screenDecisionReview struct {
	Correct                     int    `json:"correct"`
	Total                       int    `json:"total"`
	AccuracyBasisPoints         int    `json:"accuracyBasisPoints"`
	InvalidMutationFalseAccepts int    `json:"invalidMutationFalseAccepts"`
	SlotID                      string `json:"slotId"`
	AgentID                     string `json:"agentId"`
}

type projectedProduction struct {
	LOC      int    `json:"loc"`
	Branches int    `json:"branches"`
	Basis    string `json:"basis"`
}

type screenChallengerPredicates struct {
	GroupedJSONAccepted                   bool `json:"groupedJsonAccepted"`
	ReviewPresent                         bool `json:"reviewPresent"`
	ReviewAccuracy                        bool `json:"reviewAccuracy"`
	InvalidMutationFalseAccepts           bool `json:"invalidMutationFalseAccepts"`
	EditLocality                          bool `json:"editLocality"`
	ByteImprovement                       bool `json:"byteImprovement"`
	TokenImprovement                      bool `json:"tokenImprovement"`
	AggregateDiffNoninferior              bool `json:"aggregateDiffNoninferior"`
	PerEditDiffNoninferior                bool `json:"perEditDiffNoninferior"`
	ProjectedProductionCost               bool `json:"projectedProductionCost"`
	LowerCostComparisonComplete           bool `json:"lowerCostComparisonComplete"`
	StrictlyDominatesLowerCostComparators bool `json:"strictlyDominatesLowerCostComparators"`
}

func TestDecisionProjectionRejectsReplacementObservationDrift(t *testing.T) {
	record := readCodecSelection(t)
	root := readScreenArchive(t, record.ScreenEvidence)
	artifacts := verifyScreenArtifacts(t, root, record.ScreenEvidence.Artifacts)
	decision := readStrictEvidence[screenDecisionEvidence](t, root, artifacts["screen-decision"].Path)
	if err := verifyDecisionProjection(record, decision); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		wantError string
		mutate    func(*codecSelection, *screenDecisionEvidence)
	}{
		{name: "aggregate diff", mutate: func(value *codecSelection, _ *screenDecisionEvidence) {
			mutateObservation(value, "proofkit-source-text-v1", func(item *screenObservation) { item.AggregateDiffRegressionBasisPoints = integerPointer(0) })
		}},
		{name: "per-edit diff", mutate: func(value *codecSelection, _ *screenDecisionEvidence) {
			mutateObservation(value, "proofkit-source-text-v1", func(item *screenObservation) { item.PerEditDiffRegressionBasisPoints = integerPointer(0) })
		}},
		{name: "missing parse measurement", mutate: func(value *codecSelection, _ *screenDecisionEvidence) {
			mutateObservation(value, "proofkit-source-text-v1", func(item *screenObservation) { item.ParseTimeState = "passed" })
		}},
		{name: "JSON eligibility", mutate: func(_ *codecSelection, value *screenDecisionEvidence) {
			value.JSONEligibility = cloneBoolMap(value.JSONEligibility)
			value.JSONEligibility["json-compact-v1"] = true
		}},
		{name: "challenger predicate", mutate: func(_ *codecSelection, value *screenDecisionEvidence) {
			value.ChallengerPredicates.AggregateDiffNoninferior = true
		}},
		{name: "aggregate line regression", wantError: "screen challenger predicates", mutate: func(value *codecSelection, decision *screenDecisionEvidence) {
			mutateObservation(value, "proofkit-source-text-v1", func(item *screenObservation) {
				item.ChangedLines = 36
				item.ChangedBytes = 5721
				item.EditLocality = true
				item.AggregateDiffRegressionBasisPoints = integerPointer(588)
				item.PerEditDiffRegressionBasisPoints = integerPointer(833)
			})
			baseline := decisionCandidate(decision, "json-hybrid-v1")
			challenger := decisionCandidate(decision, "proofkit-source-text-v1")
			challenger.EditRows = cloneDecisionEditRows(baseline.EditRows)
			challenger.ChangedLines = 36
			challenger.ChangedBytes = 5721
			challenger.EditLocality = true
			for index := range challenger.EditRows {
				if challenger.EditRows[index].EditID == "merge" || challenger.EditRows[index].EditID == "split" {
					challenger.EditRows[index].ChangedLines++
				}
			}
			decision.ChallengerPredicates.AggregateDiffNoninferior = true
			decision.ChallengerPredicates.EditLocality = true
			decision.ChallengerPredicates.PerEditDiffNoninferior = true
		}},
		{name: "per-edit line regression", wantError: "screen challenger predicates", mutate: func(value *codecSelection, decision *screenDecisionEvidence) {
			mutateObservation(value, "proofkit-source-text-v1", func(item *screenObservation) {
				item.ChangedLines = 35
				item.ChangedBytes = 5721
				item.EditLocality = true
				item.AggregateDiffRegressionBasisPoints = integerPointer(294)
				item.PerEditDiffRegressionBasisPoints = integerPointer(10000)
			})
			baseline := decisionCandidate(decision, "json-hybrid-v1")
			challenger := decisionCandidate(decision, "proofkit-source-text-v1")
			challenger.EditRows = cloneDecisionEditRows(baseline.EditRows)
			challenger.ChangedLines = 35
			challenger.ChangedBytes = 5721
			challenger.EditLocality = true
			for index := range challenger.EditRows {
				if challenger.EditRows[index].EditID == "add" {
					challenger.EditRows[index].ChangedLines++
				}
			}
			decision.ChallengerPredicates.AggregateDiffNoninferior = true
			decision.ChallengerPredicates.EditLocality = true
			decision.ChallengerPredicates.PerEditDiffNoninferior = true
		}},
		{name: "production branch regression", wantError: "screen challenger predicates", mutate: func(value *codecSelection, decision *screenDecisionEvidence) {
			mutateObservation(value, "proofkit-source-text-v1", func(item *screenObservation) {
				item.ProjectedProductionLOC = 535
				item.ProjectedProductionBranches = 70
			})
			challenger := decisionCandidate(decision, "proofkit-source-text-v1")
			challenger.ProjectedProduction.LOC = 535
			challenger.ProjectedProduction.Branches = 70
			decision.ChallengerPredicates.ProjectedProductionCost = true
		}},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			mutatedRecord := readCodecSelection(t)
			mutatedRecord.ScreenObservations = append([]screenObservation(nil), mutatedRecord.ScreenObservations...)
			mutatedDecision := cloneScreenDecisionEvidence(decision)
			item.mutate(&mutatedRecord, &mutatedDecision)
			err := verifyDecisionProjection(mutatedRecord, mutatedDecision)
			if err == nil {
				t.Fatal("decision projection admitted a causal evidence mutation")
			}
			if item.wantError != "" && !strings.Contains(err.Error(), item.wantError) {
				t.Fatalf("decision projection error = %q, want %q", err, item.wantError)
			}
		})
	}
}

func verifyDecisionProjection(record codecSelection, decision screenDecisionEvidence) error {
	if decision.State != record.Decision.State || decision.SelectedJSONLayout != record.Decision.SelectedJSONLayout || !reflect.DeepEqual(decision.SelectedChallenger, record.Decision.SelectedChallenger) {
		return fmt.Errorf("screen decision projection mismatch: %#v", decision)
	}
	eligibility, ok := jsonLayoutEligibility(record)
	if !ok || !reflect.DeepEqual(decision.JSONEligibility, eligibility) {
		return fmt.Errorf("screen JSON eligibility = %v, want %v", decision.JSONEligibility, eligibility)
	}
	wantStageE := []string{record.Decision.SelectedCodec}
	if record.Decision.SelectedChallenger != nil {
		wantStageE = append(wantStageE, *record.Decision.SelectedChallenger)
	}
	if !reflect.DeepEqual(decision.StageECandidates, wantStageE) {
		return fmt.Errorf("screen stage-E candidates = %v, want %v", decision.StageECandidates, wantStageE)
	}
	byID := make(map[string]screenObservation, len(record.ScreenObservations))
	for _, item := range record.ScreenObservations {
		if _, duplicate := byID[item.CandidateID]; duplicate {
			return fmt.Errorf("selection repeats candidate %q", item.CandidateID)
		}
		byID[item.CandidateID] = item
	}
	decisionByID := make(map[string]screenDecisionCandidate, len(decision.Candidates))
	previousCandidateID := ""
	for _, candidate := range decision.Candidates {
		if candidate.CandidateID == "" || candidate.CandidateID <= previousCandidateID {
			return errors.New("screen decision candidates are not sorted unique")
		}
		if _, duplicate := decisionByID[candidate.CandidateID]; duplicate {
			return fmt.Errorf("decision repeats candidate %q", candidate.CandidateID)
		}
		decisionByID[candidate.CandidateID] = candidate
		previousCandidateID = candidate.CandidateID
		observation, exists := byID[candidate.CandidateID]
		if !exists {
			return fmt.Errorf("decision contains unknown candidate %q", candidate.CandidateID)
		}
		if observation.WeightedCanonicalBytes != candidate.WeightedCanonicalBytes || observation.WeightedTokensO200kBase != candidate.WeightedTokensO200kBase ||
			observation.ChangedLines != candidate.ChangedLines || observation.ChangedBytes != candidate.ChangedBytes || observation.EditLocality != candidate.EditLocality ||
			observation.ProjectedProductionLOC != candidate.ProjectedProduction.LOC || observation.ProjectedProductionBranches != candidate.ProjectedProduction.Branches {
			return fmt.Errorf("candidate %q observation drift", candidate.CandidateID)
		}
		if observation.FieldClosure != candidate.JSONFieldClosure {
			return fmt.Errorf("candidate %q field closure drift", candidate.CandidateID)
		}
		if candidate.Review != nil && (observation.ReviewAccuracyBasisPoints == nil || observation.InvalidMutationFalseAccepts == nil ||
			*observation.ReviewAccuracyBasisPoints != candidate.Review.AccuracyBasisPoints || *observation.InvalidMutationFalseAccepts != candidate.Review.InvalidMutationFalseAccepts) {
			return fmt.Errorf("candidate %q review projection drift", candidate.CandidateID)
		}
		if candidate.Review != nil && (candidate.Review.Total <= 0 || candidate.Review.Correct < 0 || candidate.Review.Correct > candidate.Review.Total ||
			candidate.Review.AccuracyBasisPoints != candidate.Review.Correct*10000/candidate.Review.Total || candidate.Review.InvalidMutationFalseAccepts < 0 ||
			candidate.Review.SlotID == "" || candidate.Review.AgentID == "") {
			return fmt.Errorf("candidate %q has internally inconsistent review evidence", candidate.CandidateID)
		}
		if candidate.Review == nil && (observation.ReviewAccuracyBasisPoints != nil || observation.InvalidMutationFalseAccepts != nil) {
			return fmt.Errorf("candidate %q unexpected review projection", candidate.CandidateID)
		}
		if candidate.ProjectedProduction.Basis == "" {
			return fmt.Errorf("candidate %q lacks projected-production basis", candidate.CandidateID)
		}
		if err := verifyDecisionEditRows(candidate); err != nil {
			return err
		}
	}
	if len(decision.Candidates) != len(record.ScreenObservations) {
		return fmt.Errorf("decision candidate count = %d, want %d", len(decision.Candidates), len(record.ScreenObservations))
	}
	wantPredicates, err := frozenScreenChallengerPredicates(record, decisionByID)
	if err != nil {
		return err
	}
	if decision.ChallengerPredicates != wantPredicates {
		return fmt.Errorf("screen challenger predicates = %#v, want %#v", decision.ChallengerPredicates, wantPredicates)
	}
	return verifyReplacementProjection(record, decisionByID, decision.ChallengerPredicates)
}

func verifyDecisionEditRows(candidate screenDecisionCandidate) error {
	if len(candidate.EditRows) == 0 {
		return fmt.Errorf("candidate %q has no frozen edit rows", candidate.CandidateID)
	}
	seen := make(map[string]struct{}, len(candidate.EditRows))
	changedLines := 0
	changedBytes := 0
	local := true
	previous := ""
	for _, row := range candidate.EditRows {
		if row.EditID == "" || row.EditID <= previous {
			return fmt.Errorf("candidate %q edit rows are not sorted unique", candidate.CandidateID)
		}
		if _, duplicate := seen[row.EditID]; duplicate {
			return fmt.Errorf("candidate %q repeats edit %q", candidate.CandidateID, row.EditID)
		}
		if row.ChangedLines < 0 || row.ChangedBytes < 0 {
			return fmt.Errorf("candidate %q edit %q has negative measurements", candidate.CandidateID, row.EditID)
		}
		if !sort.StringsAreSorted(row.LocalityViolations) {
			return fmt.Errorf("candidate %q edit %q locality violations are not sorted", candidate.CandidateID, row.EditID)
		}
		for index, violation := range row.LocalityViolations {
			if violation == "" || index > 0 && violation == row.LocalityViolations[index-1] {
				return fmt.Errorf("candidate %q edit %q has invalid locality violations", candidate.CandidateID, row.EditID)
			}
		}
		seen[row.EditID] = struct{}{}
		previous = row.EditID
		changedLines += row.ChangedLines
		changedBytes += row.ChangedBytes
		local = local && len(row.LocalityViolations) == 0
	}
	if changedLines != candidate.ChangedLines || changedBytes != candidate.ChangedBytes || local != candidate.EditLocality {
		return fmt.Errorf("candidate %q edit projection does not close aggregate measurements", candidate.CandidateID)
	}
	return nil
}

func frozenScreenChallengerPredicates(record codecSelection, candidates map[string]screenDecisionCandidate) (screenChallengerPredicates, error) {
	if len(record.Roles.RestrictedTextChallengers) != 1 {
		return screenChallengerPredicates{}, errors.New("screen must have exactly one restricted-text challenger")
	}
	baseline, baselineExists := candidates[record.Decision.SelectedJSONLayout]
	challenger, challengerExists := candidates[record.Roles.RestrictedTextChallengers[0]]
	if !baselineExists || !challengerExists {
		return screenChallengerPredicates{}, errors.New("screen decision lacks baseline or challenger")
	}
	lowerCostRows := make([]screenDecisionCandidate, 0, len(record.Roles.ScreenOnlyComparators))
	for _, candidateID := range record.Roles.ScreenOnlyComparators {
		candidate, exists := candidates[candidateID]
		if !exists {
			return screenChallengerPredicates{}, fmt.Errorf("screen decision lacks lower-cost comparator %q", candidateID)
		}
		lowerCostRows = append(lowerCostRows, candidate)
	}
	lowerCostComplete := true
	strictlyDominates := true
	for _, candidate := range lowerCostRows {
		if candidate.Review == nil {
			lowerCostComplete = false
			strictlyDominates = false
			continue
		}
		if challenger.Review == nil || !dominatesEveryPrimaryMetric(challenger, candidate) {
			strictlyDominates = false
		}
	}
	perEditRegression, err := maximumEditRegression(baseline.EditRows, challenger.EditRows)
	if err != nil {
		return screenChallengerPredicates{}, err
	}
	return screenChallengerPredicates{
		GroupedJSONAccepted:                   record.Decision.SelectedJSONLayout != "",
		ReviewPresent:                         challenger.Review != nil,
		ReviewAccuracy:                        challenger.Review != nil && challenger.Review.AccuracyBasisPoints == record.ReplacementPolicy.MinimumReviewAccuracyBasisPoints,
		InvalidMutationFalseAccepts:           challenger.Review != nil && challenger.Review.InvalidMutationFalseAccepts == record.ReplacementPolicy.MaximumInvalidMutationFalseAccepts,
		EditLocality:                          challenger.EditLocality,
		ByteImprovement:                       materiallyBetter(baseline.WeightedCanonicalBytes, challenger.WeightedCanonicalBytes, record.ReplacementPolicy.MinimumByteImprovementBasisPoints),
		TokenImprovement:                      materiallyBetter(baseline.WeightedTokensO200kBase, challenger.WeightedTokensO200kBase, record.ReplacementPolicy.MinimumTokenImprovementBasisPoints),
		AggregateDiffNoninferior:              aggregateDiffRegression(baseline, challenger) <= record.ReplacementPolicy.MaximumAggregateDiffRegressionBasisPoints,
		PerEditDiffNoninferior:                perEditRegression <= record.ReplacementPolicy.MaximumPerEditDiffRegressionBasisPoints,
		ProjectedProductionCost:               projectedProductionWithinPolicy(baseline, challenger, record.ReplacementPolicy.MaximumProjectedProductionCostBasisPoints),
		LowerCostComparisonComplete:           lowerCostComplete,
		StrictlyDominatesLowerCostComparators: lowerCostComplete && strictlyDominates,
	}, nil
}

func dominatesEveryPrimaryMetric(challenger screenDecisionCandidate, candidate screenDecisionCandidate) bool {
	if challenger.Review == nil || candidate.Review == nil {
		return false
	}
	nonWorse := challenger.WeightedCanonicalBytes <= candidate.WeightedCanonicalBytes &&
		challenger.WeightedTokensO200kBase <= candidate.WeightedTokensO200kBase &&
		challenger.ChangedLines <= candidate.ChangedLines && challenger.ChangedBytes <= candidate.ChangedBytes &&
		challenger.Review.AccuracyBasisPoints >= candidate.Review.AccuracyBasisPoints
	strict := challenger.WeightedCanonicalBytes < candidate.WeightedCanonicalBytes ||
		challenger.WeightedTokensO200kBase < candidate.WeightedTokensO200kBase ||
		challenger.ChangedLines < candidate.ChangedLines || challenger.ChangedBytes < candidate.ChangedBytes ||
		challenger.Review.AccuracyBasisPoints > candidate.Review.AccuracyBasisPoints
	return nonWorse && strict
}

func verifyReplacementProjection(record codecSelection, candidates map[string]screenDecisionCandidate, predicates screenChallengerPredicates) error {
	if len(record.Roles.RestrictedTextChallengers) != 1 {
		return errors.New("selection must have exactly one restricted-text challenger")
	}
	baseline, baselineExists := candidates[record.Decision.SelectedJSONLayout]
	challenger, challengerExists := candidates[record.Roles.RestrictedTextChallengers[0]]
	observation, observationExists := observationByID(record.ScreenObservations, record.Roles.RestrictedTextChallengers[0])
	if !baselineExists || !challengerExists || !observationExists {
		return errors.New("replacement projection lacks baseline or challenger")
	}
	aggregate := aggregateDiffRegression(baseline, challenger)
	perEdit, err := maximumEditRegression(baseline.EditRows, challenger.EditRows)
	if err != nil {
		return err
	}
	if observation.AggregateDiffRegressionBasisPoints == nil || *observation.AggregateDiffRegressionBasisPoints != aggregate ||
		observation.PerEditDiffRegressionBasisPoints == nil || *observation.PerEditDiffRegressionBasisPoints != perEdit {
		return fmt.Errorf("challenger replacement diff projection = aggregate %v per-edit %v, want %d and %d", observation.AggregateDiffRegressionBasisPoints, observation.PerEditDiffRegressionBasisPoints, aggregate, perEdit)
	}
	if observation.ParseTimeState != "missing" || observation.FormatTimeState != "missing" {
		return fmt.Errorf("challenger unmeasured performance state = parse %q format %q, want missing", observation.ParseTimeState, observation.FormatTimeState)
	}
	wantDominance := "failed"
	if predicates.LowerCostComparisonComplete && predicates.StrictlyDominatesLowerCostComparators {
		wantDominance = "passed"
	}
	if observation.LowerCostDominanceState != wantDominance {
		return fmt.Errorf("challenger lower-cost dominance = %q, want %q", observation.LowerCostDominanceState, wantDominance)
	}
	return nil
}

func aggregateDiffRegression(baseline screenDecisionCandidate, challenger screenDecisionCandidate) int {
	return maximum(
		regressionBasisPoints(baseline.ChangedLines, challenger.ChangedLines),
		regressionBasisPoints(baseline.ChangedBytes, challenger.ChangedBytes),
	)
}

func projectedProductionWithinPolicy(baseline screenDecisionCandidate, challenger screenDecisionCandidate, maximumBasisPoints int) bool {
	return withinRatio(baseline.ProjectedProduction.LOC, challenger.ProjectedProduction.LOC, maximumBasisPoints) &&
		withinRatio(baseline.ProjectedProduction.Branches, challenger.ProjectedProduction.Branches, maximumBasisPoints)
}

func maximumEditRegression(baselineRows []screenDecisionEditRow, challengerRows []screenDecisionEditRow) (int, error) {
	baseline := make(map[string]screenDecisionEditRow, len(baselineRows))
	for _, row := range baselineRows {
		if _, duplicate := baseline[row.EditID]; duplicate {
			return 0, fmt.Errorf("baseline repeats edit %q", row.EditID)
		}
		baseline[row.EditID] = row
	}
	if len(baseline) != len(challengerRows) {
		return 0, errors.New("replacement edit sets differ")
	}
	result := 0
	seen := make(map[string]struct{}, len(challengerRows))
	for _, row := range challengerRows {
		if _, duplicate := seen[row.EditID]; duplicate {
			return 0, fmt.Errorf("challenger repeats edit %q", row.EditID)
		}
		seen[row.EditID] = struct{}{}
		baselineRow, exists := baseline[row.EditID]
		if !exists {
			return 0, fmt.Errorf("challenger edit %q has no baseline", row.EditID)
		}
		result = maximum(result, regressionBasisPoints(baselineRow.ChangedLines, row.ChangedLines), regressionBasisPoints(baselineRow.ChangedBytes, row.ChangedBytes))
	}
	return result, nil
}

func regressionBasisPoints(baseline int, candidate int) int {
	if baseline <= 0 || candidate <= baseline {
		return 0
	}
	return int(int64(candidate-baseline) * 10000 / int64(baseline))
}

func maximum(values ...int) int {
	result := 0
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func cloneBoolMap(value map[string]bool) map[string]bool {
	result := make(map[string]bool, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func cloneScreenDecisionEvidence(value screenDecisionEvidence) screenDecisionEvidence {
	result := value
	result.Candidates = append([]screenDecisionCandidate(nil), value.Candidates...)
	for index := range result.Candidates {
		result.Candidates[index].EditRows = cloneDecisionEditRows(value.Candidates[index].EditRows)
	}
	return result
}

func cloneDecisionEditRows(value []screenDecisionEditRow) []screenDecisionEditRow {
	result := append([]screenDecisionEditRow(nil), value...)
	for index := range result {
		result[index].LocalityViolations = append([]string(nil), value[index].LocalityViolations...)
	}
	return result
}

func decisionCandidate(value *screenDecisionEvidence, candidateID string) *screenDecisionCandidate {
	for index := range value.Candidates {
		if value.Candidates[index].CandidateID == candidateID {
			return &value.Candidates[index]
		}
	}
	panic("missing frozen decision candidate")
}
