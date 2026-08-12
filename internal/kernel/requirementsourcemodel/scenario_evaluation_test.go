package requirementsourcemodel

import (
	"os"
	"testing"
)

func TestNormalizeRejectsContradictoryInstantiatedObservations(t *testing.T) {
	draft := validDraft()
	draft.Scenarios[0].ExpectedObservations = []string{"The ${surface} request is accepted."}
	draft.Scenarios[0].ForbiddenObservations = []string{"The primary request is accepted."}

	_, err := Normalize(draft)
	if ErrorCode(err) != "contradictory_instantiated_observation" {
		t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestScenarioEvaluationBudgetMatchesIndependentInstantiation(t *testing.T) {
	draft := validDraft()
	scenario := &draft.Scenarios[0]
	scenario.ExpectedObservations = []string{
		"The ${surface} request is accepted.",
		"The response identifies ${surface}.",
	}
	scenario.ForbiddenObservations = []string{"The ${surface} request is rejected."}

	estimated, overflow := estimateScenarioEvaluationCost(draft)
	if overflow {
		t.Fatal("valid scenario evaluation overflowed")
	}
	observed := observeScenarioEvaluationCost(draft)
	if estimated != observed {
		t.Fatalf("estimated scenario evaluation cost = %#v, observed = %#v", estimated, observed)
	}

	limits := DefaultLimits()
	limits.MaxScenarioEvaluations = int(observed.Items)
	limits.MaxScenarioEvaluationBytes = int(observed.TextBytes)
	if _, err := NormalizeWithLimits(draft, limits); err != nil {
		t.Fatalf("exact scenario evaluation budgets rejected: %v", err)
	}

	itemLimits := DefaultLimits()
	itemLimits.MaxScenarioEvaluations = int(observed.Items - 1)
	if _, err := NormalizeWithLimits(draft, itemLimits); ErrorCode(err) != "scenario_evaluation_budget_exceeded" {
		t.Fatalf("item limit-1 ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
	textLimits := DefaultLimits()
	textLimits.MaxScenarioEvaluationBytes = int(observed.TextBytes - 1)
	if _, err := NormalizeWithLimits(draft, textLimits); ErrorCode(err) != "scenario_evaluation_text_budget_exceeded" {
		t.Fatalf("text limit-1 ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestScenarioParameterValuesAreSubstitutedOnce(t *testing.T) {
	draft := validDraft()
	scenario := &draft.Scenarios[0]
	scenario.Parameters = []string{"nested", "surface"}
	scenario.ExpectedObservations = []string{"Observed ${surface}."}
	scenario.ForbiddenObservations = []string{"Observed ${nested}."}
	scenario.Examples = []Example{
		{ExampleID: "EX-MODEL-REQUEST-001", Values: map[string]ScenarioValue{"nested": "resolved", "surface": "${nested}"}},
		{ExampleID: "EX-MODEL-REQUEST-002", Values: map[string]ScenarioValue{"nested": "other", "surface": "secondary"}},
	}

	if _, err := Normalize(draft); err != nil {
		t.Fatalf("single-pass scenario substitution rejected: %v", err)
	}
}

func observeScenarioEvaluationCost(draft Draft) scenarioEvaluationCost {
	cost := scenarioEvaluationCost{}
	for _, scenario := range draft.Scenarios {
		observations := append([]string{}, scenario.ExpectedObservations...)
		observations = append(observations, scenario.ForbiddenObservations...)
		for _, example := range scenario.Examples {
			for _, observation := range observations {
				instantiated := os.Expand(observation, func(parameter string) string {
					return string(example.Values[parameter])
				})
				cost.Items++
				cost.TextBytes += uint64(len(instantiated))
			}
		}
	}
	return cost
}
