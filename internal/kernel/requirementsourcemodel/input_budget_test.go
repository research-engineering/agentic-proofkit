package requirementsourcemodel

import (
	"reflect"
	"testing"
)

func TestInputCollectionBudgetMatchesIndependentObserver(t *testing.T) {
	draft := validDraft()
	observed := observeInputCollectionItems(reflect.ValueOf(draft))
	if observed == 0 || observed > uint64(DefaultLimits().MaxCollectionItems) {
		t.Fatalf("independent collection item count = %d", observed)
	}
	if !collectionItemsWithinBudget(draft, int(observed)) {
		t.Fatalf("exact collection budget %d was rejected", observed)
	}
	if collectionItemsWithinBudget(draft, int(observed-1)) {
		t.Fatalf("collection limit %d accepted %d observed items", observed-1, observed)
	}
}

func TestInputTextBudgetUsesArchitectureIndependentWidth(t *testing.T) {
	var observed uint64 = draftTextBytes(validDraft())
	if observed != observeStructuredCost(validDraft()).TextBytes {
		t.Fatalf("production input text bytes = %d, independently observed = %d", observed, observeStructuredCost(validDraft()).TextBytes)
	}
}

func TestLimitConfigurationRejectsEveryInvalidBoundary(t *testing.T) {
	tests := []struct {
		name string
		hard int
		set  func(*Limits, int)
	}{
		{"definitions", hardMaxDefinitions, func(value *Limits, limit int) { value.MaxDefinitions = limit }},
		{"derivations", hardMaxDerivations, func(value *Limits, limit int) { value.MaxDerivations = limit }},
		{"examples", hardMaxExamples, func(value *Limits, limit int) { value.MaxExamples = limit }},
		{"examples per scenario", hardMaxExamplesPerScenario, func(value *Limits, limit int) { value.MaxExamplesPerScenario = limit }},
		{"collection items", hardMaxCollectionItems, func(value *Limits, limit int) { value.MaxCollectionItems = limit }},
		{"expanded items", hardMaxExpandedItems, func(value *Limits, limit int) { value.MaxExpandedItems = limit }},
		{"expanded text", hardMaxExpandedTextBytes, func(value *Limits, limit int) { value.MaxExpandedTextBytes = limit }},
		{"groups", hardMaxGroups, func(value *Limits, limit int) { value.MaxGroups = limit }},
		{"members", hardMaxMembers, func(value *Limits, limit int) { value.MaxMembers = limit }},
		{"members per group", hardMaxMembersPerGroup, func(value *Limits, limit int) { value.MaxMembersPerGroup = limit }},
		{"profiles", hardMaxProfiles, func(value *Limits, limit int) { value.MaxProfiles = limit }},
		{"scenario evaluations", hardMaxScenarioEvaluations, func(value *Limits, limit int) { value.MaxScenarioEvaluations = limit }},
		{"scenario evaluation text", hardMaxScenarioEvaluationBytes, func(value *Limits, limit int) { value.MaxScenarioEvaluationBytes = limit }},
		{"scenarios", hardMaxScenarios, func(value *Limits, limit int) { value.MaxScenarios = limit }},
		{"terms", hardMaxTerms, func(value *Limits, limit int) { value.MaxTerms = limit }},
		{"total text", hardMaxTotalTextBytes, func(value *Limits, limit int) { value.MaxTotalTextBytes = limit }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exact := DefaultLimits()
			test.set(&exact, test.hard)
			if err := validateLimits(exact); err != nil {
				t.Fatalf("hard limit rejected: %v", err)
			}
			for _, invalidValue := range []int{0, test.hard + 1} {
				invalidLimits := DefaultLimits()
				test.set(&invalidLimits, invalidValue)
				if err := validateLimits(invalidLimits); ErrorCode(err) != "invalid_limit" {
					t.Fatalf("limit %d ErrorCode() = %q, error = %v", invalidValue, ErrorCode(err), err)
				}
			}
		})
	}
}

func TestPreflightCardinalityBudgetsHaveExactTransitions(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		prepare func(*Draft) int
		set     func(*Limits, int)
	}{
		{"definitions", "definition_budget_exceeded", func(draft *Draft) int {
			draft.NonClaimDefinitions = append(draft.NonClaimDefinitions, draft.NonClaimDefinitions[0])
			return len(draft.NonClaimDefinitions)
		}, func(value *Limits, limit int) { value.MaxDefinitions = limit }},
		{"vocabulary", "vocabulary_budget_exceeded", func(draft *Draft) int {
			draft.Vocabulary = append(draft.Vocabulary, draft.Vocabulary[0])
			return len(draft.Vocabulary)
		}, func(value *Limits, limit int) { value.MaxTerms = limit }},
		{"derivations", "derivation_budget_exceeded", func(draft *Draft) int {
			draft.Derivations = append(draft.Derivations, draft.Derivations[0])
			return len(draft.Derivations)
		}, func(value *Limits, limit int) { value.MaxDerivations = limit }},
		{"profiles", "profile_budget_exceeded", func(draft *Draft) int {
			draft.Profiles = append(draft.Profiles, draft.Profiles[0])
			return len(draft.Profiles)
		}, func(value *Limits, limit int) { value.MaxProfiles = limit }},
		{"groups", "group_budget_exceeded", func(draft *Draft) int {
			draft.Groups = append(draft.Groups, draft.Groups[0])
			return len(draft.Groups)
		}, func(value *Limits, limit int) { value.MaxGroups = limit }},
		{"scenarios", "scenario_budget_exceeded", func(draft *Draft) int {
			draft.Scenarios = append(draft.Scenarios, draft.Scenarios[0])
			return len(draft.Scenarios)
		}, func(value *Limits, limit int) { value.MaxScenarios = limit }},
		{"members per group", "group_member_budget_exceeded", func(draft *Draft) int {
			draft.Groups[0].Members = append(draft.Groups[0].Members, draft.Groups[0].Members[0])
			return len(draft.Groups[0].Members)
		}, func(value *Limits, limit int) { value.MaxMembersPerGroup = limit }},
		{"members", "member_budget_exceeded", func(draft *Draft) int {
			draft.Groups[0].Members = append(draft.Groups[0].Members, draft.Groups[0].Members[0])
			return totalMembers(*draft)
		}, func(value *Limits, limit int) { value.MaxMembers = limit }},
		{"examples per scenario", "scenario_example_budget_exceeded", func(draft *Draft) int {
			draft.Scenarios[0].Examples = append(draft.Scenarios[0].Examples, draft.Scenarios[0].Examples[0])
			return len(draft.Scenarios[0].Examples)
		}, func(value *Limits, limit int) { value.MaxExamplesPerScenario = limit }},
		{"examples", "example_budget_exceeded", func(draft *Draft) int {
			draft.Scenarios[0].Examples = append(draft.Scenarios[0].Examples, draft.Scenarios[0].Examples[0])
			return totalExamples(*draft)
		}, func(value *Limits, limit int) { value.MaxExamples = limit }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validDraft()
			actual := test.prepare(&draft)
			if actual < 2 {
				t.Fatalf("fixture cardinality = %d, want at least 2", actual)
			}

			below := DefaultLimits()
			test.set(&below, actual-1)
			if err := preflight(draft, below); ErrorCode(err) != test.code {
				t.Fatalf("limit-1 ErrorCode() = %q, error = %v, want %q", ErrorCode(err), err, test.code)
			}

			exact := DefaultLimits()
			test.set(&exact, actual)
			if err := preflight(draft, exact); err != nil {
				t.Fatalf("exact cardinality rejected before semantic validation: %v", err)
			}
			if _, err := NormalizeWithLimits(draft, exact); err == nil || ErrorCode(err) == test.code || ErrorCode(err) == "invalid_limit" {
				t.Fatalf("exact cardinality did not reach later semantic validation: %v", err)
			}
		})
	}

	emptyGroups := validDraft()
	emptyGroups.Groups = nil
	if err := preflight(emptyGroups, DefaultLimits()); ErrorCode(err) != "group_budget_exceeded" {
		t.Fatalf("empty groups ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
	emptyMembers := validDraft()
	emptyMembers.Groups[0].Members = nil
	if err := preflight(emptyMembers, DefaultLimits()); ErrorCode(err) != "group_member_budget_exceeded" {
		t.Fatalf("empty members ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestPreflightBudgetErrorPrecedence(t *testing.T) {
	draft := precedenceDraft()
	tests := []struct {
		name   string
		limits Limits
		code   string
	}{
		{
			name: "limit admission before draft budgets",
			limits: withLimits(func(value *Limits) {
				value.MaxDefinitions = 0
				value.MaxTerms = 1
			}),
			code: "invalid_limit",
		},
		{
			name: "definitions before vocabulary",
			limits: withLimits(func(value *Limits) {
				value.MaxDefinitions = 1
				value.MaxTerms = 1
			}),
			code: "definition_budget_exceeded",
		},
		{
			name: "vocabulary before derivations",
			limits: withLimits(func(value *Limits) {
				value.MaxTerms = 1
				value.MaxDerivations = 1
			}),
			code: "vocabulary_budget_exceeded",
		},
		{
			name: "derivations before profiles",
			limits: withLimits(func(value *Limits) {
				value.MaxDerivations = 1
				value.MaxProfiles = 1
			}),
			code: "derivation_budget_exceeded",
		},
		{
			name: "profiles before groups",
			limits: withLimits(func(value *Limits) {
				value.MaxProfiles = 1
				value.MaxGroups = 1
			}),
			code: "profile_budget_exceeded",
		},
		{
			name: "groups before scenarios",
			limits: withLimits(func(value *Limits) {
				value.MaxGroups = 1
				value.MaxScenarios = 1
			}),
			code: "group_budget_exceeded",
		},
		{
			name: "scenarios before collection",
			limits: withLimits(func(value *Limits) {
				value.MaxScenarios = 1
				value.MaxCollectionItems = 1
			}),
			code: "scenario_budget_exceeded",
		},
		{
			name: "collection before group members",
			limits: withLimits(func(value *Limits) {
				value.MaxCollectionItems = 1
				value.MaxMembersPerGroup = 1
			}),
			code: "collection_item_budget_exceeded",
		},
		{
			name: "group members before total members",
			limits: withLimits(func(value *Limits) {
				value.MaxMembersPerGroup = 1
				value.MaxMembers = 1
			}),
			code: "group_member_budget_exceeded",
		},
		{
			name: "total members before scenario examples",
			limits: withLimits(func(value *Limits) {
				value.MaxMembers = 1
				value.MaxExamplesPerScenario = 1
			}),
			code: "member_budget_exceeded",
		},
		{
			name: "scenario examples before total examples",
			limits: withLimits(func(value *Limits) {
				value.MaxExamplesPerScenario = 1
				value.MaxExamples = 1
			}),
			code: "scenario_example_budget_exceeded",
		},
		{
			name: "total examples before text",
			limits: withLimits(func(value *Limits) {
				value.MaxExamples = 1
				value.MaxTotalTextBytes = 1
			}),
			code: "example_budget_exceeded",
		},
		{
			name: "text before scenario evaluation",
			limits: withLimits(func(value *Limits) {
				value.MaxTotalTextBytes = 1
				value.MaxScenarioEvaluations = 1
			}),
			code: "text_budget_exceeded",
		},
		{
			name: "scenario evaluation items before text",
			limits: withLimits(func(value *Limits) {
				value.MaxScenarioEvaluations = 1
				value.MaxScenarioEvaluationBytes = 1
			}),
			code: "scenario_evaluation_budget_exceeded",
		},
		{
			name: "scenario evaluation text before expansion",
			limits: withLimits(func(value *Limits) {
				value.MaxScenarioEvaluationBytes = 1
				value.MaxExpandedItems = 1
			}),
			code: "scenario_evaluation_text_budget_exceeded",
		},
		{
			name: "expanded items before expanded text",
			limits: withLimits(func(value *Limits) {
				value.MaxExpandedItems = 1
				value.MaxExpandedTextBytes = 1
			}),
			code: "expanded_item_budget_exceeded",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizeWithLimits(draft, test.limits)
			if ErrorCode(err) != test.code {
				t.Fatalf("ErrorCode() = %q, error = %v, want %q", ErrorCode(err), err, test.code)
			}
		})
	}
}

func precedenceDraft() Draft {
	draft := validDraft()
	draft.NonClaimDefinitions = append(draft.NonClaimDefinitions, draft.NonClaimDefinitions[0])
	draft.Vocabulary = append(draft.Vocabulary, draft.Vocabulary[0])
	draft.Derivations = append(draft.Derivations, draft.Derivations[0])
	draft.Profiles = append(draft.Profiles, draft.Profiles[0])
	draft.Groups = append(draft.Groups, draft.Groups[0])
	draft.Scenarios = append(draft.Scenarios, draft.Scenarios[0])
	return draft
}

func totalMembers(draft Draft) int {
	total := 0
	for _, group := range draft.Groups {
		total += len(group.Members)
	}
	return total
}

func totalExamples(draft Draft) int {
	total := 0
	for _, scenario := range draft.Scenarios {
		total += len(scenario.Examples)
	}
	return total
}

func observeInputCollectionItems(value reflect.Value) uint64 {
	if !value.IsValid() {
		return 0
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Struct:
		if isPresenceField(value.Type()) {
			if !value.FieldByName("Present").Bool() {
				return 0
			}
			return observeInputCollectionItems(value.FieldByName("Value"))
		}
		total := uint64(0)
		for index := 0; index < value.NumField(); index++ {
			total += observeInputCollectionItems(value.Field(index))
		}
		return total
	case reflect.Slice, reflect.Array:
		total := uint64(value.Len())
		for index := 0; index < value.Len(); index++ {
			total += observeInputCollectionItems(value.Index(index))
		}
		return total
	case reflect.Map:
		total := uint64(value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			total += observeInputCollectionItems(iterator.Value())
		}
		return total
	default:
		return 0
	}
}

func withLimits(edit func(*Limits)) Limits {
	value := DefaultLimits()
	edit(&value)
	return value
}
