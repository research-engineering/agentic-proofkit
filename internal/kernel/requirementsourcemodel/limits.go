package requirementsourcemodel

const (
	hardMaxDefinitions             = 4096
	hardMaxDerivations             = 4096
	hardMaxExamples                = 65536
	hardMaxExamplesPerScenario     = 256
	hardMaxCollectionItems         = 262144
	hardMaxExpandedItems           = 1 << 20
	hardMaxExpandedTextBytes       = 64 << 20
	hardMaxGroups                  = 4096
	hardMaxMembers                 = 16384
	hardMaxMembersPerGroup         = 4096
	hardMaxProfiles                = 2048
	hardMaxScenarioEvaluations     = 1 << 20
	hardMaxScenarioEvaluationBytes = 64 << 20
	hardMaxScenarios               = 8192
	hardMaxTerms                   = 4096
	hardMaxTotalTextBytes          = 16 << 20
)

type Limits struct {
	MaxDefinitions             int
	MaxDerivations             int
	MaxExamples                int
	MaxExamplesPerScenario     int
	MaxCollectionItems         int
	MaxExpandedItems           int
	MaxExpandedTextBytes       int
	MaxGroups                  int
	MaxMembers                 int
	MaxMembersPerGroup         int
	MaxProfiles                int
	MaxScenarioEvaluations     int
	MaxScenarioEvaluationBytes int
	MaxScenarios               int
	MaxTerms                   int
	MaxTotalTextBytes          int
}

func DefaultLimits() Limits {
	return Limits{
		MaxDefinitions:             hardMaxDefinitions,
		MaxDerivations:             hardMaxDerivations,
		MaxExamples:                hardMaxExamples,
		MaxExamplesPerScenario:     hardMaxExamplesPerScenario,
		MaxCollectionItems:         hardMaxCollectionItems,
		MaxExpandedItems:           hardMaxExpandedItems,
		MaxExpandedTextBytes:       hardMaxExpandedTextBytes,
		MaxGroups:                  hardMaxGroups,
		MaxMembers:                 hardMaxMembers,
		MaxMembersPerGroup:         hardMaxMembersPerGroup,
		MaxProfiles:                hardMaxProfiles,
		MaxScenarioEvaluations:     hardMaxScenarioEvaluations,
		MaxScenarioEvaluationBytes: hardMaxScenarioEvaluationBytes,
		MaxScenarios:               hardMaxScenarios,
		MaxTerms:                   hardMaxTerms,
		MaxTotalTextBytes:          hardMaxTotalTextBytes,
	}
}

func ValidateLimits(value Limits) error {
	return validateLimits(value)
}

func validateLimits(value Limits) error {
	checks := []struct {
		actual int
		hard   int
		path   string
	}{
		{value.MaxDefinitions, hardMaxDefinitions, "limits.maxDefinitions"},
		{value.MaxDerivations, hardMaxDerivations, "limits.maxDerivations"},
		{value.MaxExamples, hardMaxExamples, "limits.maxExamples"},
		{value.MaxExamplesPerScenario, hardMaxExamplesPerScenario, "limits.maxExamplesPerScenario"},
		{value.MaxCollectionItems, hardMaxCollectionItems, "limits.maxCollectionItems"},
		{value.MaxExpandedItems, hardMaxExpandedItems, "limits.maxExpandedItems"},
		{value.MaxExpandedTextBytes, hardMaxExpandedTextBytes, "limits.maxExpandedTextBytes"},
		{value.MaxGroups, hardMaxGroups, "limits.maxGroups"},
		{value.MaxMembers, hardMaxMembers, "limits.maxMembers"},
		{value.MaxMembersPerGroup, hardMaxMembersPerGroup, "limits.maxMembersPerGroup"},
		{value.MaxProfiles, hardMaxProfiles, "limits.maxProfiles"},
		{value.MaxScenarioEvaluations, hardMaxScenarioEvaluations, "limits.maxScenarioEvaluations"},
		{value.MaxScenarioEvaluationBytes, hardMaxScenarioEvaluationBytes, "limits.maxScenarioEvaluationBytes"},
		{value.MaxScenarios, hardMaxScenarios, "limits.maxScenarios"},
		{value.MaxTerms, hardMaxTerms, "limits.maxTerms"},
		{value.MaxTotalTextBytes, hardMaxTotalTextBytes, "limits.maxTotalTextBytes"},
	}
	for _, check := range checks {
		if check.actual <= 0 || check.actual > check.hard {
			return invalid("invalid_limit", check.path)
		}
	}
	return nil
}

func preflight(draft Draft, limits Limits) error {
	if len(draft.NonClaimDefinitions) > limits.MaxDefinitions {
		return invalid("definition_budget_exceeded", "nonClaimDefinitions")
	}
	if len(draft.Vocabulary) > limits.MaxTerms {
		return invalid("vocabulary_budget_exceeded", "vocabulary")
	}
	if len(draft.Derivations) > limits.MaxDerivations {
		return invalid("derivation_budget_exceeded", "derivations")
	}
	if len(draft.Profiles) > limits.MaxProfiles {
		return invalid("profile_budget_exceeded", "profiles")
	}
	if len(draft.Groups) == 0 || len(draft.Groups) > limits.MaxGroups {
		return invalid("group_budget_exceeded", "groups")
	}
	if len(draft.Scenarios) > limits.MaxScenarios {
		return invalid("scenario_budget_exceeded", "scenarios")
	}
	if !collectionItemsWithinBudget(draft, limits.MaxCollectionItems) {
		return invalid("collection_item_budget_exceeded", "draft")
	}

	members := 0
	for index, group := range draft.Groups {
		if len(group.Members) == 0 || len(group.Members) > limits.MaxMembersPerGroup {
			return invalid("group_member_budget_exceeded", indexed("groups", index, "members"))
		}
		members += len(group.Members)
		if members > limits.MaxMembers {
			return invalid("member_budget_exceeded", "groups.members")
		}
	}

	examples := 0
	for index, scenario := range draft.Scenarios {
		if len(scenario.Examples) > limits.MaxExamplesPerScenario {
			return invalid("scenario_example_budget_exceeded", indexed("scenarios", index, "examples"))
		}
		examples += len(scenario.Examples)
		if examples > limits.MaxExamples {
			return invalid("example_budget_exceeded", "scenarios.examples")
		}
	}

	if draftTextBytes(draft) > uint64(limits.MaxTotalTextBytes) {
		return invalid("text_budget_exceeded", "draft")
	}
	if err := preflightScenarioEvaluationBudget(draft, limits); err != nil {
		return err
	}
	if err := preflightExpandedProjectionBudget(draft, limits); err != nil {
		return err
	}
	return nil
}

func collectionItemsWithinBudget(draft Draft, limit int) bool {
	remaining := uint64(limit)
	add := func(count int) bool {
		value := uint64(count)
		if value > remaining {
			return false
		}
		remaining -= value
		return true
	}
	if !add(len(draft.SourceNonClaimRefs)) || !add(len(draft.NonClaimDefinitions)) || !add(len(draft.Vocabulary)) ||
		!add(len(draft.Derivations)) || !add(len(draft.Profiles)) || !add(len(draft.Groups)) || !add(len(draft.Scenarios)) {
		return false
	}
	for _, derivation := range draft.Derivations {
		if !add(len(derivation.RequirementIDs)) || !add(len(derivation.NonClaimRefs)) {
			return false
		}
	}
	for _, profile := range draft.Profiles {
		if !metadataCollectionsWithinBudget(profile.Fields, add) {
			return false
		}
	}
	for _, group := range draft.Groups {
		if !add(len(group.SharedPremises)) || !add(len(group.Members)) {
			return false
		}
		for _, member := range group.Members {
			if !metadataCollectionsWithinBudget(member.Fields, add) {
				return false
			}
		}
	}
	for _, scenario := range draft.Scenarios {
		if !add(len(scenario.RequirementIDs)) || !add(len(scenario.Parameters)) || !add(len(scenario.Preconditions)) ||
			!add(len(scenario.ActionSequence)) || !add(len(scenario.ExpectedObservations)) || !add(len(scenario.ForbiddenObservations)) ||
			!add(len(scenario.Examples)) || !add(len(scenario.VocabularyRefs)) || !add(len(scenario.NonClaimRefs)) {
			return false
		}
		for _, example := range scenario.Examples {
			if !add(len(example.Values)) {
				return false
			}
		}
	}
	return true
}

func metadataCollectionsWithinBudget(fields MetadataFields, add func(int) bool) bool {
	if fields.NonClaimRefs.Present && !add(len(fields.NonClaimRefs.Value)) {
		return false
	}
	if fields.Lifecycle.Present && (!add(len(fields.Lifecycle.Value.ReplacementRequirementIDs)) || !add(len(fields.Lifecycle.Value.EvidenceRefs))) {
		return false
	}
	return !fields.Deferral.Present || fields.Deferral.Value == nil || add(len(fields.Deferral.Value.EvidenceRefs))
}

func indexed(root string, index int, leaf string) string {
	return root + "[" + decimal(index) + "]." + leaf
}

func decimal(value int) string {
	if value == 0 {
		return "0"
	}
	buffer := [20]byte{}
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}

func draftTextBytes(draft Draft) uint64 {
	total := textBytes(draft.SourceID, draft.SpecPackagePath)
	total += stringsBytes(draft.SourceNonClaimRefs)
	for _, definition := range draft.NonClaimDefinitions {
		total += textBytes(definition.NonClaimID, definition.Statement)
	}
	for _, term := range draft.Vocabulary {
		total += textBytes(term.TermID, string(term.Kind), term.Label, term.Definition)
	}
	for _, derivation := range draft.Derivations {
		total += textBytes(derivation.DerivationID, string(derivation.SourceKind), string(derivation.SourceRef.ObjectFormat), derivation.SourceRef.CommitOID, derivation.SourceRef.Path, derivation.SourceRef.SHA256)
		total += stringsBytes(derivation.RequirementIDs) + stringsBytes(derivation.NonClaimRefs)
	}
	for _, profile := range draft.Profiles {
		total += uint64(len(profile.ProfileID)) + metadataTextBytes(profile.Fields)
	}
	for _, group := range draft.Groups {
		total += textBytes(group.GroupID, group.ProfileID, group.StatementStem) + stringsBytes(group.SharedPremises)
		for _, member := range group.Members {
			total += textBytes(member.RequirementID, member.StatementCompletion) + metadataTextBytes(member.Fields)
		}
	}
	for _, scenario := range draft.Scenarios {
		total += uint64(len(scenario.ScenarioID))
		total += stringsBytes(scenario.RequirementIDs) + stringsBytes(scenario.Parameters) + stringsBytes(scenario.Preconditions)
		total += stringsBytes(scenario.ActionSequence) + stringsBytes(scenario.ExpectedObservations) + stringsBytes(scenario.ForbiddenObservations)
		total += stringsBytes(scenario.VocabularyRefs) + stringsBytes(scenario.NonClaimRefs)
		for _, example := range scenario.Examples {
			total += uint64(len(example.ExampleID))
			for key, scalar := range example.Values {
				total += textBytes(key, string(scalar))
			}
		}
	}
	return total
}

func metadataTextBytes(fields MetadataFields) uint64 {
	total := uint64(0)
	if fields.OwnerID.Present {
		total += uint64(len(fields.OwnerID.Value))
	}
	if fields.ClaimLevel.Present {
		total += uint64(len(fields.ClaimLevel.Value))
	}
	if fields.RiskClass.Present {
		total += uint64(len(fields.RiskClass.Value))
	}
	if fields.NonClaimRefs.Present {
		total += stringsBytes(fields.NonClaimRefs.Value)
	}
	if fields.Lifecycle.Present {
		total += uint64(len(fields.Lifecycle.Value.State)) + stringsBytes(fields.Lifecycle.Value.ReplacementRequirementIDs) + stringsBytes(fields.Lifecycle.Value.EvidenceRefs)
	}
	if fields.Deferral.Present && fields.Deferral.Value != nil {
		value := fields.Deferral.Value
		total += textBytes(value.OwnerID, value.RiskAcceptedBy, value.ReviewCondition, value.ExpiryRef, value.MergePolicy)
		total += stringsBytes(value.EvidenceRefs)
	}
	if fields.UpdatePolicy.Present {
		total += uint64(len(fields.UpdatePolicy.Value.ReviewOwnerID))
	}
	return total
}

func textBytes(values ...string) uint64 {
	return stringsBytes(values)
}

func stringsBytes(values []string) uint64 {
	total := uint64(0)
	for _, value := range values {
		total += uint64(len(value))
	}
	return total
}
