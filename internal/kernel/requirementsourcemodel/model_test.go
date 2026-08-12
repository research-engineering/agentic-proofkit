package requirementsourcemodel

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeBuildsDeterministicSeparatedProjections(t *testing.T) {
	draft := validDraft()
	model, err := Normalize(draft)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	atomic := model.Atomic()
	if len(atomic.Requirements) != 4 {
		t.Fatalf("requirement count = %d, want 4", len(atomic.Requirements))
	}
	if got := atomic.Requirements[0].Invariant; got != "The service must accept requests." {
		t.Fatalf("first invariant = %q", got)
	}
	if got := atomic.Requirements[0].SharedPremises; !reflect.DeepEqual(got, []string{"The service is available."}) {
		t.Fatalf("shared premises = %#v", got)
	}

	permuted := validDraft()
	reverseDefinitions(permuted.NonClaimDefinitions)
	reverseVocabulary(permuted.Vocabulary)
	reverseDerivations(permuted.Derivations)
	reverseProfiles(permuted.Profiles)
	reverseGroups(permuted.Groups)
	reverseScenarios(permuted.Scenarios)
	permuted.Groups[2].Members[0].Fields.NonClaimRefs.Value = []string{"NCL-MODEL-002"}
	other, err := Normalize(permuted)
	if err != nil {
		t.Fatalf("Normalize(permuted) error = %v", err)
	}
	if !reflect.DeepEqual(model.Atomic(), other.Atomic()) ||
		!reflect.DeepEqual(model.Layout(), other.Layout()) ||
		!reflect.DeepEqual(model.References(), other.References()) {
		t.Fatal("set-like input permutation changed normalized projections")
	}
}

func TestNormalizeSeparatesAuthoringLayoutFromAtomicSemantics(t *testing.T) {
	baseline, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	changedDraft := validDraft()
	changedDraft.Groups[0].GroupID = "RGRP-MODEL-RENAMED"
	changed, err := Normalize(changedDraft)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(baseline.Atomic(), changed.Atomic()) {
		t.Fatal("group rename changed atomic semantics")
	}
	if reflect.DeepEqual(baseline.Layout(), changed.Layout()) {
		t.Fatal("group rename did not change layout projection")
	}
	if reflect.DeepEqual(baseline.References(), changed.References()) {
		t.Fatal("group rename did not change reference projection")
	}
}

func TestNormalizeBuildsEveryTypedReferenceRole(t *testing.T) {
	model, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	expected := map[ReferenceKind]struct {
		from EntityKind
		to   EntityKind
	}{
		ReferenceDerivationNonClaim:    {EntityDerivation, EntityNonClaim},
		ReferenceDerivationRequirement: {EntityDerivation, EntityRequirement},
		ReferenceGroupMember:           {EntityGroup, EntityRequirement},
		ReferenceGroupProfile:          {EntityGroup, EntityProfile},
		ReferenceLifecycleReplacement:  {EntityRequirement, EntityRequirement},
		ReferenceRequirementNonClaim:   {EntityRequirement, EntityNonClaim},
		ReferenceScenarioNonClaim:      {EntityScenario, EntityNonClaim},
		ReferenceScenarioRequirement:   {EntityScenario, EntityRequirement},
		ReferenceScenarioVocabulary:    {EntityScenario, EntityTerm},
		ReferenceSourceNonClaim:        {EntitySource, EntityNonClaim},
	}
	seen := map[ReferenceKind]bool{}
	for _, edge := range model.References().Edges {
		roles, exists := expected[edge.Kind]
		if !exists {
			t.Fatalf("unknown reference kind %q", edge.Kind)
		}
		if edge.From.Kind != roles.from || edge.To.Kind != roles.to {
			t.Fatalf("reference %q has roles %q -> %q, want %q -> %q", edge.Kind, edge.From.Kind, edge.To.Kind, roles.from, roles.to)
		}
		seen[edge.Kind] = true
	}
	for kind := range expected {
		if !seen[kind] {
			t.Fatalf("reference kind %q is not exercised", kind)
		}
	}
}

func TestModelAccessorsDoNotExposeMutableOwnerState(t *testing.T) {
	model, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	assertAccessorReturnsDetachedState(t, "atomic", model.Atomic)
	assertAccessorReturnsDetachedState(t, "layout", model.Layout)
	assertAccessorReturnsDetachedState(t, "references", model.References)
}

func TestNormalizeRejectsInvalidReferenceAndMetadataPartitions(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*Draft)
	}{
		{
			name: "dangling nonclaim",
			code: "dangling_nonclaim_ref",
			edit: func(draft *Draft) { draft.SourceNonClaimRefs[0] = "NCL-MISSING" },
		},
		{
			name: "unreferenced vocabulary",
			code: "unreferenced_vocabulary",
			edit: func(draft *Draft) { draft.Scenarios[0].VocabularyRefs = nil },
		},
		{
			name: "dangling scenario requirement",
			code: "dangling_requirement_ref",
			edit: func(draft *Draft) { draft.Scenarios[0].RequirementIDs[0] = "REQ-MISSING" },
		},
		{
			name: "profile member overlap",
			code: "metadata_partition_violation",
			edit: func(draft *Draft) { draft.Groups[0].Members[0].Fields.OwnerID = Own("owner.duplicate") },
		},
		{
			name: "profile member gap",
			code: "metadata_partition_violation",
			edit: func(draft *Draft) { draft.Groups[0].Members[0].Fields.NonClaimRefs = Field[[]string]{} },
		},
		{
			name: "hidden omitted payload",
			code: "hidden_field_payload",
			edit: func(draft *Draft) {
				draft.Groups[0].Members[0].Fields.OwnerID = Field[string]{Value: "owner.hidden"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validDraft()
			test.edit(&draft)
			_, err := Normalize(draft)
			if ErrorCode(err) != test.code {
				t.Fatalf("ErrorCode() = %q, error = %v, want %q", ErrorCode(err), err, test.code)
			}
		})
	}
}

func TestNormalizeRejectsBudgetBeforeMemberSemantics(t *testing.T) {
	draft := validDraft()
	draft.Groups[0].Members[1].StatementCompletion = "TODO"
	limits := DefaultLimits()
	limits.MaxMembers = 1
	_, err := NormalizeWithLimits(draft, limits)
	if ErrorCode(err) != "member_budget_exceeded" {
		t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestNormalizeRejectsNestedCollectionBudgetBeforeElementSemantics(t *testing.T) {
	draft := validDraft()
	limits := DefaultLimits()
	baselineItems := observeInputCollectionItems(reflect.ValueOf(draft))
	limits.MaxCollectionItems = int(baselineItems)
	draft.Scenarios[0].Preconditions = append(draft.Scenarios[0].Preconditions, "TODO")
	_, err := NormalizeWithLimits(draft, limits)
	if ErrorCode(err) != "collection_item_budget_exceeded" {
		t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestNormalizeEnforcesExactInputTextBudgetBeforeElementSemantics(t *testing.T) {
	draft := validDraft()
	limits := DefaultLimits()
	observedBytes := observeStructuredCost(draft).TextBytes
	if draftTextBytes(draft) != observedBytes {
		t.Fatalf("production input text bytes = %d, observed = %d", draftTextBytes(draft), observedBytes)
	}
	limits.MaxTotalTextBytes = int(observedBytes)
	if _, err := NormalizeWithLimits(draft, limits); err != nil {
		t.Fatalf("exact input text budget rejected: %v", err)
	}

	invalidDraft := validDraft()
	invalidDraft.Groups[0].Members[0].StatementCompletion = "TODO"
	invalidBytes := int(observeStructuredCost(invalidDraft).TextBytes)
	limits.MaxTotalTextBytes = invalidBytes - 1
	_, err := NormalizeWithLimits(invalidDraft, limits)
	if ErrorCode(err) != "text_budget_exceeded" {
		t.Fatalf("limit-1 ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
	limits.MaxTotalTextBytes = invalidBytes
	_, err = NormalizeWithLimits(invalidDraft, limits)
	if ErrorCode(err) != "placeholder_text" {
		t.Fatalf("exact-limit ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestNormalizeRejectsExpandedProjectionBudgetsBeforeMemberSemantics(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*Draft, *Limits)
	}{
		{
			name: "text amplification",
			code: "expanded_text_budget_exceeded",
			edit: func(draft *Draft, limits *Limits) {
				draft.Groups[0].StatementStem = strings.Repeat("A", 4096)
				draft.Groups[0].Members = expandedMembers(draft.Groups[0].Members[0], 512)
				limits.MaxExpandedTextBytes = 1 << 20
			},
		},
		{
			name: "item amplification",
			code: "expanded_item_budget_exceeded",
			edit: func(draft *Draft, limits *Limits) {
				draft.Groups[0].Members = expandedMembers(draft.Groups[0].Members[0], 100)
				draft.Groups[0].SharedPremises = make([]string, 20)
				for index := range draft.Groups[0].SharedPremises {
					draft.Groups[0].SharedPremises[index] = "Premise " + decimal(index+1) + "."
				}
				limits.MaxExpandedItems = 1000
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validDraft()
			limits := DefaultLimits()
			test.edit(&draft, &limits)
			draft.Groups[0].Members[len(draft.Groups[0].Members)-1].StatementCompletion = "TODO"
			_, err := NormalizeWithLimits(draft, limits)
			if ErrorCode(err) != test.code {
				t.Fatalf("ErrorCode() = %q, error = %v, want %q", ErrorCode(err), err, test.code)
			}
		})
	}
}

func TestNormalizeRejectsContradictoryScenarioObservations(t *testing.T) {
	draft := validDraft()
	draft.Scenarios[0].ForbiddenObservations = []string{"The request is accepted."}
	_, err := Normalize(draft)
	if ErrorCode(err) != "contradictory_observation" {
		t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestNormalizeReportsUnreferencedDefinitionsDeterministically(t *testing.T) {
	draft := validDraft()
	draft.NonClaimDefinitions = append(draft.NonClaimDefinitions,
		NonClaimDefinition{NonClaimID: "NCL-MODEL-006", Statement: "This sixth declaration remains deliberately unreferenced."},
		NonClaimDefinition{NonClaimID: "NCL-MODEL-005", Statement: "This fifth declaration remains deliberately unreferenced."},
	)
	const expected = "unreferenced_definition: nonClaimDefinitions.NCL-MODEL-005"
	for attempt := 0; attempt < 100; attempt++ {
		_, err := Normalize(draft)
		if err == nil || err.Error() != expected {
			t.Fatalf("attempt %d error = %v, want %q", attempt, err, expected)
		}
	}
}

func expandedMembers(template Member, count int) []Member {
	result := make([]Member, count)
	for index := range result {
		requirementID := "REQ-MODEL-EXPANDED-" + decimal(index+1)
		if index == 0 {
			requirementID = "REQ-MODEL-001"
		} else if index == 1 {
			requirementID = "REQ-MODEL-002"
		}
		result[index] = Member{
			RequirementID:       requirementID,
			StatementCompletion: "accept request " + decimal(index+1) + ".",
			Fields:              cloneMetadataFields(template.Fields),
		}
	}
	return result
}

func TestNormalizeDiagnosticsDoNotEchoCallerText(t *testing.T) {
	const sentinel = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	draft := validDraft()
	draft.NonClaimDefinitions[0].Statement = "token=" + sentinel
	_, err := Normalize(draft)
	if err == nil {
		t.Fatal("secret-shaped caller text was accepted")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatal("validation error disclosed caller-owned text")
	}
	if ErrorCode(err) != "invalid_text" {
		t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func validDraft() Draft {
	active := Lifecycle{State: LifecycleActive}
	blockingProfile := Profile{
		ProfileID: "RPROF-MODEL-BLOCKING",
		Fields: MetadataFields{
			OwnerID:    Own("proofkit.model"),
			ClaimLevel: Own(ClaimBlocking),
			RiskClass:  Own(RiskHigh),
			UpdatePolicy: Own(UpdatePolicy{
				ReviewOwnerID:              "proofkit.model",
				RequiresImpactDeclaration:  true,
				RequiresProofBindingReview: true,
			}),
		},
	}
	memberFields := func() MetadataFields {
		return MetadataFields{
			NonClaimRefs: Own([]string{"NCL-MODEL-002"}),
			Lifecycle:    Own(active),
			Deferral:     Own[*Deferral](nil),
		}
	}
	fullFields := func(claim ClaimLevel, lifecycle Lifecycle, deferral *Deferral) MetadataFields {
		return MetadataFields{
			OwnerID:      Own("proofkit.model"),
			ClaimLevel:   Own(claim),
			RiskClass:    Own(RiskMedium),
			NonClaimRefs: Own([]string{"NCL-MODEL-002"}),
			Lifecycle:    Own(lifecycle),
			Deferral:     Own(deferral),
			UpdatePolicy: Own(UpdatePolicy{
				ReviewOwnerID:              "proofkit.model",
				RequiresImpactDeclaration:  true,
				RequiresProofBindingReview: true,
			}),
		}
	}
	deferral := &Deferral{
		OwnerID:         "proofkit.model",
		RiskAcceptedBy:  "proofkit.owner",
		ReviewCondition: "Review after the model experiment.",
		ExpiryRef:       "proofkit.model.expiry",
		MergePolicy:     "proofkit.model.merge",
		EvidenceRefs:    []string{"docs/evidence/deferral.md"},
	}
	return Draft{
		SourceID:           "proofkit.model.source",
		SpecPackagePath:    "docs/specs/proofkit-model",
		SourceNonClaimRefs: []string{"NCL-MODEL-001"},
		NonClaimDefinitions: []NonClaimDefinition{
			{NonClaimID: "NCL-MODEL-001", Statement: "The model does not prove implementation correctness."},
			{NonClaimID: "NCL-MODEL-002", Statement: "A declared requirement does not prove its own satisfaction."},
			{NonClaimID: "NCL-MODEL-003", Statement: "Scenario examples are not exhaustive proof."},
			{NonClaimID: "NCL-MODEL-004", Statement: "Derivation provenance does not prove requirement correctness."},
		},
		Vocabulary: []VocabularyTerm{
			{TermID: "TERM-MODEL-SERVICE", Kind: TermSubject, Label: "service", Definition: "The bounded service under specification."},
		},
		Derivations: []Derivation{
			{
				DerivationID: "DRV-MODEL-001",
				SourceKind:   SourceOwnerDecision,
				SourceRef: GitBlobRef{
					ObjectFormat: ObjectSHA1,
					CommitOID:    "0123456789abcdef0123456789abcdef01234567",
					Path:         "docs/decisions/model.md",
					SHA256:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				},
				Selector:       ByteRange{Start: 0, End: 64},
				RequirementIDs: []string{"REQ-MODEL-001", "REQ-MODEL-002"},
				NonClaimRefs:   []string{"NCL-MODEL-004"},
			},
		},
		Profiles: []Profile{blockingProfile},
		Groups: []Group{
			{
				GroupID:        "RGRP-MODEL-REQUESTS",
				ProfileID:      "RPROF-MODEL-BLOCKING",
				StatementStem:  "The service must",
				SharedPremises: []string{"The service is available."},
				Members: []Member{
					{RequirementID: "REQ-MODEL-001", StatementCompletion: "accept requests.", Fields: memberFields()},
					{RequirementID: "REQ-MODEL-002", StatementCompletion: "reject malformed requests.", Fields: memberFields()},
				},
			},
			{
				GroupID: "RGRP-MODEL-DEFERRED",
				Members: []Member{
					{RequirementID: "REQ-MODEL-003", StatementCompletion: "Deferred behavior remains owner-reviewed.", Fields: fullFields(ClaimDeferred, active, deferral)},
				},
			},
			{
				GroupID: "RGRP-MODEL-SUPERSEDED",
				Members: []Member{
					{
						RequirementID:       "REQ-MODEL-004",
						StatementCompletion: "Historical behavior is superseded.",
						Fields: fullFields(ClaimAdvisory, Lifecycle{
							State:                     LifecycleSuperseded,
							ReplacementRequirementIDs: []string{"REQ-MODEL-001"},
							EvidenceRefs:              []string{"docs/evidence/superseded.md"},
						}, nil),
					},
				},
			},
		},
		Scenarios: []Scenario{
			{
				ScenarioID:            "SCN-MODEL-REQUEST",
				RequirementIDs:        []string{"REQ-MODEL-001"},
				Parameters:            []string{"surface"},
				Preconditions:         []string{"The ${surface} surface is available."},
				ActionSequence:        []string{"Submit a request.", "Wait for the response."},
				ExpectedObservations:  []string{"The request is accepted."},
				ForbiddenObservations: []string{"The service exposes a secret."},
				Examples: []Example{
					{ExampleID: "EX-MODEL-REQUEST-001", Values: map[string]ScenarioValue{"surface": "primary"}},
					{ExampleID: "EX-MODEL-REQUEST-002", Values: map[string]ScenarioValue{"surface": "secondary"}},
				},
				VocabularyRefs: []string{"TERM-MODEL-SERVICE"},
				NonClaimRefs:   []string{"NCL-MODEL-003"},
			},
		},
	}
}

func reverseDefinitions(values []NonClaimDefinition) {
	reverse(len(values), func(left, right int) { values[left], values[right] = values[right], values[left] })
}
func reverseVocabulary(values []VocabularyTerm) {
	reverse(len(values), func(left, right int) { values[left], values[right] = values[right], values[left] })
}
func reverseDerivations(values []Derivation) {
	reverse(len(values), func(left, right int) { values[left], values[right] = values[right], values[left] })
}
func reverseProfiles(values []Profile) {
	reverse(len(values), func(left, right int) { values[left], values[right] = values[right], values[left] })
}
func reverseGroups(values []Group) {
	reverse(len(values), func(left, right int) { values[left], values[right] = values[right], values[left] })
}
func reverseScenarios(values []Scenario) {
	reverse(len(values), func(left, right int) { values[left], values[right] = values[right], values[left] })
}

func reverse(length int, swap func(int, int)) {
	for left, right := 0, length-1; left < right; left, right = left+1, right-1 {
		swap(left, right)
	}
}
