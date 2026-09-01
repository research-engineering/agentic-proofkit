package requirementsourcecodec

import (
	"bytes"
	"encoding/json"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type document struct {
	SchemaVersion       int                  `json:"schemaVersion"`
	Kind                string               `json:"kind"`
	SourceID            string               `json:"sourceId"`
	SpecPackagePath     string               `json:"specPackagePath"`
	SourceNonClaimRefs  []string             `json:"sourceNonClaimRefs"`
	NonClaimDefinitions []nonClaimDefinition `json:"nonClaimDefinitions"`
	Vocabulary          []vocabularyTerm     `json:"vocabulary"`
	Derivations         []derivation         `json:"derivations"`
	Profiles            []profile            `json:"profiles"`
	Groups              []group              `json:"groups"`
	Scenarios           []scenario           `json:"scenarios"`
}

type nonClaimDefinition struct {
	NonClaimID string `json:"nonClaimId"`
	Statement  string `json:"statement"`
}

type vocabularyTerm struct {
	TermID     string `json:"termId"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	Definition string `json:"definition"`
}

type derivation struct {
	DerivationID   string     `json:"derivationId"`
	SourceKind     string     `json:"sourceKind"`
	SourceRef      gitBlobRef `json:"sourceRef"`
	Selector       byteRange  `json:"selector"`
	RequirementIDs []string   `json:"requirementIds"`
	NonClaimRefs   []string   `json:"nonClaimRefs"`
}

type gitBlobRef struct {
	ObjectFormat string `json:"objectFormat"`
	CommitOID    string `json:"commitOid"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
}

type byteRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type profile struct {
	ProfileID string         `json:"profileId"`
	Fields    metadataFields `json:"fields"`
}

type group struct {
	GroupID        string   `json:"groupId"`
	ProfileID      string   `json:"profileId"`
	StatementStem  string   `json:"statementStem"`
	SharedPremises []string `json:"sharedPremises"`
	Members        []member `json:"members"`
}

type member struct {
	RequirementID       string         `json:"requirementId"`
	StatementCompletion string         `json:"statementCompletion"`
	Fields              metadataFields `json:"fields"`
}

type metadataFields struct {
	OwnerID      *string         `json:"ownerId,omitempty"`
	ClaimLevel   *string         `json:"claimLevel,omitempty"`
	RiskClass    *string         `json:"riskClass,omitempty"`
	NonClaimRefs *[]string       `json:"nonClaimRefs,omitempty"`
	Lifecycle    *lifecycle      `json:"lifecycle,omitempty"`
	Deferral     json.RawMessage `json:"deferral,omitempty"`
	UpdatePolicy *updatePolicy   `json:"updatePolicy,omitempty"`
}

type lifecycle struct {
	State                     string   `json:"state"`
	ReplacementRequirementIDs []string `json:"replacementRequirementIds"`
	EvidenceRefs              []string `json:"evidenceRefs"`
}

type deferral struct {
	OwnerID         string   `json:"ownerId"`
	RiskAcceptedBy  string   `json:"riskAcceptedBy"`
	ReviewCondition string   `json:"reviewCondition"`
	ExpiryRef       string   `json:"expiryRef"`
	MergePolicy     string   `json:"mergePolicy"`
	EvidenceRefs    []string `json:"evidenceRefs"`
}

type updatePolicy struct {
	ReviewOwnerID              string `json:"reviewOwnerId"`
	RequiresImpactDeclaration  bool   `json:"requiresImpactDeclaration"`
	RequiresProofBindingReview bool   `json:"requiresProofBindingReview"`
}

type scenario struct {
	ScenarioID            string    `json:"scenarioId"`
	RequirementIDs        []string  `json:"requirementIds"`
	Parameters            []string  `json:"parameters"`
	Preconditions         []string  `json:"preconditions"`
	ActionSequence        []string  `json:"actionSequence"`
	ExpectedObservations  []string  `json:"expectedObservations"`
	ForbiddenObservations []string  `json:"forbiddenObservations"`
	Examples              []example `json:"examples"`
	VocabularyRefs        []string  `json:"vocabularyRefs"`
	NonClaimRefs          []string  `json:"nonClaimRefs"`
}

type example struct {
	ExampleID string            `json:"exampleId"`
	Values    map[string]string `json:"values"`
}

func draftFromDocument(value document) (requirementsourcemodel.Draft, error) {
	definitions := make([]requirementsourcemodel.NonClaimDefinition, len(value.NonClaimDefinitions))
	for index, item := range value.NonClaimDefinitions {
		definitions[index] = requirementsourcemodel.NonClaimDefinition{NonClaimID: item.NonClaimID, Statement: item.Statement}
	}
	vocabulary := make([]requirementsourcemodel.VocabularyTerm, len(value.Vocabulary))
	for index, item := range value.Vocabulary {
		vocabulary[index] = requirementsourcemodel.VocabularyTerm{TermID: item.TermID, Kind: requirementsourcemodel.TermKind(item.Kind), Label: item.Label, Definition: item.Definition}
	}
	derivations := make([]requirementsourcemodel.Derivation, len(value.Derivations))
	for index, item := range value.Derivations {
		derivations[index] = requirementsourcemodel.Derivation{
			DerivationID: item.DerivationID, SourceKind: requirementsourcemodel.SourceKind(item.SourceKind),
			SourceRef:      requirementsourcemodel.GitBlobRef{ObjectFormat: requirementsourcemodel.ObjectFormat(item.SourceRef.ObjectFormat), CommitOID: item.SourceRef.CommitOID, Path: item.SourceRef.Path, SHA256: item.SourceRef.SHA256},
			Selector:       requirementsourcemodel.ByteRange{Start: item.Selector.Start, End: item.Selector.End},
			RequirementIDs: cloneStrings(item.RequirementIDs), NonClaimRefs: cloneStrings(item.NonClaimRefs),
		}
	}
	profiles := make([]requirementsourcemodel.Profile, len(value.Profiles))
	for index, item := range value.Profiles {
		fields, err := modelMetadata(item.Fields)
		if err != nil {
			return requirementsourcemodel.Draft{}, err
		}
		profiles[index] = requirementsourcemodel.Profile{ProfileID: item.ProfileID, Fields: fields}
	}
	groups := make([]requirementsourcemodel.Group, len(value.Groups))
	for groupIndex, item := range value.Groups {
		members := make([]requirementsourcemodel.Member, len(item.Members))
		for memberIndex, memberValue := range item.Members {
			fields, err := modelMetadata(memberValue.Fields)
			if err != nil {
				return requirementsourcemodel.Draft{}, err
			}
			members[memberIndex] = requirementsourcemodel.Member{RequirementID: memberValue.RequirementID, StatementCompletion: memberValue.StatementCompletion, Fields: fields}
		}
		groups[groupIndex] = requirementsourcemodel.Group{GroupID: item.GroupID, ProfileID: item.ProfileID, StatementStem: item.StatementStem, SharedPremises: cloneStrings(item.SharedPremises), Members: members}
	}
	scenarios := make([]requirementsourcemodel.Scenario, len(value.Scenarios))
	for index, item := range value.Scenarios {
		examples := make([]requirementsourcemodel.Example, len(item.Examples))
		for exampleIndex, exampleValue := range item.Examples {
			values := make(map[string]requirementsourcemodel.ScenarioValue, len(exampleValue.Values))
			for key, scalar := range exampleValue.Values {
				values[key] = requirementsourcemodel.ScenarioValue(scalar)
			}
			examples[exampleIndex] = requirementsourcemodel.Example{ExampleID: exampleValue.ExampleID, Values: values}
		}
		scenarios[index] = requirementsourcemodel.Scenario{
			ScenarioID: item.ScenarioID, RequirementIDs: cloneStrings(item.RequirementIDs), Parameters: cloneStrings(item.Parameters),
			Preconditions: cloneStrings(item.Preconditions), ActionSequence: cloneStrings(item.ActionSequence), ExpectedObservations: cloneStrings(item.ExpectedObservations),
			ForbiddenObservations: cloneStrings(item.ForbiddenObservations), Examples: examples, VocabularyRefs: cloneStrings(item.VocabularyRefs), NonClaimRefs: cloneStrings(item.NonClaimRefs),
		}
	}
	return requirementsourcemodel.Draft{
		SourceID: value.SourceID, SpecPackagePath: value.SpecPackagePath, SourceNonClaimRefs: cloneStrings(value.SourceNonClaimRefs),
		NonClaimDefinitions: definitions, Vocabulary: vocabulary, Derivations: derivations, Profiles: profiles, Groups: groups, Scenarios: scenarios,
	}, nil
}

func modelMetadata(value metadataFields) (requirementsourcemodel.MetadataFields, error) {
	result := requirementsourcemodel.MetadataFields{}
	if value.OwnerID != nil {
		result.OwnerID = requirementsourcemodel.Own(*value.OwnerID)
	}
	if value.ClaimLevel != nil {
		result.ClaimLevel = requirementsourcemodel.Own(requirementsourcemodel.ClaimLevel(*value.ClaimLevel))
	}
	if value.RiskClass != nil {
		result.RiskClass = requirementsourcemodel.Own(requirementsourcemodel.RiskClass(*value.RiskClass))
	}
	if value.NonClaimRefs != nil {
		result.NonClaimRefs = requirementsourcemodel.Own(cloneStrings(*value.NonClaimRefs))
	}
	if value.Lifecycle != nil {
		result.Lifecycle = requirementsourcemodel.Own(requirementsourcemodel.Lifecycle{State: requirementsourcemodel.LifecycleState(value.Lifecycle.State), ReplacementRequirementIDs: cloneStrings(value.Lifecycle.ReplacementRequirementIDs), EvidenceRefs: cloneStrings(value.Lifecycle.EvidenceRefs)})
	}
	if value.Deferral != nil {
		if bytes.Equal(bytes.TrimSpace(value.Deferral), []byte("null")) {
			result.Deferral = requirementsourcemodel.Own[*requirementsourcemodel.Deferral](nil)
		} else {
			var item deferral
			if err := json.Unmarshal(value.Deferral, &item); err != nil {
				return requirementsourcemodel.MetadataFields{}, err
			}
			result.Deferral = requirementsourcemodel.Own(&requirementsourcemodel.Deferral{OwnerID: item.OwnerID, RiskAcceptedBy: item.RiskAcceptedBy, ReviewCondition: item.ReviewCondition, ExpiryRef: item.ExpiryRef, MergePolicy: item.MergePolicy, EvidenceRefs: cloneStrings(item.EvidenceRefs)})
		}
	}
	if value.UpdatePolicy != nil {
		result.UpdatePolicy = requirementsourcemodel.Own(requirementsourcemodel.UpdatePolicy{ReviewOwnerID: value.UpdatePolicy.ReviewOwnerID, RequiresImpactDeclaration: value.UpdatePolicy.RequiresImpactDeclaration, RequiresProofBindingReview: value.UpdatePolicy.RequiresProofBindingReview})
	}
	return result, nil
}

func documentFromModel(model requirementsourcemodel.Model) (document, error) {
	atomic := model.Atomic()
	layout := model.Layout()
	references := model.References()
	value := document{
		SchemaVersion: SchemaVersion, Kind: DocumentKind, SourceID: atomic.SourceID, SpecPackagePath: atomic.SpecPackagePath,
		SourceNonClaimRefs: nonNilStrings(atomic.SourceNonClaimRefs), NonClaimDefinitions: make([]nonClaimDefinition, len(atomic.NonClaimDefinitions)),
		Vocabulary: make([]vocabularyTerm, len(atomic.Vocabulary)), Derivations: make([]derivation, len(references.Derivations)),
		Profiles: make([]profile, len(layout.Profiles)), Groups: make([]group, len(layout.Groups)), Scenarios: make([]scenario, len(atomic.Scenarios)),
	}
	for index, item := range atomic.NonClaimDefinitions {
		value.NonClaimDefinitions[index] = nonClaimDefinition{NonClaimID: item.NonClaimID, Statement: item.Statement}
	}
	for index, item := range atomic.Vocabulary {
		value.Vocabulary[index] = vocabularyTerm{TermID: item.TermID, Kind: string(item.Kind), Label: item.Label, Definition: item.Definition}
	}
	for index, item := range references.Derivations {
		value.Derivations[index] = derivation{DerivationID: item.DerivationID, SourceKind: string(item.SourceKind), SourceRef: gitBlobRef{ObjectFormat: string(item.SourceRef.ObjectFormat), CommitOID: item.SourceRef.CommitOID, Path: item.SourceRef.Path, SHA256: item.SourceRef.SHA256}, Selector: byteRange{Start: item.Selector.Start, End: item.Selector.End}, RequirementIDs: nonNilStrings(item.RequirementIDs), NonClaimRefs: nonNilStrings(item.NonClaimRefs)}
	}
	for index, item := range layout.Profiles {
		fields, err := wireMetadata(item.Fields)
		if err != nil {
			return document{}, err
		}
		value.Profiles[index] = profile{ProfileID: item.ProfileID, Fields: fields}
	}
	for groupIndex, item := range layout.Groups {
		members := make([]member, len(item.Members))
		for memberIndex, memberValue := range item.Members {
			fields, err := wireMetadata(memberValue.Fields)
			if err != nil {
				return document{}, err
			}
			members[memberIndex] = member{RequirementID: memberValue.RequirementID, StatementCompletion: memberValue.StatementCompletion, Fields: fields}
		}
		value.Groups[groupIndex] = group{GroupID: item.GroupID, ProfileID: item.ProfileID, StatementStem: item.StatementStem, SharedPremises: nonNilStrings(item.SharedPremises), Members: members}
	}
	for index, item := range atomic.Scenarios {
		examples := make([]example, len(item.Examples))
		for exampleIndex, exampleValue := range item.Examples {
			values := make(map[string]string, len(exampleValue.Values))
			for key, scalar := range exampleValue.Values {
				values[key] = string(scalar)
			}
			examples[exampleIndex] = example{ExampleID: exampleValue.ExampleID, Values: values}
		}
		value.Scenarios[index] = scenario{ScenarioID: item.ScenarioID, RequirementIDs: nonNilStrings(item.RequirementIDs), Parameters: nonNilStrings(item.Parameters), Preconditions: nonNilStrings(item.Preconditions), ActionSequence: nonNilStrings(item.ActionSequence), ExpectedObservations: nonNilStrings(item.ExpectedObservations), ForbiddenObservations: nonNilStrings(item.ForbiddenObservations), Examples: examples, VocabularyRefs: nonNilStrings(item.VocabularyRefs), NonClaimRefs: nonNilStrings(item.NonClaimRefs)}
	}
	return value, nil
}

func wireMetadata(value requirementsourcemodel.MetadataFields) (metadataFields, error) {
	result := metadataFields{}
	if value.OwnerID.Present {
		item := value.OwnerID.Value
		result.OwnerID = &item
	}
	if value.ClaimLevel.Present {
		item := string(value.ClaimLevel.Value)
		result.ClaimLevel = &item
	}
	if value.RiskClass.Present {
		item := string(value.RiskClass.Value)
		result.RiskClass = &item
	}
	if value.NonClaimRefs.Present {
		item := nonNilStrings(value.NonClaimRefs.Value)
		result.NonClaimRefs = &item
	}
	if value.Lifecycle.Present {
		result.Lifecycle = &lifecycle{State: string(value.Lifecycle.Value.State), ReplacementRequirementIDs: nonNilStrings(value.Lifecycle.Value.ReplacementRequirementIDs), EvidenceRefs: nonNilStrings(value.Lifecycle.Value.EvidenceRefs)}
	}
	if value.Deferral.Present {
		if value.Deferral.Value == nil {
			result.Deferral = json.RawMessage("null")
		} else {
			payload, err := json.Marshal(deferral{OwnerID: value.Deferral.Value.OwnerID, RiskAcceptedBy: value.Deferral.Value.RiskAcceptedBy, ReviewCondition: value.Deferral.Value.ReviewCondition, ExpiryRef: value.Deferral.Value.ExpiryRef, MergePolicy: value.Deferral.Value.MergePolicy, EvidenceRefs: nonNilStrings(value.Deferral.Value.EvidenceRefs)})
			if err != nil {
				return metadataFields{}, err
			}
			result.Deferral = payload
		}
	}
	if value.UpdatePolicy.Present {
		result.UpdatePolicy = &updatePolicy{ReviewOwnerID: value.UpdatePolicy.Value.ReviewOwnerID, RequiresImpactDeclaration: value.UpdatePolicy.Value.RequiresImpactDeclaration, RequiresProofBindingReview: value.UpdatePolicy.Value.RequiresProofBindingReview}
	}
	return result, nil
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func nonNilStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}
