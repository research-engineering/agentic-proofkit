package requirementsourcemodel

import (
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func Normalize(draft Draft) (Model, error) {
	return NormalizeWithLimits(draft, DefaultLimits())
}

func NormalizeWithLimits(draft Draft, limits Limits) (Model, error) {
	if err := ValidateLimits(limits); err != nil {
		return Model{}, err
	}
	if err := preflight(draft, limits); err != nil {
		return Model{}, err
	}
	snapshot := cloneDraft(draft)
	if err := preflight(snapshot, limits); err != nil {
		return Model{}, err
	}

	sourceID, err := canonicalExternalID(snapshot.SourceID, "sourceId")
	if err != nil {
		return Model{}, err
	}
	specPackagePath, err := canonicalPath(snapshot.SpecPackagePath, "specPackagePath")
	if err != nil {
		return Model{}, err
	}
	sourceNonClaimRefs, err := normalizeIDs(snapshot.SourceNonClaimRefs, "NCL-", "sourceNonClaimRefs", true)
	if err != nil {
		return Model{}, err
	}

	definitions, definitionIDs, err := normalizeDefinitions(snapshot.NonClaimDefinitions)
	if err != nil {
		return Model{}, err
	}
	vocabulary, vocabularyIDs, err := normalizeVocabulary(snapshot.Vocabulary)
	if err != nil {
		return Model{}, err
	}
	profiles, profilesByID, err := normalizeProfiles(snapshot.Profiles)
	if err != nil {
		return Model{}, err
	}
	groups, requirements, origins, profileUses, err := normalizeGroups(snapshot.Groups, profilesByID)
	if err != nil {
		return Model{}, err
	}
	if err := validateProfileUses(profiles, profileUses); err != nil {
		return Model{}, err
	}
	requirementsByID := make(map[string]AtomicRequirement, len(requirements))
	for _, requirement := range requirements {
		requirementsByID[requirement.RequirementID] = requirement
	}
	if err := validateRequirementLifecycles(requirements, requirementsByID); err != nil {
		return Model{}, err
	}

	scenarios, err := normalizeScenarios(snapshot.Scenarios, requirementsByID, vocabularyIDs)
	if err != nil {
		return Model{}, err
	}
	derivations, err := normalizeDerivations(snapshot.Derivations, requirementsByID)
	if err != nil {
		return Model{}, err
	}
	edges := buildReferenceEdges(sourceID, sourceNonClaimRefs, groups, requirements, scenarios, derivations)
	if err := validateReferenceClosure(definitionIDs, vocabularyIDs, edges); err != nil {
		return Model{}, err
	}

	atomic := AtomicProjection{
		SourceID:            sourceID,
		SpecPackagePath:     specPackagePath,
		SourceNonClaimRefs:  sourceNonClaimRefs,
		NonClaimDefinitions: definitions,
		Vocabulary:          vocabulary,
		Requirements:        requirements,
		Scenarios:           scenarios,
	}
	layout := LayoutProjection{SourceID: sourceID, Profiles: profiles, Groups: groups, Origins: origins}
	references := ReferenceProjection{SourceID: sourceID, Derivations: derivations, Edges: edges}
	return Model{
		atomic:     cloneAtomicProjection(atomic),
		layout:     cloneLayoutProjection(layout),
		references: cloneReferenceProjection(references),
	}, nil
}

func normalizeDefinitions(values []NonClaimDefinition) ([]NonClaimDefinition, map[string]struct{}, error) {
	result := make([]NonClaimDefinition, len(values))
	ids := make(map[string]struct{}, len(values))
	statements := make(map[string]struct{}, len(values))
	for index, value := range values {
		path := indexed("nonClaimDefinitions", index, "")
		id, err := canonicalID(value.NonClaimID, "NCL-", path+"nonClaimId")
		if err != nil {
			return nil, nil, err
		}
		if _, exists := ids[id]; exists {
			return nil, nil, invalid("duplicate_id", "nonClaimDefinitions")
		}
		statement, err := canonicalText(value.Statement, path+"statement", false, true)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := statements[statement]; exists {
			return nil, nil, invalid("duplicate_definition", "nonClaimDefinitions")
		}
		ids[id] = struct{}{}
		statements[statement] = struct{}{}
		result[index] = NonClaimDefinition{NonClaimID: id, Statement: statement}
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].NonClaimID < result[right].NonClaimID })
	return result, ids, nil
}

func normalizeVocabulary(values []VocabularyTerm) ([]VocabularyTerm, map[string]struct{}, error) {
	result := make([]VocabularyTerm, len(values))
	ids := make(map[string]struct{}, len(values))
	for index, value := range values {
		path := indexed("vocabulary", index, "")
		id, err := canonicalID(value.TermID, "TERM-", path+"termId")
		if err != nil {
			return nil, nil, err
		}
		if _, exists := ids[id]; exists {
			return nil, nil, invalid("duplicate_id", "vocabulary")
		}
		if err := validTermKind(value.Kind, path+"kind"); err != nil {
			return nil, nil, err
		}
		label, err := canonicalText(value.Label, path+"label", false, false)
		if err != nil {
			return nil, nil, err
		}
		definition, err := canonicalText(value.Definition, path+"definition", false, true)
		if err != nil {
			return nil, nil, err
		}
		ids[id] = struct{}{}
		result[index] = VocabularyTerm{TermID: id, Kind: value.Kind, Label: label, Definition: definition}
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].TermID < result[right].TermID })
	return result, ids, nil
}

func normalizeProfiles(values []Profile) ([]Profile, map[string]Profile, error) {
	result := make([]Profile, len(values))
	byID := make(map[string]Profile, len(values))
	for index, value := range values {
		path := indexed("profiles", index, "")
		id, err := canonicalID(value.ProfileID, "RPROF-", path+"profileId")
		if err != nil {
			return nil, nil, err
		}
		if _, exists := byID[id]; exists {
			return nil, nil, invalid("duplicate_id", "profiles")
		}
		fields, err := normalizeMetadataFields(value.Fields, path+"fields")
		if err != nil {
			return nil, nil, err
		}
		if metadataFieldCount(fields) == 0 {
			return nil, nil, invalid("empty_profile", path+"fields")
		}
		profile := Profile{ProfileID: id, Fields: fields}
		result[index] = profile
		byID[id] = profile
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].ProfileID < result[right].ProfileID })
	return result, byID, nil
}

func normalizeDerivations(values []Derivation, requirements map[string]AtomicRequirement) ([]Derivation, error) {
	result := make([]Derivation, len(values))
	ids := make(map[string]struct{}, len(values))
	for index, value := range values {
		path := indexed("derivations", index, "")
		id, err := canonicalID(value.DerivationID, "DRV-", path+"derivationId")
		if err != nil {
			return nil, err
		}
		if _, exists := ids[id]; exists {
			return nil, invalid("duplicate_id", "derivations")
		}
		if err := validSourceKind(value.SourceKind, path+"sourceKind"); err != nil {
			return nil, err
		}
		sourceRef, err := normalizeGitBlobRef(value.SourceRef, path+"sourceRef")
		if err != nil {
			return nil, err
		}
		if value.Selector.Start < 0 || value.Selector.End <= value.Selector.Start {
			return nil, invalid("invalid_byte_range", path+"selector")
		}
		requirementIDs, err := normalizeIDs(value.RequirementIDs, "REQ-", path+"requirementIds", false)
		if err != nil {
			return nil, err
		}
		for _, requirementID := range requirementIDs {
			if _, exists := requirements[requirementID]; !exists {
				return nil, invalid("dangling_requirement_ref", path+"requirementIds")
			}
		}
		nonClaimRefs, err := normalizeIDs(value.NonClaimRefs, "NCL-", path+"nonClaimRefs", true)
		if err != nil {
			return nil, err
		}
		ids[id] = struct{}{}
		result[index] = Derivation{
			DerivationID:   id,
			SourceKind:     value.SourceKind,
			SourceRef:      sourceRef,
			Selector:       value.Selector,
			RequirementIDs: requirementIDs,
			NonClaimRefs:   nonClaimRefs,
		}
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].DerivationID < result[right].DerivationID })
	return result, nil
}

func normalizeGitBlobRef(value GitBlobRef, path string) (GitBlobRef, error) {
	if err := validObjectFormat(value.ObjectFormat, path+".objectFormat"); err != nil {
		return GitBlobRef{}, err
	}
	expectedLength := 40
	if value.ObjectFormat == ObjectSHA256 {
		expectedLength = 64
	}
	if len(value.CommitOID) != expectedLength || strings.ToLower(value.CommitOID) != value.CommitOID || strings.Trim(value.CommitOID, "0123456789abcdef") != "" {
		return GitBlobRef{}, invalid("invalid_commit_oid", path+".commitOid")
	}
	refPath, err := canonicalPath(value.Path, path+".path")
	if err != nil {
		return GitBlobRef{}, err
	}
	digest, err := admit.LowercaseSHA256(value.SHA256, path+".sha256")
	if err != nil {
		return GitBlobRef{}, invalid("invalid_sha256", path+".sha256")
	}
	return GitBlobRef{ObjectFormat: value.ObjectFormat, CommitOID: value.CommitOID, Path: refPath, SHA256: digest}, nil
}
