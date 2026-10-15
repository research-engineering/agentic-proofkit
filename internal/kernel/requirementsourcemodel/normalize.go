package requirementsourcemodel

import (
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// Normalize admits a detached model. Callers must not mutate draft's shared
// slices or maps until this call returns.
func Normalize(draft Draft) (Model, error) {
	return NormalizeWithLimits(draft, DefaultLimits())
}

// NormalizeWithLimits uses the same borrowed-input contract as Normalize.
func NormalizeWithLimits(draft Draft, limits Limits) (Model, error) {
	assessment, err := normalizeSource(draft, limits, false)
	if err != nil {
		return Model{}, err
	}
	return assessment.model, nil
}

func normalizeSource(draft Draft, limits Limits, collectPolicyFailures bool) (Assessment, error) {
	if err := ValidateLimits(limits); err != nil {
		return Assessment{}, err
	}
	if err := preflight(draft, limits); err != nil {
		return Assessment{}, err
	}
	snapshot := cloneDraft(draft)
	if err := preflight(snapshot, limits); err != nil {
		return Assessment{}, err
	}

	// Phases collect independent entity faults. A dependent phase runs only
	// over declared identities, so an earlier fault cannot invent a later one.
	var problems validationCollector
	sourceID, err := canonicalExternalID(snapshot.SourceID, "sourceId")
	problems.add(err)
	specPackagePath, err := canonicalPath(snapshot.SpecPackagePath, "specPackagePath")
	problems.add(err)
	sourceNonClaimRefs, refsErr := normalizeIDs(snapshot.SourceNonClaimRefs, "NCL-", "sourceNonClaimRefs", true)
	problems.add(refsErr)
	sourceNonClaims, textsErr := normalizeTexts(snapshot.SourceNonClaims, "sourceNonClaims", true, false)
	problems.add(textsErr)
	if refsErr == nil && textsErr == nil && len(sourceNonClaims) == 0 && len(sourceNonClaimRefs) == 0 {
		problems.add(invalid("empty_source_nonclaims", "sourceNonClaims"))
	}

	definitions, definitionIDs, err := normalizeDefinitions(snapshot.NonClaimDefinitions)
	problems.add(err)
	vocabulary, vocabularyIDs, err := normalizeVocabulary(snapshot.Vocabulary)
	problems.add(err)
	profiles, profilesByID, err := normalizeProfiles(snapshot.Profiles)
	problems.add(err)
	if err != nil || problems.fatal != nil {
		// Group metadata resolution depends on every admitted profile.
		return Assessment{}, problems.err()
	}
	groups, requirements, origins, profileUses, declaredRequirementIDs, err := normalizeGroups(snapshot.Groups, profilesByID)
	problems.add(err)
	var violations []PolicyViolation
	if err == nil {
		problems.add(validateProfileUses(profiles, profileUses))
		requirementsByID := make(map[string]AtomicRequirement, len(requirements))
		for _, requirement := range requirements {
			requirementsByID[requirement.RequirementID] = requirement
		}
		violations = requirementLifecycleViolations(requirements, requirementsByID)
		if !collectPolicyFailures && len(violations) != 0 {
			// Strict normalization keeps its first-policy-fault classification;
			// Assess reports every policy occurrence in its admitted report.
			problems.add(invalid(violations[0].Code, violations[0].Path))
		}
	}

	scenarios, err := normalizeScenarios(snapshot.Scenarios, declaredRequirementIDs, vocabularyIDs)
	problems.add(err)
	derivations, err := normalizeDerivations(snapshot.Derivations, declaredRequirementIDs)
	problems.add(err)
	if problems.failed() {
		return Assessment{}, problems.err()
	}
	edges := buildReferenceEdges(sourceID, sourceNonClaimRefs, groups, requirements, scenarios, derivations)
	if err := validateReferenceClosure(definitionIDs, vocabularyIDs, edges); err != nil {
		return Assessment{}, err
	}
	if err := validateNonClaimScopes(sourceNonClaims, sourceNonClaimRefs, definitions, requirements); err != nil {
		return Assessment{}, err
	}

	atomic := AtomicProjection{
		SourceID:            sourceID,
		SpecPackagePath:     specPackagePath,
		SourceNonClaims:     sourceNonClaims,
		SourceNonClaimRefs:  sourceNonClaimRefs,
		NonClaimDefinitions: definitions,
		Vocabulary:          vocabulary,
		Requirements:        requirements,
		Scenarios:           scenarios,
	}
	layout := LayoutProjection{SourceID: sourceID, Profiles: profiles, Groups: groups, Origins: origins}
	references := ReferenceProjection{SourceID: sourceID, Derivations: derivations, Edges: edges}
	// Atomic and layout values belong to this detached snapshot; accessors copy
	// them on exit. Reference cloning also trims its append-built edge storage.
	model := Model{
		atomic:     atomic,
		layout:     layout,
		references: cloneReferenceProjection(references),
	}
	if !collectPolicyFailures {
		return Assessment{model: model, admitted: true}, nil
	}
	return sourceAssessment(model, violations), nil
}

func normalizeDefinitions(values []NonClaimDefinition) ([]NonClaimDefinition, map[string]struct{}, error) {
	result := make([]NonClaimDefinition, len(values))
	ids := make(map[string]struct{}, len(values))
	var problems validationCollector
	for index, value := range values {
		path := indexed("nonClaimDefinitions", index, "")
		id, err := canonicalID(value.NonClaimID, "NCL-", path+"nonClaimId")
		if err != nil {
			problems.add(err)
			continue
		}
		if _, exists := ids[id]; exists {
			problems.add(invalid("duplicate_id", path+"nonClaimId"))
			continue
		}
		ids[id] = struct{}{}
		statement, err := canonicalText(value.Statement, path+"statement", false, false)
		if err != nil {
			problems.add(err)
			continue
		}
		result[index] = NonClaimDefinition{NonClaimID: id, Statement: statement}
	}
	if problems.failed() {
		return nil, ids, problems.err()
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].NonClaimID < result[right].NonClaimID })
	return result, ids, nil
}

// normalizeVocabulary returns every declared term identity, even on failure,
// so scenario references are not reported as dangling because of a term fault.
func normalizeVocabulary(values []VocabularyTerm) ([]VocabularyTerm, map[string]struct{}, error) {
	result := make([]VocabularyTerm, len(values))
	ids := make(map[string]struct{}, len(values))
	var problems validationCollector
	for index, value := range values {
		path := indexed("vocabulary", index, "")
		id, err := canonicalID(value.TermID, "TERM-", path+"termId")
		if err != nil {
			problems.add(err)
			continue
		}
		if _, exists := ids[id]; exists {
			problems.add(invalid("duplicate_id", path+"termId"))
			continue
		}
		ids[id] = struct{}{}
		if err := validTermKind(value.Kind, path+"kind"); err != nil {
			problems.add(err)
			continue
		}
		label, err := canonicalText(value.Label, path+"label", false, false)
		if err != nil {
			problems.add(err)
			continue
		}
		definition, err := canonicalText(value.Definition, path+"definition", false, true)
		if err != nil {
			problems.add(err)
			continue
		}
		result[index] = VocabularyTerm{TermID: id, Kind: value.Kind, Label: label, Definition: definition}
	}
	if problems.failed() {
		return nil, ids, problems.err()
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].TermID < result[right].TermID })
	return result, ids, nil
}

func normalizeProfiles(values []Profile) ([]Profile, map[string]Profile, error) {
	result := make([]Profile, len(values))
	byID := make(map[string]Profile, len(values))
	var problems validationCollector
	for index, value := range values {
		path := indexed("profiles", index, "")
		id, err := canonicalID(value.ProfileID, "RPROF-", path+"profileId")
		if err != nil {
			problems.add(err)
			continue
		}
		if _, exists := byID[id]; exists {
			problems.add(invalid("duplicate_id", path+"profileId"))
			continue
		}
		byID[id] = Profile{ProfileID: id}
		fields, err := normalizeMetadataFields(value.Fields, path+"fields")
		if err != nil {
			problems.add(err)
			continue
		}
		if metadataFieldCount(fields) == 0 {
			problems.add(invalid("empty_profile", path+"fields"))
			continue
		}
		profile := Profile{ProfileID: id, Fields: fields}
		result[index] = profile
		byID[id] = profile
	}
	if problems.failed() {
		return nil, nil, problems.err()
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].ProfileID < result[right].ProfileID })
	return result, byID, nil
}

func normalizeDerivations(values []Derivation, requirements map[string]struct{}) ([]Derivation, error) {
	result := make([]Derivation, len(values))
	ids := make(map[string]struct{}, len(values))
	var problems validationCollector
	for index, value := range values {
		path := indexed("derivations", index, "")
		id, err := canonicalID(value.DerivationID, "DRV-", path+"derivationId")
		if err != nil {
			problems.add(err)
			continue
		}
		if _, exists := ids[id]; exists {
			problems.add(invalid("duplicate_id", path+"derivationId"))
			continue
		}
		ids[id] = struct{}{}
		derivation, err := normalizeDerivation(value, id, path, requirements)
		if err != nil {
			problems.add(err)
			continue
		}
		result[index] = derivation
	}
	if problems.failed() {
		return nil, problems.err()
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].DerivationID < result[right].DerivationID })
	return result, nil
}

func normalizeDerivation(value Derivation, id string, path string, requirements map[string]struct{}) (Derivation, error) {
	if err := validSourceKind(value.SourceKind, path+"sourceKind"); err != nil {
		return Derivation{}, err
	}
	sourceRef, err := normalizeGitBlobRef(value.SourceRef, path+"sourceRef")
	if err != nil {
		return Derivation{}, err
	}
	if value.Selector.Start < 0 || value.Selector.End <= value.Selector.Start {
		return Derivation{}, invalid("invalid_byte_range", path+"selector")
	}
	requirementIDs, err := normalizeIDs(value.RequirementIDs, "REQ-", path+"requirementIds", false)
	if err != nil {
		return Derivation{}, err
	}
	for _, requirementID := range requirementIDs {
		if _, exists := requirements[requirementID]; !exists {
			return Derivation{}, invalid("dangling_requirement_ref", path+"requirementIds")
		}
	}
	nonClaimRefs, err := normalizeIDs(value.NonClaimRefs, "NCL-", path+"nonClaimRefs", true)
	if err != nil {
		return Derivation{}, err
	}
	return Derivation{
		DerivationID:   id,
		SourceKind:     value.SourceKind,
		SourceRef:      sourceRef,
		Selector:       value.Selector,
		RequirementIDs: requirementIDs,
		NonClaimRefs:   nonClaimRefs,
	}, nil
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
