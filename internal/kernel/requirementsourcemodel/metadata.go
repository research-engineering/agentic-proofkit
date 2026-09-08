package requirementsourcemodel

import "reflect"

var metadataFieldIDs = []MetadataFieldID{
	"claimLevel",
	"deferral",
	"externalNonClaimRefs",
	"lifecycle",
	"nonClaimRefs",
	"nonClaims",
	"ownerId",
	"proofBindingRefs",
	"riskClass",
	"updatePolicy",
}

func normalizeMetadataFields(value MetadataFields, path string) (MetadataFields, error) {
	if err := rejectHiddenMetadataValues(value, path); err != nil {
		return MetadataFields{}, err
	}
	result := value
	var err error
	if value.NonClaims.Present {
		result.NonClaims.Value, err = normalizeTexts(value.NonClaims.Value, path+".nonClaims", true, false)
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.ExternalNonClaimRefs.Present {
		result.ExternalNonClaimRefs.Value, err = normalizeIDs(value.ExternalNonClaimRefs.Value, "", path+".externalNonClaimRefs", true)
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.ProofBindingRefs.Present {
		result.ProofBindingRefs.Value, err = normalizePaths(value.ProofBindingRefs.Value, path+".proofBindingRefs", true)
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.OwnerID.Present {
		result.OwnerID.Value, err = canonicalExternalID(value.OwnerID.Value, path+".ownerId")
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.ClaimLevel.Present {
		if err := validClaimLevel(value.ClaimLevel.Value, path+".claimLevel"); err != nil {
			return MetadataFields{}, err
		}
	}
	if value.RiskClass.Present {
		if err := validRiskClass(value.RiskClass.Value, path+".riskClass"); err != nil {
			return MetadataFields{}, err
		}
	}
	if value.NonClaimRefs.Present {
		result.NonClaimRefs.Value, err = normalizeIDs(value.NonClaimRefs.Value, "NCL-", path+".nonClaimRefs", true)
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.Lifecycle.Present {
		result.Lifecycle.Value, err = normalizeLifecycle(value.Lifecycle.Value, path+".lifecycle")
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.Deferral.Present && value.Deferral.Value != nil {
		result.Deferral.Value, err = normalizeDeferral(value.Deferral.Value, path+".deferral")
		if err != nil {
			return MetadataFields{}, err
		}
	}
	if value.UpdatePolicy.Present {
		result.UpdatePolicy.Value, err = normalizeUpdatePolicy(value.UpdatePolicy.Value, path+".updatePolicy")
		if err != nil {
			return MetadataFields{}, err
		}
	}
	return result, nil
}

func rejectHiddenMetadataValues(value MetadataFields, path string) error {
	checks := []struct {
		present bool
		value   any
		zero    any
		field   string
	}{
		{value.NonClaims.Present, value.NonClaims.Value, []string(nil), "nonClaims"},
		{value.ExternalNonClaimRefs.Present, value.ExternalNonClaimRefs.Value, []string(nil), "externalNonClaimRefs"},
		{value.ProofBindingRefs.Present, value.ProofBindingRefs.Value, []string(nil), "proofBindingRefs"},
		{value.OwnerID.Present, value.OwnerID.Value, "", "ownerId"},
		{value.ClaimLevel.Present, value.ClaimLevel.Value, ClaimLevel(""), "claimLevel"},
		{value.RiskClass.Present, value.RiskClass.Value, RiskClass(""), "riskClass"},
		{value.NonClaimRefs.Present, value.NonClaimRefs.Value, []string(nil), "nonClaimRefs"},
		{value.Lifecycle.Present, value.Lifecycle.Value, Lifecycle{}, "lifecycle"},
		{value.Deferral.Present, value.Deferral.Value, (*Deferral)(nil), "deferral"},
		{value.UpdatePolicy.Present, value.UpdatePolicy.Value, UpdatePolicy{}, "updatePolicy"},
	}
	for _, check := range checks {
		if !check.present && !reflect.DeepEqual(check.value, check.zero) {
			return invalid("hidden_field_payload", path+"."+check.field)
		}
	}
	return nil
}

func normalizeLifecycle(value Lifecycle, path string) (Lifecycle, error) {
	if err := validLifecycleState(value.State, path+".state"); err != nil {
		return Lifecycle{}, err
	}
	replacements, err := normalizeIDs(value.ReplacementRequirementIDs, "REQ-", path+".replacementRequirementIds", true)
	if err != nil {
		return Lifecycle{}, err
	}
	evidence, err := normalizePaths(value.EvidenceRefs, path+".evidenceRefs", true)
	if err != nil {
		return Lifecycle{}, err
	}
	return Lifecycle{State: value.State, ReplacementRequirementIDs: replacements, EvidenceRefs: evidence}, nil
}

func normalizeDeferral(value *Deferral, path string) (*Deferral, error) {
	ownerID, err := canonicalExternalID(value.OwnerID, path+".ownerId")
	if err != nil {
		return nil, err
	}
	riskAcceptedBy, err := canonicalExternalID(value.RiskAcceptedBy, path+".riskAcceptedBy")
	if err != nil {
		return nil, err
	}
	reviewCondition, err := canonicalText(value.ReviewCondition, path+".reviewCondition", false, false)
	if err != nil {
		return nil, err
	}
	expiryRef, err := canonicalExternalID(value.ExpiryRef, path+".expiryRef")
	if err != nil {
		return nil, err
	}
	mergePolicy, err := canonicalExternalID(value.MergePolicy, path+".mergePolicy")
	if err != nil {
		return nil, err
	}
	evidence, err := normalizePaths(value.EvidenceRefs, path+".evidenceRefs", false)
	if err != nil {
		return nil, err
	}
	return &Deferral{
		OwnerID:         ownerID,
		RiskAcceptedBy:  riskAcceptedBy,
		ReviewCondition: reviewCondition,
		ExpiryRef:       expiryRef,
		MergePolicy:     mergePolicy,
		EvidenceRefs:    evidence,
	}, nil
}

func normalizeUpdatePolicy(value UpdatePolicy, path string) (UpdatePolicy, error) {
	reviewOwnerID, err := canonicalExternalID(value.ReviewOwnerID, path+".reviewOwnerId")
	if err != nil {
		return UpdatePolicy{}, err
	}
	value.ReviewOwnerID = reviewOwnerID
	return value, nil
}

func metadataFieldCount(value MetadataFields) int {
	count := 0
	for _, present := range metadataPresence(value) {
		if present {
			count++
		}
	}
	return count
}

func metadataPresence(value MetadataFields) map[MetadataFieldID]bool {
	return map[MetadataFieldID]bool{
		"nonClaims":            value.NonClaims.Present,
		"externalNonClaimRefs": value.ExternalNonClaimRefs.Present,
		"proofBindingRefs":     value.ProofBindingRefs.Present,
		"ownerId":              value.OwnerID.Present,
		"claimLevel":           value.ClaimLevel.Present,
		"riskClass":            value.RiskClass.Present,
		"nonClaimRefs":         value.NonClaimRefs.Present,
		"lifecycle":            value.Lifecycle.Present,
		"deferral":             value.Deferral.Present,
		"updatePolicy":         value.UpdatePolicy.Present,
	}
}

func resolveMetadata(profileID string, memberID string, profile MetadataFields, member MetadataFields, path string) (AtomicRequirement, []FieldOwner, error) {
	profilePresence := metadataPresence(profile)
	memberPresence := metadataPresence(member)
	for _, fieldID := range metadataFieldIDs {
		if profilePresence[fieldID] == memberPresence[fieldID] {
			return AtomicRequirement{}, nil, invalid("metadata_partition_violation", path+"."+string(fieldID))
		}
	}
	owners := make([]FieldOwner, 0, len(metadataFieldIDs))
	ownerFor := func(fieldID MetadataFieldID) (MetadataOwnerKind, string) {
		if profilePresence[fieldID] {
			return MetadataOwnerProfile, profileID
		}
		return MetadataOwnerMember, memberID
	}
	for _, fieldID := range metadataFieldIDs {
		ownerKind, ownerID := ownerFor(fieldID)
		owners = append(owners, FieldOwner{FieldID: fieldID, OwnerKind: ownerKind, OwnerID: ownerID})
	}
	result := AtomicRequirement{}
	if profile.NonClaims.Present {
		result.NonClaims = cloneStrings(profile.NonClaims.Value)
	} else {
		result.NonClaims = cloneStrings(member.NonClaims.Value)
	}
	if profile.ExternalNonClaimRefs.Present {
		result.ExternalNonClaimRefs = cloneStrings(profile.ExternalNonClaimRefs.Value)
	} else {
		result.ExternalNonClaimRefs = cloneStrings(member.ExternalNonClaimRefs.Value)
	}
	if profile.ProofBindingRefs.Present {
		result.ProofBindingRefs = cloneStrings(profile.ProofBindingRefs.Value)
	} else {
		result.ProofBindingRefs = cloneStrings(member.ProofBindingRefs.Value)
	}
	if profile.OwnerID.Present {
		result.OwnerID = profile.OwnerID.Value
	} else {
		result.OwnerID = member.OwnerID.Value
	}
	if profile.ClaimLevel.Present {
		result.ClaimLevel = profile.ClaimLevel.Value
	} else {
		result.ClaimLevel = member.ClaimLevel.Value
	}
	if profile.RiskClass.Present {
		result.RiskClass = profile.RiskClass.Value
	} else {
		result.RiskClass = member.RiskClass.Value
	}
	if profile.NonClaimRefs.Present {
		result.NonClaimRefs = cloneStrings(profile.NonClaimRefs.Value)
	} else {
		result.NonClaimRefs = cloneStrings(member.NonClaimRefs.Value)
	}
	if profile.Lifecycle.Present {
		result.Lifecycle = cloneLifecycle(profile.Lifecycle.Value)
	} else {
		result.Lifecycle = cloneLifecycle(member.Lifecycle.Value)
	}
	if profile.Deferral.Present {
		result.Deferral = cloneDeferral(profile.Deferral.Value)
	} else {
		result.Deferral = cloneDeferral(member.Deferral.Value)
	}
	if profile.UpdatePolicy.Present {
		result.UpdatePolicy = profile.UpdatePolicy.Value
	} else {
		result.UpdatePolicy = member.UpdatePolicy.Value
	}
	return result, owners, nil
}
