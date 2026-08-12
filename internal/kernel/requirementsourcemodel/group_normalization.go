package requirementsourcemodel

import "sort"

func normalizeGroups(values []Group, profiles map[string]Profile) ([]Group, []AtomicRequirement, []Origin, map[string]int, error) {
	groups := make([]Group, len(values))
	groupIDs := make(map[string]struct{}, len(values))
	requirementIDs := map[string]struct{}{}
	requirements := []AtomicRequirement{}
	origins := []Origin{}
	profileUses := map[string]int{}

	for groupIndex, value := range values {
		path := indexed("groups", groupIndex, "")
		groupID, err := canonicalID(value.GroupID, "RGRP-", path+"groupId")
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if _, exists := groupIDs[groupID]; exists {
			return nil, nil, nil, nil, invalid("duplicate_id", "groups")
		}
		groupIDs[groupID] = struct{}{}

		profileID := ""
		profileFields := MetadataFields{}
		if value.ProfileID != "" {
			profileID, err = canonicalID(value.ProfileID, "RPROF-", path+"profileId")
			if err != nil {
				return nil, nil, nil, nil, err
			}
			profile, exists := profiles[profileID]
			if !exists {
				return nil, nil, nil, nil, invalid("dangling_profile_ref", path+"profileId")
			}
			profileFields = profile.Fields
			profileUses[profileID] += len(value.Members)
		}

		stem, err := canonicalText(value.StatementStem, path+"statementStem", true, true)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if stem != "" && len(value.Members) < 2 {
			return nil, nil, nil, nil, invalid("vacuous_group_stem", path+"statementStem")
		}
		premises, err := normalizeTexts(value.SharedPremises, path+"sharedPremises", true, true)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		members := make([]Member, len(value.Members))
		for memberIndex, memberValue := range value.Members {
			memberPath := indexed(path+"members", memberIndex, "")
			requirementID, err := canonicalID(memberValue.RequirementID, "REQ-", memberPath+"requirementId")
			if err != nil {
				return nil, nil, nil, nil, err
			}
			if _, exists := requirementIDs[requirementID]; exists {
				return nil, nil, nil, nil, invalid("duplicate_requirement_id", "groups.members")
			}
			requirementIDs[requirementID] = struct{}{}
			completion, err := canonicalText(memberValue.StatementCompletion, memberPath+"statementCompletion", false, true)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			fields, err := normalizeMetadataFields(memberValue.Fields, memberPath+"fields")
			if err != nil {
				return nil, nil, nil, nil, err
			}
			resolved, fieldOwners, err := resolveMetadata(profileID, requirementID, profileFields, fields, memberPath+"fields")
			if err != nil {
				return nil, nil, nil, nil, err
			}
			invariant := completion
			if stem != "" {
				invariant = stem + " " + completion
			}
			resolved.RequirementID = requirementID
			resolved.Invariant = invariant
			resolved.SharedPremises = cloneStrings(premises)
			requirements = append(requirements, resolved)
			origins = append(origins, Origin{
				RequirementID: requirementID,
				GroupID:       groupID,
				ProfileID:     profileID,
				FieldOwners:   fieldOwners,
			})
			members[memberIndex] = Member{RequirementID: requirementID, StatementCompletion: completion, Fields: fields}
		}
		sort.Slice(members, func(left int, right int) bool { return members[left].RequirementID < members[right].RequirementID })
		groups[groupIndex] = Group{
			GroupID:        groupID,
			ProfileID:      profileID,
			StatementStem:  stem,
			SharedPremises: premises,
			Members:        members,
		}
	}

	sort.Slice(groups, func(left int, right int) bool { return groups[left].GroupID < groups[right].GroupID })
	sort.Slice(requirements, func(left int, right int) bool {
		return requirements[left].RequirementID < requirements[right].RequirementID
	})
	sort.Slice(origins, func(left int, right int) bool { return origins[left].RequirementID < origins[right].RequirementID })
	return groups, requirements, origins, profileUses, nil
}

func validateProfileUses(profiles []Profile, uses map[string]int) error {
	for _, profile := range profiles {
		if uses[profile.ProfileID] < 2 {
			return invalid("vacuous_profile", "profiles."+profile.ProfileID)
		}
	}
	return nil
}

func validateRequirementLifecycles(requirements []AtomicRequirement, byID map[string]AtomicRequirement) error {
	for _, requirement := range requirements {
		path := "requirements." + requirement.RequirementID
		if requirement.ClaimLevel == ClaimDeferred && requirement.Deferral == nil {
			return invalid("missing_deferral", path+".deferral")
		}
		if requirement.ClaimLevel != ClaimDeferred && requirement.Deferral != nil {
			return invalid("unexpected_deferral", path+".deferral")
		}
		if requirement.Lifecycle.State != LifecycleActive && len(requirement.Lifecycle.EvidenceRefs) == 0 {
			return invalid("missing_lifecycle_evidence", path+".lifecycle.evidenceRefs")
		}
		if requirement.Lifecycle.State == LifecycleSuperseded && len(requirement.Lifecycle.ReplacementRequirementIDs) == 0 {
			return invalid("missing_replacement", path+".lifecycle.replacementRequirementIds")
		}
		if requirement.Lifecycle.State != LifecycleSuperseded && len(requirement.Lifecycle.ReplacementRequirementIDs) != 0 {
			return invalid("unexpected_replacement", path+".lifecycle.replacementRequirementIds")
		}
		if requirement.ClaimLevel == ClaimBlocking && requirement.Lifecycle.State != LifecycleActive {
			return invalid("nonactive_blocking_requirement", path+".claimLevel")
		}
		if requirement.ClaimLevel == ClaimBlocking && requirement.Lifecycle.State == LifecycleActive {
			if !requirement.UpdatePolicy.RequiresImpactDeclaration {
				return invalid("impact_review_required", path+".updatePolicy.requiresImpactDeclaration")
			}
			if !requirement.UpdatePolicy.RequiresProofBindingReview {
				return invalid("proof_binding_review_required", path+".updatePolicy.requiresProofBindingReview")
			}
		}
		for _, replacementID := range requirement.Lifecycle.ReplacementRequirementIDs {
			if replacementID == requirement.RequirementID {
				return invalid("self_replacement", path+".lifecycle.replacementRequirementIds")
			}
			replacement, exists := byID[replacementID]
			if !exists {
				return invalid("dangling_replacement", path+".lifecycle.replacementRequirementIds")
			}
			if replacement.Lifecycle.State != LifecycleActive {
				return invalid("inactive_replacement", path+".lifecycle.replacementRequirementIds")
			}
		}
	}
	return nil
}
