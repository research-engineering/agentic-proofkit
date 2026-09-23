package requirementsourcemodel

import "sort"

func normalizeGroups(values []Group, profiles map[string]Profile) ([]Group, []AtomicRequirement, []Origin, map[string]int, error) {
	groups := make([]Group, len(values))
	groupIDs := make(map[string]struct{}, len(values))
	requirementIDs := map[string]struct{}{}
	// NormalizeWithLimits has already bounded the complete snapshot membership.
	memberCount := 0
	for _, group := range values {
		memberCount += len(group.Members)
	}
	requirements := make([]AtomicRequirement, 0, memberCount)
	origins := make([]Origin, 0, memberCount)
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
				invariant, err = canonicalText(stem+" "+completion, memberPath+"statementCompletion", false, true)
				if err != nil {
					return nil, nil, nil, nil, err
				}
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
			return invalid("vacuous_profile", identified("profiles", profile.ProfileID))
		}
	}
	return nil
}

func requirementLifecycleViolations(requirements []AtomicRequirement, byID map[string]AtomicRequirement) []PolicyViolation {
	var violations []PolicyViolation
	for _, requirement := range requirements {
		path := identified("requirements", requirement.RequirementID)
		add := func(code, field, related string) {
			violations = append(violations, PolicyViolation{Code: code, Path: path + field,
				RequirementID: requirement.RequirementID, RelatedRequirementID: related})
		}
		if requirement.ClaimLevel == ClaimDeferred && requirement.Deferral == nil {
			add("missing_deferral", ".deferral", "")
		}
		if requirement.ClaimLevel != ClaimDeferred && requirement.Deferral != nil {
			add("unexpected_deferral", ".deferral", "")
		}
		if requirement.Lifecycle.State != LifecycleActive && len(requirement.Lifecycle.EvidenceRefs) == 0 {
			add("missing_lifecycle_evidence", ".lifecycle.evidenceRefs", "")
		}
		if requirement.Lifecycle.State == LifecycleSuperseded && len(requirement.Lifecycle.ReplacementRequirementIDs) == 0 {
			add("missing_replacement", ".lifecycle.replacementRequirementIds", "")
		}
		if requirement.Lifecycle.State != LifecycleSuperseded && len(requirement.Lifecycle.ReplacementRequirementIDs) != 0 {
			add("unexpected_replacement", ".lifecycle.replacementRequirementIds", "")
		}
		if requirement.ClaimLevel == ClaimBlocking && requirement.Lifecycle.State != LifecycleActive {
			add("nonactive_blocking_requirement", ".claimLevel", "")
		}
		if requirement.ClaimLevel == ClaimBlocking && requirement.Lifecycle.State == LifecycleActive {
			if len(requirement.ProofBindingRefs) == 0 {
				add("missing_proof_binding", ".proofBindingRefs", "")
			}
			if !requirement.UpdatePolicy.RequiresImpactDeclaration {
				add("impact_review_required", ".updatePolicy.requiresImpactDeclaration", "")
			}
			if !requirement.UpdatePolicy.RequiresProofBindingReview {
				add("proof_binding_review_required", ".updatePolicy.requiresProofBindingReview", "")
			}
		}
		for _, replacementID := range requirement.Lifecycle.ReplacementRequirementIDs {
			if replacementID == requirement.RequirementID {
				add("self_replacement", ".lifecycle.replacementRequirementIds", replacementID)
			}
			replacement, exists := byID[replacementID]
			if !exists {
				add("dangling_replacement", ".lifecycle.replacementRequirementIds", replacementID)
				continue
			}
			if replacement.Lifecycle.State != LifecycleActive {
				add("inactive_replacement", ".lifecycle.replacementRequirementIds", replacementID)
			}
		}
	}
	return violations
}
