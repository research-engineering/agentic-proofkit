package requirementsourcemodel

import "sort"

// normalizeGroups returns every declared requirement identity, even on
// failure, so dependent scenario and derivation references stay checkable.
func normalizeGroups(values []Group, profiles map[string]Profile) ([]Group, []AtomicRequirement, []Origin, map[string]int, map[string]struct{}, error) {
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
	var problems validationCollector

	for groupIndex, value := range values {
		path := indexed("groups", groupIndex, "")
		// Member resolution consumes the admitted group ID, profile and stem.
		groupAdmitted := true
		groupID, err := canonicalID(value.GroupID, "RGRP-", path+"groupId")
		if err != nil {
			problems.add(err)
			groupAdmitted = false
		} else if _, exists := groupIDs[groupID]; exists {
			problems.add(invalid("duplicate_id", path+"groupId"))
			groupAdmitted = false
		} else {
			groupIDs[groupID] = struct{}{}
		}

		profileID := ""
		profileFields := MetadataFields{}
		if value.ProfileID != "" {
			profileID, err = canonicalID(value.ProfileID, "RPROF-", path+"profileId")
			if err != nil {
				problems.add(err)
				groupAdmitted = false
			} else if profile, exists := profiles[profileID]; !exists {
				problems.add(invalid("dangling_profile_ref", path+"profileId"))
				groupAdmitted = false
			} else {
				profileFields = profile.Fields
				profileUses[profileID] += len(value.Members)
			}
		}

		stem, err := canonicalText(value.StatementStem, path+"statementStem", true, true)
		if err != nil {
			problems.add(err)
			groupAdmitted = false
		} else if stem != "" && len(value.Members) < 2 {
			problems.add(invalid("vacuous_group_stem", path+"statementStem"))
		}
		premises, err := normalizeTexts(value.SharedPremises, path+"sharedPremises", true, true)
		if err != nil {
			problems.add(err)
		}

		members := make([]Member, len(value.Members))
		for memberIndex, memberValue := range value.Members {
			memberPath := indexed(path+"members", memberIndex, "")
			requirementID, err := canonicalID(memberValue.RequirementID, "REQ-", memberPath+"requirementId")
			if err != nil {
				problems.add(err)
				continue
			}
			if _, exists := requirementIDs[requirementID]; exists {
				problems.add(invalid("duplicate_requirement_id", memberPath+"requirementId"))
				continue
			}
			requirementIDs[requirementID] = struct{}{}
			completion, err := canonicalText(memberValue.StatementCompletion, memberPath+"statementCompletion", false, true)
			if err != nil {
				problems.add(err)
				continue
			}
			fields, err := normalizeMetadataFields(memberValue.Fields, memberPath+"fields")
			if err != nil {
				problems.add(err)
				continue
			}
			if !groupAdmitted {
				continue
			}
			resolved, fieldOwners, err := resolveMetadata(profileID, requirementID, profileFields, fields, memberPath+"fields")
			if err != nil {
				problems.add(err)
				continue
			}
			invariant := completion
			if stem != "" {
				invariant, err = canonicalText(stem+" "+completion, memberPath+"statementCompletion", false, true)
				if err != nil {
					problems.add(err)
					continue
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
		if problems.failed() {
			continue
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
	if problems.failed() {
		return nil, nil, nil, nil, requirementIDs, problems.err()
	}

	sort.Slice(groups, func(left int, right int) bool { return groups[left].GroupID < groups[right].GroupID })
	sort.Slice(requirements, func(left int, right int) bool {
		return requirements[left].RequirementID < requirements[right].RequirementID
	})
	sort.Slice(origins, func(left int, right int) bool { return origins[left].RequirementID < origins[right].RequirementID })
	return groups, requirements, origins, profileUses, requirementIDs, nil
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
