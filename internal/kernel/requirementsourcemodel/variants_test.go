package requirementsourcemodel

import (
	"testing"
)

func TestNormalizeAdmitsEveryDeclaredEnumVariantThroughWholeModel(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Draft)
	}{
		{name: "claim advisory", edit: func(draft *Draft) { setSingletonClaim(draft, ClaimAdvisory) }},
		{name: "claim blocking", edit: func(draft *Draft) { setSingletonClaim(draft, ClaimBlocking) }},
		{name: "claim deferred", edit: func(draft *Draft) { setSingletonClaim(draft, ClaimDeferred) }},
		{name: "risk critical", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.RiskClass.Value = RiskCritical }},
		{name: "risk high", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.RiskClass.Value = RiskHigh }},
		{name: "risk low", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.RiskClass.Value = RiskLow }},
		{name: "risk medium", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.RiskClass.Value = RiskMedium }},
		{name: "lifecycle active", edit: func(draft *Draft) { setSingletonLifecycle(draft, LifecycleActive) }},
		{name: "lifecycle deprecated", edit: func(draft *Draft) { setSingletonLifecycle(draft, LifecycleDeprecated) }},
		{name: "lifecycle removed", edit: func(draft *Draft) { setSingletonLifecycle(draft, LifecycleRemoved) }},
		{name: "lifecycle superseded", edit: func(draft *Draft) { setSingletonLifecycle(draft, LifecycleSuperseded) }},
		{name: "term action", edit: func(draft *Draft) { draft.Vocabulary[0].Kind = TermAction }},
		{name: "term observable", edit: func(draft *Draft) { draft.Vocabulary[0].Kind = TermObservable }},
		{name: "term state", edit: func(draft *Draft) { draft.Vocabulary[0].Kind = TermState }},
		{name: "term subject", edit: func(draft *Draft) { draft.Vocabulary[0].Kind = TermSubject }},
		{name: "term value", edit: func(draft *Draft) { draft.Vocabulary[0].Kind = TermValue }},
		{name: "source clarification", edit: func(draft *Draft) { draft.Derivations[0].SourceKind = SourceClarification }},
		{name: "source code snapshot", edit: func(draft *Draft) { draft.Derivations[0].SourceKind = SourceCodeSnapshot }},
		{name: "source design", edit: func(draft *Draft) { draft.Derivations[0].SourceKind = SourceDesign }},
		{name: "source owner decision", edit: func(draft *Draft) { draft.Derivations[0].SourceKind = SourceOwnerDecision }},
		{name: "source plan", edit: func(draft *Draft) { draft.Derivations[0].SourceKind = SourcePlan }},
		{name: "object sha1", edit: func(draft *Draft) { setObjectFormat(draft, ObjectSHA1) }},
		{name: "object sha256", edit: func(draft *Draft) { setObjectFormat(draft, ObjectSHA256) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validDraft()
			test.edit(&draft)
			if _, err := Normalize(draft); err != nil {
				t.Fatalf("whole-model normalization rejected declared variant: %v", err)
			}
		})
	}
}

func TestNormalizeProjectsEveryManifestVariantThroughWholeModel(t *testing.T) {
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	for _, variant := range manifest.Variants {
		for _, value := range variant.Values {
			t.Run(variant.VariantID+"/"+value, func(t *testing.T) {
				draft := validDraft()
				if !applyVariantInput(&draft, variant.VariantID, value) {
					t.Fatalf("variant %s=%s has no independent whole-model fixture", variant.VariantID, value)
				}
				model, err := Normalize(draft)
				if err != nil {
					t.Fatalf("Normalize() rejected %s=%s: %v", variant.VariantID, value, err)
				}
				for _, projection := range variant.RequiredProjections {
					if !variantProjected(model, variant.VariantID, value, projection) {
						t.Fatalf("%s=%s is absent from %s projection", variant.VariantID, value, projection)
					}
				}
			})
		}
	}
}

func TestNormalizeAdmitsAndProjectsMetadataEnumVariantsFromEachOwner(t *testing.T) {
	manifest := readStrictJSON[completenessManifest](t, "testdata/field-projection-manifest.v1.json")
	for _, variant := range manifest.Variants {
		if variant.VariantID != "claimLevel" && variant.VariantID != "riskClass" && variant.VariantID != "lifecycleState" {
			continue
		}
		for _, ownerKind := range []MetadataOwnerKind{MetadataOwnerMember, MetadataOwnerProfile} {
			for _, value := range variant.Values {
				t.Run(variant.VariantID+"/"+string(ownerKind)+"/"+value, func(t *testing.T) {
					draft := validDraft()
					requirementID := applyMetadataVariantForOwner(&draft, variant.VariantID, value, ownerKind)
					model, err := Normalize(draft)
					if err != nil {
						t.Fatalf("Normalize() rejected variant: %v", err)
					}
					assertMetadataVariantForOwner(t, model, variant.VariantID, value, ownerKind, requirementID)
				})
			}
		}
	}
}

func applyMetadataVariantForOwner(draft *Draft, variantID string, value string, ownerKind MetadataOwnerKind) string {
	if ownerKind == MetadataOwnerMember {
		switch variantID {
		case "claimLevel":
			setSingletonClaim(draft, ClaimLevel(value))
		case "riskClass":
			draft.Groups[1].Members[0].Fields.RiskClass.Value = RiskClass(value)
		case "lifecycleState":
			setSingletonLifecycle(draft, LifecycleState(value))
		}
		return "REQ-MODEL-003"
	}

	profile := &draft.Profiles[0].Fields
	switch variantID {
	case "claimLevel":
		profile.ClaimLevel.Value = ClaimLevel(value)
		if ClaimLevel(value) == ClaimDeferred {
			profile.Deferral = Own(cloneDeferral(draft.Groups[1].Members[0].Fields.Deferral.Value))
			for index := range draft.Groups[0].Members {
				draft.Groups[0].Members[index].Fields.Deferral = Field[*Deferral]{}
			}
		}
	case "riskClass":
		profile.RiskClass.Value = RiskClass(value)
	case "lifecycleState":
		state := LifecycleState(value)
		lifecycle := Lifecycle{State: state}
		if state != LifecycleActive {
			lifecycle.EvidenceRefs = []string{"docs/evidence/lifecycle.md"}
		}
		if state == LifecycleSuperseded {
			lifecycle.ReplacementRequirementIDs = []string{"REQ-MODEL-003"}
		}
		if state != LifecycleActive {
			profile.ClaimLevel.Value = ClaimAdvisory
			draft.Groups[2].Members[0].Fields.Lifecycle.Value.ReplacementRequirementIDs = []string{"REQ-MODEL-003"}
		}
		profile.Lifecycle = Own(lifecycle)
		for index := range draft.Groups[0].Members {
			draft.Groups[0].Members[index].Fields.Lifecycle = Field[Lifecycle]{}
		}
	}
	return "REQ-MODEL-001"
}

func assertMetadataVariantForOwner(t *testing.T, model Model, variantID string, value string, ownerKind MetadataOwnerKind, requirementID string) {
	t.Helper()
	foundAtomic := false
	for _, requirement := range model.Atomic().Requirements {
		if requirement.RequirementID != requirementID {
			continue
		}
		foundAtomic = metadataAtomicVariantValue(requirement, variantID) == value
	}
	if !foundAtomic {
		t.Fatalf("%s=%s is absent from atomic requirement %s", variantID, value, requirementID)
	}

	layout := model.Layout()
	for _, origin := range layout.Origins {
		if origin.RequirementID != requirementID {
			continue
		}
		fieldID := MetadataFieldID(metadataVariantFieldID(variantID))
		for _, owner := range origin.FieldOwners {
			if owner.FieldID == fieldID && owner.OwnerKind == ownerKind && metadataLayoutVariantValue(layout, origin, variantID, ownerKind) == value {
				return
			}
		}
	}
	t.Fatalf("%s=%s is absent from %s-owned layout", variantID, value, ownerKind)
}

func metadataAtomicVariantValue(requirement AtomicRequirement, variantID string) string {
	switch variantID {
	case "claimLevel":
		return string(requirement.ClaimLevel)
	case "riskClass":
		return string(requirement.RiskClass)
	case "lifecycleState":
		return string(requirement.Lifecycle.State)
	default:
		return ""
	}
}

func metadataLayoutVariantValue(layout LayoutProjection, origin Origin, variantID string, ownerKind MetadataOwnerKind) string {
	if ownerKind == MetadataOwnerProfile {
		for _, profile := range layout.Profiles {
			if profile.ProfileID == origin.ProfileID {
				return metadataFieldsVariantValue(profile.Fields, variantID)
			}
		}
		return ""
	}
	fields, exists := memberFieldsByRequirement(layout, origin.RequirementID)
	if !exists {
		return ""
	}
	return metadataFieldsVariantValue(fields, variantID)
}

func metadataFieldsVariantValue(fields MetadataFields, variantID string) string {
	switch variantID {
	case "claimLevel":
		if fields.ClaimLevel.Present {
			return string(fields.ClaimLevel.Value)
		}
	case "riskClass":
		if fields.RiskClass.Present {
			return string(fields.RiskClass.Value)
		}
	case "lifecycleState":
		if fields.Lifecycle.Present {
			return string(fields.Lifecycle.Value.State)
		}
	}
	return ""
}

func metadataVariantFieldID(variantID string) string {
	switch variantID {
	case "claimLevel":
		return "claimLevel"
	case "riskClass":
		return "riskClass"
	case "lifecycleState":
		return "lifecycle"
	default:
		return ""
	}
}

func applyVariantInput(draft *Draft, variantID string, value string) bool {
	switch variantID {
	case "claimLevel":
		setSingletonClaim(draft, ClaimLevel(value))
	case "riskClass":
		draft.Groups[1].Members[0].Fields.RiskClass.Value = RiskClass(value)
	case "lifecycleState":
		setSingletonLifecycle(draft, LifecycleState(value))
	case "termKind":
		draft.Vocabulary[0].Kind = TermKind(value)
	case "sourceKind":
		draft.Derivations[0].SourceKind = SourceKind(value)
	case "objectFormat":
		setObjectFormat(draft, ObjectFormat(value))
	case "entityKind", "referenceKind", "metadataOwner", "deferral", "profileRef", "scenarioValue":
		// The baseline contains every derived or presence variant.
	default:
		return false
	}
	return true
}

func variantProjected(model Model, variantID string, value string, projection string) bool {
	switch variantID {
	case "claimLevel", "riskClass", "lifecycleState":
		return metadataEnumProjected(model, variantID, value, projection)
	case "termKind":
		return projection == "atomic" && len(model.Atomic().Vocabulary) == 1 && string(model.Atomic().Vocabulary[0].Kind) == value
	case "sourceKind":
		return projection == "references" && len(model.References().Derivations) == 1 && string(model.References().Derivations[0].SourceKind) == value
	case "objectFormat":
		return projection == "references" && len(model.References().Derivations) == 1 && string(model.References().Derivations[0].SourceRef.ObjectFormat) == value
	case "entityKind":
		if projection != "references" {
			return false
		}
		for _, edge := range model.References().Edges {
			if string(edge.From.Kind) == value || string(edge.To.Kind) == value {
				return true
			}
		}
	case "referenceKind":
		if projection != "references" {
			return false
		}
		for _, edge := range model.References().Edges {
			if string(edge.Kind) == value {
				return true
			}
		}
	case "metadataOwner":
		if projection != "layout" {
			return false
		}
		for _, origin := range model.Layout().Origins {
			for _, owner := range origin.FieldOwners {
				if string(owner.OwnerKind) == value {
					return true
				}
			}
		}
	case "deferral":
		return deferralVariantProjected(model, value, projection)
	case "profileRef":
		return profileRefVariantProjected(model, value, projection)
	case "scenarioValue":
		atomic := model.Atomic()
		return projection == "atomic" && value == "string" && len(atomic.Scenarios) == 1 && string(atomic.Scenarios[0].Examples[0].Values["surface"]) == "primary"
	}
	return false
}

func metadataEnumProjected(model Model, variantID string, value string, projection string) bool {
	if projection == "atomic" {
		for _, requirement := range model.Atomic().Requirements {
			if requirement.RequirementID != "REQ-MODEL-003" {
				continue
			}
			switch variantID {
			case "claimLevel":
				return string(requirement.ClaimLevel) == value
			case "riskClass":
				return string(requirement.RiskClass) == value
			case "lifecycleState":
				return string(requirement.Lifecycle.State) == value
			}
		}
	}
	if projection == "layout" {
		fields, exists := memberFieldsByRequirement(model.Layout(), "REQ-MODEL-003")
		if !exists {
			return false
		}
		switch variantID {
		case "claimLevel":
			return fields.ClaimLevel.Present && string(fields.ClaimLevel.Value) == value
		case "riskClass":
			return fields.RiskClass.Present && string(fields.RiskClass.Value) == value
		case "lifecycleState":
			return fields.Lifecycle.Present && string(fields.Lifecycle.Value.State) == value
		}
	}
	return false
}

func deferralVariantProjected(model Model, value string, projection string) bool {
	requirementID := "REQ-MODEL-003"
	wantRecord := value == "record"
	if value == "explicit_null" {
		requirementID = "REQ-MODEL-001"
	} else if !wantRecord {
		return false
	}
	if projection == "atomic" {
		for _, requirement := range model.Atomic().Requirements {
			if requirement.RequirementID == requirementID {
				return (requirement.Deferral != nil) == wantRecord
			}
		}
	}
	if projection == "layout" {
		fields, exists := memberFieldsByRequirement(model.Layout(), requirementID)
		return exists && fields.Deferral.Present && (fields.Deferral.Value != nil) == wantRecord
	}
	return false
}

func profileRefVariantProjected(model Model, value string, projection string) bool {
	groupID := "RGRP-MODEL-REQUESTS"
	wantPresent := value == "present"
	if value == "absent" {
		groupID = "RGRP-MODEL-DEFERRED"
	} else if !wantPresent {
		return false
	}
	if projection == "layout" {
		for _, group := range model.Layout().Groups {
			if group.GroupID == groupID {
				return (group.ProfileID != "") == wantPresent
			}
		}
	}
	if projection == "references" {
		found := false
		for _, edge := range model.References().Edges {
			if edge.Kind == ReferenceGroupProfile && edge.From.ID == groupID {
				found = true
			}
		}
		return found == wantPresent
	}
	return false
}

func memberFieldsByRequirement(layout LayoutProjection, requirementID string) (MetadataFields, bool) {
	for _, group := range layout.Groups {
		for _, member := range group.Members {
			if member.RequirementID == requirementID {
				return member.Fields, true
			}
		}
	}
	return MetadataFields{}, false
}

func TestNormalizeRejectsUnknownEnumVariantsThroughWholeModel(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*Draft)
	}{
		{name: "claim", code: "invalid_claim_level", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.ClaimLevel.Value = "unknown" }},
		{name: "risk", code: "invalid_risk_class", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.RiskClass.Value = "unknown" }},
		{name: "lifecycle", code: "invalid_lifecycle_state", edit: func(draft *Draft) { draft.Groups[1].Members[0].Fields.Lifecycle.Value.State = "unknown" }},
		{name: "profile claim", code: "invalid_claim_level", edit: func(draft *Draft) { draft.Profiles[0].Fields.ClaimLevel.Value = "unknown" }},
		{name: "profile risk", code: "invalid_risk_class", edit: func(draft *Draft) { draft.Profiles[0].Fields.RiskClass.Value = "unknown" }},
		{name: "profile lifecycle", code: "invalid_lifecycle_state", edit: func(draft *Draft) {
			draft.Profiles[0].Fields.Lifecycle = Own(Lifecycle{State: "unknown"})
			for index := range draft.Groups[0].Members {
				draft.Groups[0].Members[index].Fields.Lifecycle = Field[Lifecycle]{}
			}
		}},
		{name: "term", code: "invalid_term_kind", edit: func(draft *Draft) { draft.Vocabulary[0].Kind = "unknown" }},
		{name: "source", code: "invalid_source_kind", edit: func(draft *Draft) { draft.Derivations[0].SourceKind = "unknown" }},
		{name: "object", code: "invalid_object_format", edit: func(draft *Draft) { draft.Derivations[0].SourceRef.ObjectFormat = "unknown" }},
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

func TestNormalizePreservesEveryDeclaredPresenceVariant(t *testing.T) {
	model, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	owners := map[MetadataOwnerKind]bool{}
	profileRefs := map[bool]bool{}
	for _, origin := range model.Layout().Origins {
		profileRefs[origin.ProfileID != ""] = true
		for _, owner := range origin.FieldOwners {
			owners[owner.OwnerKind] = true
		}
	}
	if !owners[MetadataOwnerMember] || !owners[MetadataOwnerProfile] {
		t.Fatalf("metadata owner variants = %v", owners)
	}
	if !profileRefs[false] || !profileRefs[true] {
		t.Fatalf("profile reference variants = %v", profileRefs)
	}
	deferrals := map[string]bool{}
	for _, requirement := range model.Atomic().Requirements {
		if requirement.Deferral == nil {
			deferrals["explicit_null"] = true
		} else {
			deferrals["record"] = true
		}
	}
	if !deferrals["explicit_null"] || !deferrals["record"] {
		t.Fatalf("deferral variants = %v", deferrals)
	}
	if _, ok := model.Atomic().Scenarios[0].Examples[0].Values["surface"]; !ok {
		t.Fatal("string scenario value variant is absent")
	}
}

func setSingletonClaim(draft *Draft, claim ClaimLevel) {
	fields := &draft.Groups[1].Members[0].Fields
	fields.ClaimLevel.Value = claim
	if claim == ClaimDeferred {
		return
	}
	fields.Deferral.Value = nil
}

func setSingletonLifecycle(draft *Draft, state LifecycleState) {
	lifecycle := &draft.Groups[1].Members[0].Fields.Lifecycle.Value
	lifecycle.State = state
	lifecycle.ReplacementRequirementIDs = nil
	lifecycle.EvidenceRefs = nil
	if state != LifecycleActive {
		lifecycle.EvidenceRefs = []string{"docs/evidence/lifecycle.md"}
	}
	if state == LifecycleSuperseded {
		lifecycle.ReplacementRequirementIDs = []string{"REQ-MODEL-001"}
	}
}

func setObjectFormat(draft *Draft, format ObjectFormat) {
	draft.Derivations[0].SourceRef.ObjectFormat = format
	if format == ObjectSHA1 {
		draft.Derivations[0].SourceRef.CommitOID = "0123456789abcdef0123456789abcdef01234567"
		return
	}
	draft.Derivations[0].SourceRef.CommitOID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
