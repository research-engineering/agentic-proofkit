package requirementsourcemodel

import (
	"reflect"
	"testing"
)

var independentlyExpectedMetadataFieldIDs = []MetadataFieldID{
	"claimLevel",
	"deferral",
	"lifecycle",
	"nonClaimRefs",
	"ownerId",
	"riskClass",
	"updatePolicy",
}

func TestNormalizeRejectsOverlapAndGapForEveryMetadataField(t *testing.T) {
	if !reflect.DeepEqual(metadataFieldIDs, independentlyExpectedMetadataFieldIDs) {
		t.Fatalf("production metadata field inventory = %v, independent inventory = %v", metadataFieldIDs, independentlyExpectedMetadataFieldIDs)
	}
	for _, fieldID := range independentlyExpectedMetadataFieldIDs {
		t.Run(string(fieldID)+" overlap", func(t *testing.T) {
			draft := validDraft()
			profile := &draft.Profiles[0].Fields
			member := &draft.Groups[0].Members[0].Fields
			if metadataPresence(*profile)[fieldID] {
				setMetadataField(member, fieldID, *profile)
			} else {
				setMetadataField(profile, fieldID, *member)
			}
			_, err := Normalize(draft)
			if ErrorCode(err) != "metadata_partition_violation" {
				t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
			}
		})
		t.Run(string(fieldID)+" gap", func(t *testing.T) {
			draft := validDraft()
			profile := &draft.Profiles[0].Fields
			member := &draft.Groups[0].Members[0].Fields
			if metadataPresence(*profile)[fieldID] {
				clearMetadataField(profile, fieldID)
			} else {
				clearMetadataField(member, fieldID)
			}
			_, err := Normalize(draft)
			if ErrorCode(err) != "metadata_partition_violation" {
				t.Fatalf("ErrorCode() = %q, error = %v", ErrorCode(err), err)
			}
		})
	}
}

func TestNormalizePreservesExactMetadataOwnershipMatrix(t *testing.T) {
	for _, fieldID := range metadataFieldIDs {
		t.Run(string(fieldID), func(t *testing.T) {
			baseline, err := Normalize(validDraft())
			if err != nil {
				t.Fatal(err)
			}
			assertEveryOriginHasResolvingFieldOwners(t, baseline.Layout())
			movedDraft := validDraft()
			moveMetadataFieldToOtherOwner(&movedDraft, fieldID)
			moved, err := Normalize(movedDraft)
			if err != nil {
				t.Fatal(err)
			}
			assertEveryOriginHasResolvingFieldOwners(t, moved.Layout())
			if !reflect.DeepEqual(baseline.Atomic(), moved.Atomic()) {
				t.Fatal("moving metadata ownership changed atomic semantics")
			}
			if !reflect.DeepEqual(baseline.References(), moved.References()) {
				t.Fatal("moving metadata ownership changed reference semantics")
			}
			baselineOwners := ownersByRequirement(baseline.Layout())
			movedOwners := ownersByRequirement(moved.Layout())
			for _, requirementID := range []string{"REQ-MODEL-001", "REQ-MODEL-002"} {
				before := baselineOwners[requirementID]
				after := movedOwners[requirementID]
				if len(before) != len(metadataFieldIDs) || len(after) != len(metadataFieldIDs) {
					t.Fatalf("owner cardinality before=%d after=%d", len(before), len(after))
				}
				for _, candidate := range metadataFieldIDs {
					left, leftExists := before[candidate]
					right, rightExists := after[candidate]
					if !leftExists || !rightExists {
						t.Fatalf("field owner %q is missing", candidate)
					}
					if candidate == fieldID {
						if left.OwnerKind == right.OwnerKind || !ownerIDMatches(left, requirementID, baseline.Layout()) || !ownerIDMatches(right, requirementID, moved.Layout()) {
							t.Fatalf("field %q owner transition = %#v -> %#v", fieldID, left, right)
						}
						continue
					}
					if !reflect.DeepEqual(left, right) {
						t.Fatalf("moving %q changed unrelated owner %q: %#v -> %#v", fieldID, candidate, left, right)
					}
				}
			}
		})
	}
}

func TestNormalizeClosesEveryOriginOwnerReference(t *testing.T) {
	model, err := Normalize(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	assertEveryOriginHasResolvingFieldOwners(t, model.Layout())
}

func assertEveryOriginHasResolvingFieldOwners(t *testing.T, layout LayoutProjection) {
	t.Helper()
	profiles := make(map[string]struct{}, len(layout.Profiles))
	for _, profile := range layout.Profiles {
		profiles[profile.ProfileID] = struct{}{}
	}
	members := map[string]struct{}{}
	for _, group := range layout.Groups {
		for _, member := range group.Members {
			members[member.RequirementID] = struct{}{}
		}
	}
	origins := make(map[string]struct{}, len(layout.Origins))
	profileless := 0
	for _, origin := range layout.Origins {
		if _, duplicate := origins[origin.RequirementID]; duplicate {
			t.Fatalf("duplicate origin for %q", origin.RequirementID)
		}
		origins[origin.RequirementID] = struct{}{}
		if _, exists := members[origin.RequirementID]; !exists {
			t.Fatalf("origin %q has no layout member", origin.RequirementID)
		}
		if origin.ProfileID == "" {
			profileless++
		} else if _, exists := profiles[origin.ProfileID]; !exists {
			t.Fatalf("origin %q has missing profile %q", origin.RequirementID, origin.ProfileID)
		}

		seenFields := make(map[MetadataFieldID]struct{}, len(origin.FieldOwners))
		for _, owner := range origin.FieldOwners {
			if _, duplicate := seenFields[owner.FieldID]; duplicate {
				t.Fatalf("origin %q has duplicate owner for %q", origin.RequirementID, owner.FieldID)
			}
			seenFields[owner.FieldID] = struct{}{}
			switch owner.OwnerKind {
			case MetadataOwnerMember:
				if owner.OwnerID != origin.RequirementID {
					t.Fatalf("origin %q member owner resolves to %q", origin.RequirementID, owner.OwnerID)
				}
			case MetadataOwnerProfile:
				if origin.ProfileID == "" || owner.OwnerID != origin.ProfileID {
					t.Fatalf("origin %q profile owner resolves to %q with profile %q", origin.RequirementID, owner.OwnerID, origin.ProfileID)
				}
				if _, exists := profiles[owner.OwnerID]; !exists {
					t.Fatalf("origin %q owner profile %q is missing", origin.RequirementID, owner.OwnerID)
				}
			default:
				t.Fatalf("origin %q has unknown owner kind %q", origin.RequirementID, owner.OwnerKind)
			}
		}
		if len(seenFields) != len(metadataFieldIDs) {
			t.Fatalf("origin %q owner cardinality = %d, want %d", origin.RequirementID, len(seenFields), len(metadataFieldIDs))
		}
		for _, fieldID := range metadataFieldIDs {
			if _, exists := seenFields[fieldID]; !exists {
				t.Fatalf("origin %q is missing owner for %q", origin.RequirementID, fieldID)
			}
		}
	}
	if profileless == 0 {
		t.Fatal("ownership closure fixture has no profile-less origin")
	}
	if !reflect.DeepEqual(origins, members) {
		t.Fatalf("origin/member closure differs: origins=%v members=%v", origins, members)
	}
}

func moveMetadataFieldToOtherOwner(draft *Draft, fieldID MetadataFieldID) {
	profile := &draft.Profiles[0].Fields
	members := draft.Groups[0].Members
	if metadataPresence(*profile)[fieldID] {
		source := cloneMetadataFields(*profile)
		for index := range members {
			setMetadataField(&members[index].Fields, fieldID, source)
		}
		clearMetadataField(profile, fieldID)
		return
	}
	source := cloneMetadataFields(members[0].Fields)
	setMetadataField(profile, fieldID, source)
	for index := range members {
		clearMetadataField(&members[index].Fields, fieldID)
	}
}

func setMetadataField(target *MetadataFields, fieldID MetadataFieldID, source MetadataFields) {
	value := cloneMetadataFields(source)
	switch fieldID {
	case "ownerId":
		target.OwnerID = value.OwnerID
	case "claimLevel":
		target.ClaimLevel = value.ClaimLevel
	case "riskClass":
		target.RiskClass = value.RiskClass
	case "nonClaimRefs":
		target.NonClaimRefs = value.NonClaimRefs
	case "lifecycle":
		target.Lifecycle = value.Lifecycle
	case "deferral":
		target.Deferral = value.Deferral
	case "updatePolicy":
		target.UpdatePolicy = value.UpdatePolicy
	}
}

func clearMetadataField(target *MetadataFields, fieldID MetadataFieldID) {
	switch fieldID {
	case "ownerId":
		target.OwnerID = Field[string]{}
	case "claimLevel":
		target.ClaimLevel = Field[ClaimLevel]{}
	case "riskClass":
		target.RiskClass = Field[RiskClass]{}
	case "nonClaimRefs":
		target.NonClaimRefs = Field[[]string]{}
	case "lifecycle":
		target.Lifecycle = Field[Lifecycle]{}
	case "deferral":
		target.Deferral = Field[*Deferral]{}
	case "updatePolicy":
		target.UpdatePolicy = Field[UpdatePolicy]{}
	}
}

func ownersByRequirement(layout LayoutProjection) map[string]map[MetadataFieldID]FieldOwner {
	result := map[string]map[MetadataFieldID]FieldOwner{}
	for _, origin := range layout.Origins {
		owners := map[MetadataFieldID]FieldOwner{}
		for _, owner := range origin.FieldOwners {
			owners[owner.FieldID] = owner
		}
		result[origin.RequirementID] = owners
	}
	return result
}

func ownerIDMatches(owner FieldOwner, requirementID string, layout LayoutProjection) bool {
	if owner.OwnerKind == MetadataOwnerMember {
		return owner.OwnerID == requirementID
	}
	for _, origin := range layout.Origins {
		if origin.RequirementID == requirementID {
			return owner.OwnerKind == MetadataOwnerProfile && owner.OwnerID == origin.ProfileID && origin.ProfileID != ""
		}
	}
	return false
}
