package requirementsourcemodel

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNonClaimTextDoesNotMergeIndependentOwners(t *testing.T) {
	draft := validDraft()
	const statement = "Admission does not execute native witnesses."
	draft.SourceNonClaims = []string{statement}
	for i := range draft.Groups[0].Members {
		draft.Groups[0].Members[i].Fields.NonClaims = Own([]string{statement})
	}
	baseline, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	draft.SourceNonClaims[0] = "Source-level owner text changed."
	afterSource, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(baseline.Atomic().Requirements, afterSource.Atomic().Requirements) || !reflect.DeepEqual(baseline.Layout(), afterSource.Layout()) {
		t.Fatal("editing direct source text changed an independent requirement owner")
	}
	draft.Groups[0].Members[0].Fields.NonClaims.Value[0] = "First requirement owner text changed."
	afterMember, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	if got := afterMember.Atomic().Requirements[1].NonClaims; !reflect.DeepEqual(got, []string{statement}) {
		t.Fatalf("editing one direct member changed another: %#v", got)
	}
	if !reflect.DeepEqual(afterSource.References(), afterMember.References()) {
		t.Fatal("direct text created or changed a named reference")
	}
}

func TestEqualDefinitionTextIsScopedByReferenceOwnership(t *testing.T) {
	draft := validDraft()
	draft.NonClaimDefinitions[1].Statement = draft.NonClaimDefinitions[0].Statement
	if _, err := Normalize(draft); err != nil {
		t.Fatalf("equal text in separate named scopes was rejected: %v", err)
	}
	draft.SourceNonClaimRefs = append(draft.SourceNonClaimRefs, draft.NonClaimDefinitions[1].NonClaimID)
	if _, err := Normalize(draft); ErrorCode(err) != "duplicate_effective_nonclaim" {
		t.Fatalf("equal named statements in one scope: %v", err)
	}
}

func TestMetadataBoundaryAdmissionRejectsIndependentCounterexamples(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*Draft)
	}{
		{"empty source boundary", "empty_source_nonclaims", func(d *Draft) { d.SourceNonClaims = nil; d.SourceNonClaimRefs = nil }},
		{"duplicate direct source", "duplicate_value", func(d *Draft) { d.SourceNonClaims = append(d.SourceNonClaims, d.SourceNonClaims[0]) }},
		{"source direct and named", "duplicate_effective_nonclaim", func(d *Draft) { d.SourceNonClaims = []string{d.NonClaimDefinitions[0].Statement} }},
		{"member direct and named", "duplicate_effective_nonclaim", func(d *Draft) {
			d.Groups[0].Members[0].Fields.NonClaims.Value = []string{d.NonClaimDefinitions[1].Statement}
		}},
		{"duplicate direct member", "duplicate_value", func(d *Draft) {
			f := &d.Groups[0].Members[0].Fields
			f.NonClaims.Value = append(f.NonClaims.Value, f.NonClaims.Value[0])
		}},
		{"empty active binding route", "missing_proof_binding", func(d *Draft) { d.Groups[0].Members[0].Fields.ProofBindingRefs.Value = nil }},
		{"traversal binding route", "invalid_path", func(d *Draft) { d.Groups[0].Members[0].Fields.ProofBindingRefs.Value = []string{"../bindings.json"} }},
		{"duplicate binding route", "duplicate_value", func(d *Draft) {
			f := &d.Groups[0].Members[0].Fields
			f.ProofBindingRefs.Value = append(f.ProofBindingRefs.Value, f.ProofBindingRefs.Value[0])
		}},
		{"invalid external ID", "invalid_id", func(d *Draft) {
			d.Groups[0].Members[0].Fields.ExternalNonClaimRefs.Value = []string{"invalid external id"}
		}},
		{"duplicate external ID", "duplicate_value", func(d *Draft) {
			d.Groups[0].Members[0].Fields.ExternalNonClaimRefs.Value = []string{"external.id", "external.id"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			draft := validDraft()
			tt.edit(&draft)
			if _, err := Normalize(draft); ErrorCode(err) != tt.code {
				t.Fatalf("error = %v, want %s", err, tt.code)
			}
		})
	}
}

func TestExternalNonClaimRefsRemainIndependentDeclarations(t *testing.T) {
	draft := validDraft()
	draft.Groups[0].Members[0].Fields.ExternalNonClaimRefs.Value = []string{"NCL-UNRESOLVED", "external.nonclaim.other"}
	draft.Groups[0].Members[1].Fields.ExternalNonClaimRefs.Value = nil
	draft.Groups[1].Members[0].Fields.ProofBindingRefs.Value = nil
	model, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(model.Atomic().Requirements[0].ExternalNonClaimRefs, []string{"NCL-UNRESOLVED", "external.nonclaim.other"}) {
		t.Fatal("independent external IDs were rewritten or erased")
	}
	for _, edge := range model.References().Edges {
		if edge.To.ID == "NCL-UNRESOLVED" || edge.To.ID == "external.nonclaim.other" {
			t.Fatal("external declaration was laundered into local reference closure")
		}
	}
}

func TestDirectNonClaimAdmissionDoesNotDiscloseRejectedText(t *testing.T) {
	const sentinel = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	for _, source := range []bool{false, true} {
		draft := validDraft()
		if source {
			draft.SourceNonClaims = []string{sentinel}
		} else {
			draft.Groups[0].Members[0].Fields.NonClaims.Value = []string{sentinel}
		}
		_, err := Normalize(draft)
		if ErrorCode(err) != "invalid_text" || strings.Contains(err.Error(), sentinel) {
			t.Fatal("direct statement admission failed its nondisclosure boundary")
		}
	}
}

func TestBoundaryMetadataRejectsHiddenPayloads(t *testing.T) {
	for _, field := range []struct {
		id  MetadataFieldID
		get func(*MetadataFields) *Field[[]string]
	}{
		{"nonClaims", func(f *MetadataFields) *Field[[]string] { return &f.NonClaims }},
		{"externalNonClaimRefs", func(f *MetadataFields) *Field[[]string] { return &f.ExternalNonClaimRefs }},
		{"proofBindingRefs", func(f *MetadataFields) *Field[[]string] { return &f.ProofBindingRefs }},
	} {
		for _, profile := range []bool{false, true} {
			for _, size := range []int{1, 1000} {
				t.Run(fmt.Sprintf("%s/profile=%t/size=%d", field.id, profile, size), func(t *testing.T) {
					draft := validDraft()
					if profile {
						moveMetadataFieldToOtherOwner(&draft, field.id)
					}
					fields := &draft.Groups[0].Members[0].Fields
					if profile {
						fields = &draft.Profiles[0].Fields
					}
					payload := make([]string, size)
					*field.get(fields) = Field[[]string]{Value: payload}
					if _, err := NormalizeWithLimits(draft, DefaultLimits()); ErrorCode(err) != "hidden_field_payload" {
						t.Fatalf("hidden metadata field: %v", err)
					}
					cloned := cloneMetadataFields(*fields)
					if value := field.get(&cloned); value.Present || len(value.Value) != size || &value.Value[0] != &payload[0] {
						t.Fatal("clone copied or erased an absent payload before admission")
					}
					field.get(fields).Present = true
					cloned = cloneMetadataFields(*fields)
					value := field.get(&cloned)
					if !value.Present || len(value.Value) != size || &value.Value[0] == &payload[0] {
						t.Fatal("present payload was not detached")
					}
					value.Value[0] = "Changed detached payload."
					if payload[0] != "" {
						t.Fatal("editing a cloned value changed caller storage")
					}
				})
			}
		}
	}
}
