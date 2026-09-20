package requirementsourcemodel

import (
	"fmt"
	"testing"
)

func flatRequirementDraft(count int) Draft {
	draft := Draft{SourceID: "source.resource-cost", SpecPackagePath: "docs/specs/resource-cost",
		SourceNonClaims: []string{"Synthetic resource observation, not execution authority."}}
	if count == 0 {
		return draft
	}
	draft.Groups = []Group{{GroupID: "RGRP-RESOURCE", Members: make([]Member, count)}}
	for index := range draft.Groups[0].Members {
		draft.Groups[0].Members[index] = Member{
			RequirementID:       fmt.Sprintf("REQ-RESOURCE-%05d", index),
			StatementCompletion: "The operation preserves the declared input value.",
			Fields: MetadataFields{
				OwnerID: Own("owner.resource"), ClaimLevel: Own(ClaimAdvisory), RiskClass: Own(RiskLow),
				NonClaims:            Own([]string{"No native witness is asserted."}),
				ExternalNonClaimRefs: Own([]string{}), NonClaimRefs: Own([]string{}), ProofBindingRefs: Own([]string{}),
				Lifecycle: Own(Lifecycle{State: LifecycleActive}), Deferral: Own[*Deferral](nil),
				UpdatePolicy: Own(UpdatePolicy{ReviewOwnerID: "owner.resource"}),
			},
		}
	}
	return draft
}

func TestNormalizedMemberStorageMatchesAdmittedCardinality(t *testing.T) {
	for _, count := range []int{0, 1, 5, 64, 512, 4096} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			draft := flatRequirementDraft(count)
			if count == 5 {
				group := draft.Groups[0]
				draft.Groups = []Group{
					{GroupID: "RGRP-FIRST", Members: group.Members[:2]},
					{GroupID: "RGRP-SECOND", Members: group.Members[2:]},
				}
			}
			model, err := Normalize(draft)
			if err != nil {
				t.Fatal(err)
			}
			if len(model.atomic.Requirements) != count || cap(model.atomic.Requirements) != count || len(model.layout.Origins) != count || cap(model.layout.Origins) != count {
				t.Fatal("model retained excess or incomplete member projection storage")
			}
			compactedEdges := append([]ReferenceEdge(nil), model.references.Edges...)
			if cap(model.references.Edges) != cap(compactedEdges) {
				t.Fatal("model retained uncompacted reference edge storage")
			}
		})
	}
}

var normalizationBenchmarkSink Model

func BenchmarkNormalizeMemberStorage(b *testing.B) {
	for _, count := range []int{64, 512, 4096} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			draft := flatRequirementDraft(count)
			if _, err := Normalize(draft); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				model, err := Normalize(draft)
				if err != nil {
					b.Fatal(err)
				}
				normalizationBenchmarkSink = model
			}
		})
	}
}
