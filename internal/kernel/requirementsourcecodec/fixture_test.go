package requirementsourcecodec

import (
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func testDraft() requirementsourcemodel.Draft {
	active := requirementsourcemodel.Lifecycle{State: requirementsourcemodel.LifecycleActive}
	profile := requirementsourcemodel.Profile{
		ProfileID: "RPROF-CODEC-BLOCKING",
		Fields: requirementsourcemodel.MetadataFields{
			OwnerID:    requirementsourcemodel.Own("proofkit.codec"),
			ClaimLevel: requirementsourcemodel.Own(requirementsourcemodel.ClaimBlocking),
			RiskClass:  requirementsourcemodel.Own(requirementsourcemodel.RiskHigh),
			UpdatePolicy: requirementsourcemodel.Own(requirementsourcemodel.UpdatePolicy{
				ReviewOwnerID:              "proofkit.codec",
				RequiresImpactDeclaration:  true,
				RequiresProofBindingReview: true,
			}),
		},
	}
	memberFields := requirementsourcemodel.MetadataFields{
		NonClaimRefs: requirementsourcemodel.Own([]string{"NCL-CODEC-002"}),
		Lifecycle:    requirementsourcemodel.Own(active),
		Deferral:     requirementsourcemodel.Own[*requirementsourcemodel.Deferral](nil),
	}
	completeFields := func(claim requirementsourcemodel.ClaimLevel, lifecycle requirementsourcemodel.Lifecycle, deferral *requirementsourcemodel.Deferral) requirementsourcemodel.MetadataFields {
		return requirementsourcemodel.MetadataFields{
			OwnerID:      requirementsourcemodel.Own("proofkit.codec"),
			ClaimLevel:   requirementsourcemodel.Own(claim),
			RiskClass:    requirementsourcemodel.Own(requirementsourcemodel.RiskMedium),
			NonClaimRefs: requirementsourcemodel.Own([]string{"NCL-CODEC-002"}),
			Lifecycle:    requirementsourcemodel.Own(lifecycle),
			Deferral:     requirementsourcemodel.Own(deferral),
			UpdatePolicy: requirementsourcemodel.Own(requirementsourcemodel.UpdatePolicy{
				ReviewOwnerID:              "proofkit.codec",
				RequiresImpactDeclaration:  true,
				RequiresProofBindingReview: true,
			}),
		}
	}
	deferral := &requirementsourcemodel.Deferral{
		OwnerID:         "proofkit.codec",
		RiskAcceptedBy:  "proofkit.owner",
		ReviewCondition: "Review after the codec experiment.",
		ExpiryRef:       "proofkit.codec.expiry",
		MergePolicy:     "proofkit.codec.merge",
		EvidenceRefs:    []string{"docs/evidence/codec-deferral.md"},
	}
	return requirementsourcemodel.Draft{
		SourceID:           "proofkit.codec.source",
		SpecPackagePath:    "docs/specs/proofkit-codec",
		SourceNonClaimRefs: []string{"NCL-CODEC-001"},
		NonClaimDefinitions: []requirementsourcemodel.NonClaimDefinition{
			{NonClaimID: "NCL-CODEC-001", Statement: "The codec does not prove implementation correctness."},
			{NonClaimID: "NCL-CODEC-002", Statement: "A declared requirement does not prove its satisfaction."},
			{NonClaimID: "NCL-CODEC-003", Statement: "Scenario examples are not exhaustive proof."},
			{NonClaimID: "NCL-CODEC-004", Statement: "Derivation provenance does not prove requirement correctness."},
		},
		Vocabulary: []requirementsourcemodel.VocabularyTerm{
			{TermID: "TERM-CODEC-SERVICE", Kind: requirementsourcemodel.TermSubject, Label: "service", Definition: "The bounded service under specification."},
		},
		Derivations: []requirementsourcemodel.Derivation{
			{
				DerivationID: "DRV-CODEC-001",
				SourceKind:   requirementsourcemodel.SourceOwnerDecision,
				SourceRef: requirementsourcemodel.GitBlobRef{
					ObjectFormat: requirementsourcemodel.ObjectSHA1,
					CommitOID:    "0123456789abcdef0123456789abcdef01234567",
					Path:         "docs/decisions/codec.md",
					SHA256:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				},
				Selector:       requirementsourcemodel.ByteRange{Start: 0, End: 64},
				RequirementIDs: []string{"REQ-CODEC-001", "REQ-CODEC-002"},
				NonClaimRefs:   []string{"NCL-CODEC-004"},
			},
		},
		Profiles: []requirementsourcemodel.Profile{profile},
		Groups: []requirementsourcemodel.Group{
			{
				GroupID:        "RGRP-CODEC-REQUESTS",
				ProfileID:      "RPROF-CODEC-BLOCKING",
				StatementStem:  "The service must",
				SharedPremises: []string{"The service is available."},
				Members: []requirementsourcemodel.Member{
					{RequirementID: "REQ-CODEC-001", StatementCompletion: "accept requests.", Fields: memberFields},
					{RequirementID: "REQ-CODEC-002", StatementCompletion: "reject malformed requests.", Fields: memberFields},
				},
			},
			{
				GroupID: "RGRP-CODEC-DEFERRED",
				Members: []requirementsourcemodel.Member{
					{RequirementID: "REQ-CODEC-003", StatementCompletion: "Deferred behavior remains owner-reviewed.", Fields: completeFields(requirementsourcemodel.ClaimDeferred, active, deferral)},
				},
			},
			{
				GroupID: "RGRP-CODEC-SUPERSEDED",
				Members: []requirementsourcemodel.Member{
					{
						RequirementID:       "REQ-CODEC-004",
						StatementCompletion: "Historical behavior is superseded.",
						Fields: completeFields(requirementsourcemodel.ClaimAdvisory, requirementsourcemodel.Lifecycle{
							State:                     requirementsourcemodel.LifecycleSuperseded,
							ReplacementRequirementIDs: []string{"REQ-CODEC-001"},
							EvidenceRefs:              []string{"docs/evidence/codec-superseded.md"},
						}, nil),
					},
				},
			},
		},
		Scenarios: []requirementsourcemodel.Scenario{
			{
				ScenarioID:            "SCN-CODEC-REQUEST",
				RequirementIDs:        []string{"REQ-CODEC-001"},
				Parameters:            []string{"surface"},
				Preconditions:         []string{"The ${surface} surface is available."},
				ActionSequence:        []string{"Submit a request.", "Wait for the response."},
				ExpectedObservations:  []string{"The request is accepted."},
				ForbiddenObservations: []string{"The service exposes a secret."},
				Examples: []requirementsourcemodel.Example{
					{ExampleID: "EX-CODEC-REQUEST-001", Values: map[string]requirementsourcemodel.ScenarioValue{"surface": "primary"}},
					{ExampleID: "EX-CODEC-REQUEST-002", Values: map[string]requirementsourcemodel.ScenarioValue{"surface": "secondary"}},
				},
				VocabularyRefs: []string{"TERM-CODEC-SERVICE"},
				NonClaimRefs:   []string{"NCL-CODEC-003"},
			},
		},
	}
}

func mustModel(t *testing.T) requirementsourcemodel.Model {
	t.Helper()
	model, err := requirementsourcemodel.Normalize(testDraft())
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	return model
}

func projectionsEqual(left requirementsourcemodel.Model, right requirementsourcemodel.Model) bool {
	return reflect.DeepEqual(left.Atomic(), right.Atomic()) &&
		reflect.DeepEqual(left.Layout(), right.Layout()) &&
		reflect.DeepEqual(left.References(), right.References())
}
