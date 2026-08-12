package requirementsourcemodel

func mutantImplementations() map[string]func(*Draft) {
	return map[string]func(*Draft){
		"source-id":            func(draft *Draft) { draft.SourceID = "proofkit.model.changed" },
		"source-package-path":  func(draft *Draft) { draft.SpecPackagePath = "docs/specs/proofkit-model-v2" },
		"source-nonclaim-refs": func(draft *Draft) { draft.SourceNonClaimRefs = []string{"NCL-MODEL-001", "NCL-MODEL-002"} },
		"nonclaim-id": func(draft *Draft) {
			draft.NonClaimDefinitions[0].NonClaimID = "NCL-MODEL-005"
			draft.SourceNonClaimRefs[0] = "NCL-MODEL-005"
		},
		"nonclaim-statement": func(draft *Draft) { draft.NonClaimDefinitions[0].Statement += " It is declaration-only." },
		"vocabulary-id": func(draft *Draft) {
			draft.Vocabulary[0].TermID = "TERM-MODEL-SERVICE-V2"
			draft.Scenarios[0].VocabularyRefs[0] = "TERM-MODEL-SERVICE-V2"
		},
		"vocabulary-kind":        func(draft *Draft) { draft.Vocabulary[0].Kind = TermState },
		"vocabulary-label":       func(draft *Draft) { draft.Vocabulary[0].Label = "bounded service" },
		"vocabulary-definition":  func(draft *Draft) { draft.Vocabulary[0].Definition += " It is repository-owned." },
		"derivation-id":          func(draft *Draft) { draft.Derivations[0].DerivationID = "DRV-MODEL-002" },
		"derivation-source-kind": func(draft *Draft) { draft.Derivations[0].SourceKind = SourceDesign },
		"derivation-object-format": func(draft *Draft) {
			draft.Derivations[0].SourceRef.ObjectFormat = ObjectSHA256
			draft.Derivations[0].SourceRef.CommitOID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		},
		"derivation-commit-oid": func(draft *Draft) {
			draft.Derivations[0].SourceRef.CommitOID = "1123456789abcdef0123456789abcdef01234567"
		},
		"derivation-path": func(draft *Draft) { draft.Derivations[0].SourceRef.Path = "docs/decisions/model-v2.md" },
		"derivation-sha256": func(draft *Draft) {
			draft.Derivations[0].SourceRef.SHA256 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		},
		"derivation-selector-start": func(draft *Draft) { draft.Derivations[0].Selector.Start = 1 },
		"derivation-selector-end":   func(draft *Draft) { draft.Derivations[0].Selector.End = 65 },
		"derivation-requirements":   func(draft *Draft) { draft.Derivations[0].RequirementIDs = []string{"REQ-MODEL-001"} },
		"derivation-nonclaims":      func(draft *Draft) { draft.Derivations[0].NonClaimRefs = []string{"NCL-MODEL-002", "NCL-MODEL-004"} },
		"profile-id": func(draft *Draft) {
			draft.Profiles[0].ProfileID = "RPROF-MODEL-BLOCKING-V2"
			draft.Groups[0].ProfileID = "RPROF-MODEL-BLOCKING-V2"
		},
		"metadata-owner":       func(draft *Draft) { draft.Profiles[0].Fields.OwnerID.Value = "proofkit.model.changed" },
		"metadata-claim-level": func(draft *Draft) { draft.Profiles[0].Fields.ClaimLevel.Value = ClaimAdvisory },
		"metadata-risk-class":  func(draft *Draft) { draft.Profiles[0].Fields.RiskClass.Value = RiskCritical },
		"metadata-nonclaims": func(draft *Draft) {
			draft.Groups[0].Members[0].Fields.NonClaimRefs.Value = []string{"NCL-MODEL-001", "NCL-MODEL-002"}
		},
		"metadata-lifecycle-state": func(draft *Draft) {
			lifecycle := draft.Groups[1].Members[0].Fields.Lifecycle.Value
			lifecycle.State = LifecycleDeprecated
			lifecycle.EvidenceRefs = []string{"docs/evidence/deprecated.md"}
			draft.Groups[1].Members[0].Fields.Lifecycle.Value = lifecycle
		},
		"metadata-lifecycle-replacements": func(draft *Draft) {
			lifecycle := draft.Groups[2].Members[0].Fields.Lifecycle.Value
			lifecycle.ReplacementRequirementIDs = []string{"REQ-MODEL-001", "REQ-MODEL-002"}
			draft.Groups[2].Members[0].Fields.Lifecycle.Value = lifecycle
		},
		"metadata-lifecycle-evidence": func(draft *Draft) {
			lifecycle := draft.Groups[1].Members[0].Fields.Lifecycle.Value
			lifecycle.EvidenceRefs = []string{"docs/evidence/active.md"}
			draft.Groups[1].Members[0].Fields.Lifecycle.Value = lifecycle
		},
		"metadata-deferral-presence": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.ClaimLevel.Value = ClaimAdvisory
			draft.Groups[1].Members[0].Fields.Deferral.Value = nil
		},
		"metadata-deferral-owner": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.Deferral.Value.OwnerID = "proofkit.model.changed"
		},
		"metadata-deferral-risk-owner": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.Deferral.Value.RiskAcceptedBy = "proofkit.owner.changed"
		},
		"metadata-deferral-review": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.Deferral.Value.ReviewCondition = "Review after another experiment."
		},
		"metadata-deferral-expiry": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.Deferral.Value.ExpiryRef = "proofkit.model.expiry.changed"
		},
		"metadata-deferral-policy": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.Deferral.Value.MergePolicy = "proofkit.model.merge.changed"
		},
		"metadata-deferral-evidence": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.Deferral.Value.EvidenceRefs = []string{"docs/evidence/deferral-v2.md"}
		},
		"metadata-update-owner": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.UpdatePolicy.Value.ReviewOwnerID = "proofkit.model.changed"
		},
		"metadata-update-impact": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.UpdatePolicy.Value.RequiresImpactDeclaration = false
		},
		"metadata-update-binding": func(draft *Draft) {
			draft.Groups[1].Members[0].Fields.UpdatePolicy.Value.RequiresProofBindingReview = false
		},
		"group-id": func(draft *Draft) { draft.Groups[0].GroupID = "RGRP-MODEL-REQUESTS-V2" },
		"group-membership": func(draft *Draft) {
			draft.Groups[1].Members[0], draft.Groups[2].Members[0] = draft.Groups[2].Members[0], draft.Groups[1].Members[0]
		},
		"group-profile-ref": removeProfileWithoutChangingSemantics,
		"group-stem":        func(draft *Draft) { draft.Groups[0].StatementStem = "The service shall" },
		"group-premises": func(draft *Draft) {
			draft.Groups[0].SharedPremises = []string{"The service is available.", "The transport is available."}
		},
		"member-id": func(draft *Draft) {
			draft.Groups[0].Members[1].RequirementID = "REQ-MODEL-005"
			draft.Derivations[0].RequirementIDs = []string{"REQ-MODEL-001", "REQ-MODEL-005"}
		},
		"member-completion":     func(draft *Draft) { draft.Groups[0].Members[0].StatementCompletion = "accept valid requests." },
		"scenario-id":           func(draft *Draft) { draft.Scenarios[0].ScenarioID = "SCN-MODEL-REQUEST-V2" },
		"scenario-requirements": func(draft *Draft) { draft.Scenarios[0].RequirementIDs = []string{"REQ-MODEL-001", "REQ-MODEL-002"} },
		"scenario-parameters": func(draft *Draft) {
			draft.Scenarios[0].Parameters = []string{"channel"}
			draft.Scenarios[0].Preconditions[0] = "The ${channel} surface is available."
			for index := range draft.Scenarios[0].Examples {
				value := draft.Scenarios[0].Examples[index].Values["surface"]
				draft.Scenarios[0].Examples[index].Values = map[string]ScenarioValue{"channel": value}
			}
		},
		"scenario-preconditions": func(draft *Draft) { draft.Scenarios[0].Preconditions[0] = "The ${surface} surface is ready." },
		"scenario-actions": func(draft *Draft) {
			draft.Scenarios[0].ActionSequence[0], draft.Scenarios[0].ActionSequence[1] = draft.Scenarios[0].ActionSequence[1], draft.Scenarios[0].ActionSequence[0]
		},
		"scenario-expected":       func(draft *Draft) { draft.Scenarios[0].ExpectedObservations[0] = "The valid request is accepted." },
		"scenario-forbidden":      func(draft *Draft) { draft.Scenarios[0].ForbiddenObservations[0] = "The service exposes credentials." },
		"scenario-example-id":     func(draft *Draft) { draft.Scenarios[0].Examples[0].ExampleID = "EX-MODEL-REQUEST-003" },
		"scenario-example-values": func(draft *Draft) { draft.Scenarios[0].Examples[0].Values["surface"] = "tertiary" },
		"scenario-vocabulary": func(draft *Draft) {
			draft.Vocabulary = append(draft.Vocabulary, VocabularyTerm{TermID: "TERM-MODEL-REQUEST", Kind: TermAction, Label: "request", Definition: "A bounded request value."})
			draft.Scenarios[0].VocabularyRefs = []string{"TERM-MODEL-REQUEST", "TERM-MODEL-SERVICE"}
		},
		"scenario-nonclaims": func(draft *Draft) { draft.Scenarios[0].NonClaimRefs = []string{"NCL-MODEL-002", "NCL-MODEL-003"} },
	}
}

func applyMutant(id string, draft *Draft) bool {
	mutation, exists := mutantImplementations()[id]
	if !exists {
		return false
	}
	mutation(draft)
	return true
}

func removeProfileWithoutChangingSemantics(draft *Draft) {
	profile := draft.Profiles[0].Fields
	for index := range draft.Groups[0].Members {
		fields := &draft.Groups[0].Members[index].Fields
		fields.OwnerID = profile.OwnerID
		fields.ClaimLevel = profile.ClaimLevel
		fields.RiskClass = profile.RiskClass
		fields.UpdatePolicy = profile.UpdatePolicy
	}
	draft.Groups[0].ProfileID = ""
	draft.Profiles = nil
}
