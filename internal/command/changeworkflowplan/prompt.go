package changeworkflowplan

const (
	promptUncertainty = "Caller-declared context, digests, checkpoint state, and external state are unauthenticated."
	promptNonClaim    = "This packet does not prove execution, correctness, review quality, merge approval, release approval, rollout, or production readiness."
	missingOwnerStop  = "Do not mutate the repository until the caller supplies the consuming-repository semantic owner and governing authority coordinates."
	terminalStop      = "Stop because the admitted workflow snapshot is complete; do not infer merge, release, rollout, or readiness."
)

func buildPrompt(input admittedInput, decision stateDecision, closure closureResult) (map[string]any, error) {
	profile, ok := actionProfileFor(decision.Action)
	if !ok {
		return nil, invalidState("action has no prompt profile")
	}
	ownerTarget := missingAuthorityTarget
	if input.GoverningAuthorityRefID != nil {
		ownerTarget = *input.GoverningAuthorityRefID
	}
	stopCondition := profile.StopCondition
	if input.GoverningAuthorityRefID == nil {
		stopCondition += " " + missingOwnerStop
	}
	observedFact := map[string]any{
		"activeStageId":           decision.ActiveStageID,
		"checkpointState":         decision.CheckpointState,
		"completedStageIds":       stringsValue(input.CompletedStageIDs),
		"governingAuthorityRefId": nullableStringValue(input.GoverningAuthorityRefID),
		"omittedContextRefIds":    stringsValue(contextRefIDs(closure.Omitted)),
		"retainedContextRefIds":   stringsValue(contextRefIDs(closure.Retained)),
	}
	coordinates := map[string]any{
		"activeStageId":         decision.ActiveStageID,
		"checkpointState":       decision.CheckpointState,
		"retainedArtifactPaths": stringsValue(contextRefPaths(closure.Retained)),
		"retainedContextRefIds": stringsValue(contextRefIDs(closure.Retained)),
	}
	if input.GoverningAuthorityRefID != nil {
		coordinates["governingAuthorityRefId"] = *input.GoverningAuthorityRefID
	}
	if input.Checkpoint != nil && input.Checkpoint.SubjectRefID != "" {
		coordinates["subjectDigest"] = input.Checkpoint.SubjectDigest
		coordinates["subjectRefId"] = input.Checkpoint.SubjectRefID
	}
	if input.Checkpoint != nil && len(input.Checkpoint.FindingRefs) > 0 {
		coordinates["findingRefs"] = stringsValue(input.Checkpoint.FindingRefs)
	}
	return map[string]any{
		"candidateAction":              profile.CandidateAction,
		"coordinates":                  coordinates,
		"expectedNextCheckpoint":       profile.ExpectedNextCheckpoint,
		"nonClaim":                     promptNonClaim,
		"observedFact":                 observedFact,
		"ownerOrEscalationTarget":      ownerTarget,
		"proofCommandOrMissingWitness": proofAvailability(closure.Retained),
		"stopCondition":                stopCondition,
		"uncertainty":                  promptUncertainty,
	}, nil
}

func proofAvailability(refs []contextRef) map[string]any {
	witnessRefIDs := contextRefIDsOfKind(refs, "witness")
	if len(witnessRefIDs) == 0 {
		return map[string]any{"state": missingConsumerWitness}
	}
	return map[string]any{
		"state":         retainedConsumerWitness,
		"witnessRefIds": stringsValue(witnessRefIDs),
	}
}

func nullableStringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
