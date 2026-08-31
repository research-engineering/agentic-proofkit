package changeworkflowplan

const (
	promptUncertainty = "Caller-declared context, digests, checkpoint state, and external state are unauthenticated."
	promptNonClaim    = "This packet does not prove execution, correctness, review quality, merge approval, release approval, rollout, or production readiness."
	missingOwnerStop  = "Do not mutate the repository until the caller supplies the consuming-repository semantic owner and governing authority coordinates."
)

type actionProfile struct {
	CandidateAction        string
	ExpectedNextCheckpoint string
	StopCondition          string
}

var promptProfiles = map[string]actionProfile{
	"author": {
		CandidateAction:        "Author only the active-stage artifact under the consuming repository's semantic owner and bind the result to a caller-owned artifact reference and digest.",
		StopCondition:          "Stop after the artifact and digest are ready for independent review.",
		ExpectedNextCheckpoint: "ready_for_review",
	},
	"implement": {
		CandidateAction:        "Implement only the accepted owner-scoped plan, preserving its non-claims and adding its native positive and negative proof paths.",
		StopCondition:          "Stop after the implementation artifact and digest are ready for independent review.",
		ExpectedNextCheckpoint: "ready_for_review",
	},
	"verify": {
		CandidateAction:        "Run the consuming repository's positive controls and independent near-miss falsifiers against the exact caller-declared subject.",
		StopCondition:          "Stop after bounded verification evidence and its subject digest are ready for independent review.",
		ExpectedNextCheckpoint: "ready_for_review",
	},
	"open_pull_request": {
		CandidateAction:        "Open a pull request only under consuming-repository policy for the exact reviewed head and expose its native checks without claiming merge authority.",
		StopCondition:          "Stop after the pull-request artifact and exact head digest are ready for independent review.",
		ExpectedNextCheckpoint: "ready_for_review",
	},
	"closeout": {
		CandidateAction:        "Assemble bounded closeout evidence for the exact reviewed subject without merging, releasing, rolling out, or declaring production readiness.",
		StopCondition:          "Stop after the closeout artifact and digest are ready for independent review.",
		ExpectedNextCheckpoint: "ready_for_review",
	},
	"review": {
		CandidateAction:        "Independently attempt to falsify the active-stage artifact under its declared owner, bounds, non-claims, and exact subject digest.",
		StopCondition:          "Stop with review_findings bound to every admitted finding, or review_passed bound to the unchanged assessed subject digest.",
		ExpectedNextCheckpoint: "review_findings_or_review_passed",
	},
	"repair": {
		CandidateAction:        "Repair every referenced finding under the same semantic owner, produce a new subject digest, and do not emit a pass claim.",
		StopCondition:          "Stop when the repaired artifact and new digest are ready for another independent review.",
		ExpectedNextCheckpoint: "ready_for_review",
	},
	"accept_stage": {
		CandidateAction:        "Apply only the reported successorStateDelta to the prior snapshot, preserve all context fields byte-for-byte, and submit the merged snapshot for ordinary admission.",
		StopCondition:          "Stop after constructing the merged immutable snapshot; do not infer execution, approval, merge, or release from stage acceptance.",
		ExpectedNextCheckpoint: "successor_state_delta",
	},
}

func buildPrompt(input admittedInput, decision stateDecision, closure closureResult) (map[string]any, error) {
	profile, ok := promptProfiles[decision.Action]
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
	if input.Checkpoint != nil && input.Checkpoint.State != "not_started" {
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
		"proofCommandOrMissingWitness": map[string]any{"state": missingConsumerWitness},
		"stopCondition":                stopCondition,
		"uncertainty":                  promptUncertainty,
	}, nil
}

func nullableStringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
