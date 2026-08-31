package changeworkflowplan

const workflowProfileID = "proofkit.reviewed-change.v1"

type stageDefinition struct {
	ID          string
	FirstAction string
}

type checkpointDefinition struct {
	State          string
	Action         string
	UseStageAction bool
}

type actionProfile struct {
	CandidateAction        string
	ExpectedNextCheckpoint string
	StopCondition          string
}

type workflowCatalogDefinition struct {
	Stages            []stageDefinition
	CheckpointActions []checkpointDefinition
	ActionProfiles    map[string]actionProfile
}

var workflowCatalog = workflowCatalogDefinition{
	Stages: []stageDefinition{
		{ID: "architecture", FirstAction: "author"},
		{ID: "design", FirstAction: "author"},
		{ID: "implementation_plan", FirstAction: "author"},
		{ID: "implementation", FirstAction: "implement"},
		{ID: "verification", FirstAction: "verify"},
		{ID: "pull_request", FirstAction: "open_pull_request"},
		{ID: "closeout", FirstAction: "closeout"},
	},
	CheckpointActions: []checkpointDefinition{
		{State: "not_started", UseStageAction: true},
		{State: "ready_for_review", Action: "review"},
		{State: "review_findings", Action: "repair"},
		{State: "review_passed", Action: "accept_stage"},
	},
	ActionProfiles: map[string]actionProfile{
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
	},
}

func actionProfileFor(action string) (actionProfile, bool) {
	profile, ok := workflowCatalog.ActionProfiles[action]
	return profile, ok
}
