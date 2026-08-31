package changeworkflowplan

var checkpointRelation = buildCheckpointRelation()

func buildCheckpointRelation() []stateRow {
	rows := make([]stateRow, 0, len(workflowCatalog.Stages)*len(workflowCatalog.CheckpointActions)+1)
	for stageIndex, stage := range workflowCatalog.Stages {
		for _, checkpoint := range workflowCatalog.CheckpointActions {
			action := checkpoint.Action
			if checkpoint.UseStageAction {
				action = stage.FirstAction
			}
			profile, ok := actionProfileFor(action)
			if !ok {
				panic("workflow catalog action has no profile")
			}
			rows = append(rows, stateRow{
				Action:          action,
				ActiveStageID:   stage.ID,
				CheckpointState: checkpoint.State,
				CompletedCount:  stageIndex,
				EmitsSuccessor:  profile.EmitsSuccessorDelta,
				OutputKind:      "next_action",
				RequiresSubject: checkpointRequiresSubject(checkpoint, stage),
				RequiresWitness: profile.RequiresWitness,
			})
		}
	}
	return append(rows, stateRow{CompletedCount: len(workflowCatalog.Stages), OutputKind: "workflow_complete", Terminal: true})
}

func decide(input admittedInput) (stateDecision, error) {
	for _, row := range checkpointRelation {
		if row.CompletedCount != len(input.CompletedStageIDs) {
			continue
		}
		if row.Terminal {
			if input.Checkpoint != nil {
				return stateDecision{}, invalidState("terminal checkpoint is non-null")
			}
			return stateDecision{OutputKind: row.OutputKind}, nil
		}
		if input.Checkpoint == nil || input.Checkpoint.State != row.CheckpointState {
			continue
		}
		decision := stateDecision{
			Action:          row.Action,
			ActiveStageID:   row.ActiveStageID,
			CheckpointState: row.CheckpointState,
			OutputKind:      row.OutputKind,
			RequiresSubject: row.RequiresSubject,
			RequiresWitness: row.RequiresWitness,
		}
		if row.EmitsSuccessor {
			completed := append(cloneStrings(input.CompletedStageIDs), row.ActiveStageID)
			var nextCheckpoint *checkpoint
			if len(completed) < len(workflowCatalog.Stages) {
				initial := initialCheckpointDefinition()
				nextCheckpoint = &checkpoint{
					FindingRefs:   []string{},
					State:         initial.State,
					SubjectDigest: input.Checkpoint.SubjectDigest,
					SubjectRefID:  input.Checkpoint.SubjectRefID,
				}
			}
			decision.SuccessorStateDelta = &successorStateDelta{Checkpoint: nextCheckpoint, CompletedStageIDs: completed}
		}
		return decision, nil
	}
	return stateDecision{}, invalidState("no checkpoint relation row matched")
}

// MergeSuccessor applies the only fields owned by a successor delta and
// returns a fresh input value for ordinary admission tests and integrations.
func MergeSuccessor(prior map[string]any, delta map[string]any) (map[string]any, error) {
	if err := knownKeys(delta, []string{"checkpoint", "completedStageIds"}, "proofkit.workflow.successor_delta_fields"); err != nil {
		return nil, err
	}
	if _, ok := delta["checkpoint"]; !ok {
		return nil, reject("proofkit.workflow.successor_delta_fields", "successor delta is missing checkpoint")
	}
	if _, ok := delta["completedStageIds"]; !ok {
		return nil, reject("proofkit.workflow.successor_delta_fields", "successor delta is missing completedStageIds")
	}
	merged := make(map[string]any, len(prior))
	for key, value := range prior {
		merged[key] = cloneJSONValue(value)
	}
	merged["completedStageIds"] = cloneJSONValue(delta["completedStageIds"])
	merged["checkpoint"] = cloneJSONValue(delta["checkpoint"])
	if _, err := admitInput(merged); err != nil {
		return nil, err
	}
	return merged, nil
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = cloneJSONValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = cloneJSONValue(child)
		}
		return result
	default:
		return typed
	}
}
