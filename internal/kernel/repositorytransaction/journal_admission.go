package repositorytransaction

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func journalValue(plan Plan) map[string]any {
	operations := make([]any, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		operations = append(operations, operationValue(operation))
	}
	return map[string]any{
		"createdDirectories": admit.StringSliceToAny(plan.CreatedDirectories),
		"desiredStateId":     plan.DesiredStateID,
		"journalKind":        "proofkit.repository-write-journal",
		"operations":         operations,
		"rootId":             plan.RootID,
		"schemaVersion":      json.Number("1"),
		"transactionId":      plan.TransactionID,
	}
}

func admitJournal(raw any) (Plan, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Plan{}, fmt.Errorf("repository transaction journal must be an object")
	}
	if err := admit.KnownKeys(record, []string{"createdDirectories", "desiredStateId", "journalKind", "operations", "rootId", "schemaVersion", "transactionId"}, "repository transaction journal"); err != nil {
		return Plan{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["journalKind"] != "proofkit.repository-write-journal" {
		return Plan{}, fmt.Errorf("repository transaction journal identity is invalid")
	}
	rootID, err := admit.SHA256Ref(record["rootId"], "repository transaction rootId")
	if err != nil {
		return Plan{}, err
	}
	transactionID, err := admit.SHA256Ref(record["transactionId"], "repository transaction transactionId")
	if err != nil {
		return Plan{}, err
	}
	desiredStateID, err := admit.SHA256Ref(record["desiredStateId"], "repository transaction desiredStateId")
	if err != nil {
		return Plan{}, err
	}
	directories, err := admit.PreserveSortedPathArray(record["createdDirectories"], "repository transaction createdDirectories", true)
	if err != nil {
		return Plan{}, err
	}
	for _, directory := range directories {
		if pathsOverlap(directory, ControlRoot) {
			return Plan{}, fmt.Errorf("repository transaction created directory overlaps its control directory")
		}
	}
	values, ok := record["operations"].([]any)
	if !ok || len(values) == 0 || len(values) > MaximumOperations {
		return Plan{}, fmt.Errorf("repository transaction journal operation count is invalid")
	}
	operations := make([]Operation, 0, len(values))
	previous := ""
	for index, value := range values {
		operation, err := admitOperation(value, index)
		if err != nil {
			return Plan{}, err
		}
		if previous != "" && previous >= operation.Path {
			return Plan{}, fmt.Errorf("repository transaction operations must be sorted and unique")
		}
		previous = operation.Path
		operations = append(operations, operation)
	}
	plan := Plan{CreatedDirectories: directories, DesiredStateID: desiredStateID, Operations: operations, RootID: rootID, TransactionID: transactionID}
	if err := validatePlanShape(plan); err != nil {
		return Plan{}, err
	}
	wantDesiredStateID, err := digest.StableJSONSHA256Ref(desiredStateIdentityValue(plan))
	if err != nil || wantDesiredStateID != desiredStateID {
		return Plan{}, fmt.Errorf("repository transaction desired-state identity does not match its targets")
	}
	wantID, err := digest.StableJSONSHA256Ref(planIdentityValue(plan))
	if err != nil || wantID != transactionID {
		return Plan{}, fmt.Errorf("repository transaction journal identity does not match its content")
	}
	return plan, nil
}

func admitOperation(raw any, index int) (Operation, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Operation{}, fmt.Errorf("repository transaction operation %d must be an object", index)
	}
	if err := admit.KnownKeys(record, []string{"action", "after", "before", "path"}, fmt.Sprintf("repository transaction operation %d", index)); err != nil {
		return Operation{}, err
	}
	targetPath, err := admit.SafeRepoRelativePath(recordText(record["path"]), fmt.Sprintf("repository transaction operation %d path", index))
	if err != nil {
		return Operation{}, err
	}
	if pathsOverlap(targetPath, ControlRoot) {
		return Operation{}, fmt.Errorf("repository transaction operation overlaps its control directory")
	}
	action, ok := record["action"].(string)
	if !ok || (action != ActionCreate && action != ActionReplace && action != ActionUnchanged) {
		return Operation{}, fmt.Errorf("repository transaction operation %d action is invalid", index)
	}
	before, err := admitSnapshot(record["before"], fmt.Sprintf("repository transaction operation %d before", index))
	if err != nil {
		return Operation{}, err
	}
	after, err := admitSnapshot(record["after"], fmt.Sprintf("repository transaction operation %d after", index))
	if err != nil || !after.Exists {
		return Operation{}, fmt.Errorf("repository transaction operation %d after snapshot is invalid", index)
	}
	wantAction := ActionCreate
	if before.Exists {
		wantAction = ActionReplace
		if equalSnapshot(before, after) {
			wantAction = ActionUnchanged
		}
	}
	if action != wantAction {
		return Operation{}, fmt.Errorf("repository transaction operation %d action contradicts its snapshots", index)
	}
	return Operation{Action: action, After: after, Before: before, Path: targetPath}, nil
}

func admitSnapshot(raw any, context string) (Snapshot, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Snapshot{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"byteCount", "exists", "mode", "sha256"}, context); err != nil {
		return Snapshot{}, err
	}
	exists, err := admit.Bool(record["exists"], context+" exists")
	if err != nil {
		return Snapshot{}, err
	}
	byteCount, err := admit.CanonicalInteger(record["byteCount"], context+" byteCount")
	if err != nil || byteCount < 0 || byteCount > MaximumFileBytes {
		return Snapshot{}, fmt.Errorf("%s byteCount is invalid", context)
	}
	mode, err := parseMode(record["mode"], context+" mode")
	if err != nil {
		return Snapshot{}, err
	}
	sha := ""
	if record["sha256"] != nil {
		sha, err = admit.SHA256Ref(record["sha256"], context+" sha256")
		if err != nil {
			return Snapshot{}, err
		}
	}
	if exists && (sha == "" || mode == 0 || mode.Perm()&0o400 == 0) {
		return Snapshot{}, fmt.Errorf("%s existing snapshot is incomplete", context)
	}
	if !exists && (sha != "" || mode != 0 || byteCount != 0) {
		return Snapshot{}, fmt.Errorf("%s missing snapshot must have zero metadata", context)
	}
	return Snapshot{ByteCount: byteCount, Exists: exists, Mode: mode, SHA256: sha}, nil
}

func validatePlanShape(plan Plan) error {
	if len(plan.Operations) == 0 || len(plan.Operations) > MaximumOperations {
		return fmt.Errorf("repository transaction operation count is invalid")
	}
	var aggregate int64
	paths := make([]string, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		for _, existingPath := range paths {
			if pathsOverlap(operation.Path, existingPath) {
				return fmt.Errorf("repository transaction operation paths must be unique and non-overlapping")
			}
		}
		if pathsOverlap(operation.Path, ControlRoot) {
			return fmt.Errorf("repository transaction operation overlaps its control directory")
		}
		paths = append(paths, operation.Path)
		aggregate += operation.Before.ByteCount + operation.After.ByteCount
		if aggregate > MaximumAggregateBytes {
			return fmt.Errorf("repository transaction exceeds the aggregate byte limit")
		}
	}
	portablePaths := append(append([]string(nil), paths...), plan.CreatedDirectories...)
	if err := validatePortablePathSet(portablePaths); err != nil {
		return fmt.Errorf("repository transaction paths have conflicting portable identities: %w", err)
	}
	for _, directory := range plan.CreatedDirectories {
		if pathsOverlap(directory, ControlRoot) {
			return fmt.Errorf("repository transaction created directory overlaps its control directory")
		}
		ownsTarget := false
		for _, operation := range plan.Operations {
			if isLexicalDescendant(operation.Path, directory) {
				ownsTarget = true
				break
			}
		}
		if !ownsTarget {
			return fmt.Errorf("repository transaction created directory does not own a target")
		}
	}
	return nil
}

func recordText(value any) string {
	text, _ := value.(string)
	return text
}
