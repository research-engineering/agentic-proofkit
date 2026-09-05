package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
)

var ErrRecoveryRequired = errors.New("repository transaction recovery is required")
var ErrBusy = errors.New("repository transaction is busy")

type RecoveryRequiredError struct {
	TransactionID string
}

func (err *RecoveryRequiredError) Error() string {
	return ErrRecoveryRequired.Error()
}

func (err *RecoveryRequiredError) Unwrap() error {
	return ErrRecoveryRequired
}

func RecoveryTransactionID(err error) (string, bool) {
	var pending *RecoveryRequiredError
	if !errors.As(err, &pending) || pending.TransactionID == "" {
		return "", false
	}
	return pending.TransactionID, true
}

func BuildPlan(ctx context.Context, rootPath string, targets []Target) (Plan, error) {
	if err := ctx.Err(); err != nil {
		return Plan{}, fmt.Errorf("repository transaction planning interrupted: %w", err)
	}
	if len(targets) == 0 || len(targets) > MaximumOperations {
		return Plan{}, fmt.Errorf("repository transaction target count must be between 1 and %d", MaximumOperations)
	}
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		return Plan{}, err
	}
	defer root.Close()
	if pending, err := pendingTransactionState(root); err != nil {
		return Plan{}, err
	} else if pending.Exists {
		return Plan{}, &RecoveryRequiredError{TransactionID: pending.TransactionID}
	}

	ordered := make([]Target, len(targets))
	for index, target := range targets {
		ordered[index] = target
		ordered[index].Content = append([]byte(nil), target.Content...)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Path < ordered[right].Path })
	plan := Plan{RootID: rootID}
	directories := map[string]struct{}{}
	prefixSpellings := map[string]string{}
	var aggregate int64
	validatedPaths := make([]string, 0, len(ordered))
	for index, target := range ordered {
		if err := ctx.Err(); err != nil {
			return Plan{}, fmt.Errorf("repository transaction planning interrupted: %w", err)
		}
		targetPath, err := admit.SafeRepoRelativePath(target.Path, fmt.Sprintf("repository transaction target %d path", index))
		if err != nil {
			return Plan{}, err
		}
		if err := registerPortablePrefixes(prefixSpellings, targetPath); err != nil {
			return Plan{}, fmt.Errorf("repository transaction target %d path has an invalid portable identity: %w", index, err)
		}
		if pathsOverlap(targetPath, ControlRoot) {
			return Plan{}, fmt.Errorf("repository transaction target must not overlap the transaction control directory")
		}
		for _, existingPath := range validatedPaths {
			if pathsOverlap(targetPath, existingPath) {
				return Plan{}, fmt.Errorf("repository transaction target paths must be unique and non-overlapping")
			}
		}
		validatedPaths = append(validatedPaths, targetPath)
		if target.Absent && (target.Mode != 0 || len(target.Content) != 0) {
			return Plan{}, fmt.Errorf("repository transaction absent target %d must have no content or mode", index)
		}
		if !target.Absent && (target.Mode == 0 || target.Mode&^fs.ModePerm != 0 || target.Mode.Perm()&0o400 == 0) {
			return Plan{}, fmt.Errorf("repository transaction target %d mode is invalid", index)
		}
		if len(target.Content) > MaximumFileBytes {
			return Plan{}, fmt.Errorf("repository transaction target %d exceeds the file byte limit", index)
		}
		missing, err := inspectParentDirectories(root, path.Dir(targetPath))
		if err != nil {
			return Plan{}, err
		}
		if !target.Absent {
			for _, directory := range missing {
				directories[directory] = struct{}{}
			}
		}
		before, beforeContent, err := inspectTarget(root, targetPath, MaximumFileBytes)
		if err != nil {
			return Plan{}, err
		}
		if before.Exists && before.Mode.Perm()&0o400 == 0 {
			return Plan{}, fmt.Errorf("repository transaction target %d existing mode is not owner-readable", index)
		}
		after := Snapshot{}
		if !target.Absent {
			after = snapshotForContent(target.Content, target.Mode)
		}
		aggregate += before.ByteCount + after.ByteCount
		if aggregate > MaximumAggregateBytes {
			return Plan{}, fmt.Errorf("repository transaction exceeds the aggregate byte limit")
		}
		action := snapshotAction(before, after)
		if action == ActionDelete {
			if err := verifyDeletionFilesystem(root, targetPath); err != nil {
				return Plan{}, err
			}
		}
		plan.Operations = append(plan.Operations, Operation{
			Action:        action,
			After:         after,
			Before:        before,
			Path:          targetPath,
			afterContent:  append([]byte(nil), target.Content...),
			beforeContent: beforeContent,
		})
	}
	for directory := range directories {
		plan.CreatedDirectories = append(plan.CreatedDirectories, directory)
	}
	sort.Strings(plan.CreatedDirectories)
	desiredStateID, err := digest.StableJSONSHA256Ref(desiredStateIdentityValue(plan))
	if err != nil {
		return Plan{}, fmt.Errorf("derive repository desired-state identity: %w", err)
	}
	plan.DesiredStateID = desiredStateID
	identity := planIdentityValue(plan)
	transactionID, err := digest.StableJSONSHA256Ref(identity)
	if err != nil {
		return Plan{}, fmt.Errorf("derive repository transaction identity: %w", err)
	}
	plan.TransactionID = transactionID
	if _, err := AdmitPlanOutput(plan.JSONValue()); err != nil {
		return Plan{}, fmt.Errorf("admit repository transaction plan output: %w", err)
	}
	plan.constructedTransactionID = plan.TransactionID
	return plan, nil
}

func registerPortablePrefixes(spellings map[string]string, value string) error {
	prefixes, err := pathidentity.Prefixes(value)
	if err != nil {
		return err
	}
	for _, prefix := range prefixes {
		if prior, exists := spellings[prefix.Key]; exists && prior != prefix.Path {
			return fmt.Errorf("path prefix %q conflicts with portable spelling %q", prefix.Path, prior)
		}
		spellings[prefix.Key] = prefix.Path
	}
	return nil
}

func validatePortablePathSet(paths []string) error {
	spellings := map[string]string{}
	for _, value := range paths {
		if err := registerPortablePrefixes(spellings, value); err != nil {
			return err
		}
	}
	return nil
}

func desiredStateIdentityValue(plan Plan) map[string]any {
	targets := make([]any, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		targets = append(targets, map[string]any{
			"after": snapshotValue(operation.After),
			"path":  operation.Path,
		})
	}
	return map[string]any{
		"desiredStateKind": "proofkit.repository-desired-state",
		"rootId":           plan.RootID,
		"schemaVersion":    plan.schemaVersion(),
		"targets":          targets,
	}
}

func planIdentityValue(plan Plan) map[string]any {
	value := plan.JSONValue()
	delete(value, "nonClaims")
	delete(value, "transactionId")
	delete(value, "transactionKind")
	return value
}

func snapshotForContent(content []byte, mode fs.FileMode) Snapshot {
	return Snapshot{
		ByteCount: int64(len(content)),
		Exists:    true,
		Mode:      mode.Perm(),
		SHA256:    digest.SHA256BytesRef(content),
	}
}

func equalSnapshot(left, right Snapshot) bool {
	return left.Exists == right.Exists && left.ByteCount == right.ByteCount && left.Mode == right.Mode && left.SHA256 == right.SHA256
}

func snapshotAction(before, after Snapshot) string {
	switch {
	case equalSnapshot(before, after):
		return ActionUnchanged
	case !after.Exists:
		return ActionDelete
	case !before.Exists:
		return ActionCreate
	default:
		return ActionReplace
	}
}

func pathsOverlap(left, right string) bool {
	overlaps, err := pathidentity.Overlaps(left, right)
	return err != nil || overlaps
}

func isLexicalDescendant(candidate, directory string) bool {
	return strings.HasPrefix(candidate, directory+"/")
}
