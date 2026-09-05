package repositorytransaction

import (
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
)

func resultWithObservedPrefix(root *os.Root, plan Plan, result Result) Result {
	prefix, err := classifyPrefix(root, plan)
	if err == nil {
		result.AppliedCount = prefix
		result.AppliedCountKnown = true
	}
	return result
}

func prefixForState(plan Plan, state string) int {
	if state == StateApplied {
		return changedCount(plan)
	}
	return 0
}

func classifyPrefix(root *os.Root, plan Plan) (int, error) {
	prefix := 0
	seenBefore := false
	for _, operation := range plan.Operations {
		if operation.Action == ActionUnchanged {
			observed, _, err := inspectTarget(root, operation.Path, MaximumFileBytes)
			if err != nil || !equalSnapshot(observed, operation.After) {
				return 0, fmt.Errorf("repository transaction unchanged target state changed")
			}
			continue
		}
		observed, _, err := inspectTarget(root, operation.Path, MaximumFileBytes)
		if err != nil {
			return 0, err
		}
		switch {
		case equalSnapshot(observed, operation.After):
			if seenBefore {
				return 0, fmt.Errorf("repository transaction target vector is not a legal prefix")
			}
			prefix++
		case equalSnapshot(observed, operation.Before):
			seenBefore = true
		default:
			return 0, fmt.Errorf("repository transaction target state is unknown")
		}
	}
	return prefix, nil
}

func verifyTargetVector(root *os.Root, plan Plan, expectedPrefix int) error {
	prefix, err := classifyPrefix(root, plan)
	if err != nil || prefix != expectedPrefix {
		return fmt.Errorf("repository transaction target snapshot changed")
	}
	return nil
}

func validateExecutablePlan(plan Plan, rootID string) error {
	if plan.RootID != rootID || plan.DesiredStateID == "" || plan.TransactionID == "" || len(plan.Operations) == 0 || len(plan.Operations) > MaximumOperations {
		return fmt.Errorf("repository transaction plan is not executable for this root")
	}
	// Empty payloads survive wire projection; only native construction binds
	// execution to the complete immutable transaction identity.
	if plan.constructedTransactionID != plan.TransactionID {
		return fmt.Errorf("repository transaction plan lacks native construction for this identity")
	}
	if _, err := admitJournal(journalValue(plan)); err != nil {
		return fmt.Errorf("repository transaction plan semantic admission failed")
	}
	for index, operation := range plan.Operations {
		if operation.After.Mode != operation.After.Mode.Perm() || operation.Before.Mode != operation.Before.Mode.Perm() {
			return fmt.Errorf("repository transaction plan mode contains non-permission bits")
		}
		if !contentMatches(operation.afterContent, operation.After) {
			return fmt.Errorf("repository transaction plan after content is invalid")
		}
		if operation.Before.Exists && !contentMatches(operation.beforeContent, operation.Before) {
			return fmt.Errorf("repository transaction plan before content is invalid")
		}
		if !operation.Before.Exists && len(operation.beforeContent) != 0 {
			return fmt.Errorf("repository transaction plan before content is invalid")
		}
		if operation.Path == "" || transactionTemporaryPath(plan.TransactionID, index, operation.Path) == "" {
			return fmt.Errorf("repository transaction plan path is invalid")
		}
	}
	return nil
}

func validateActivePlan(plan Plan) error {
	if changedCount(plan) == 0 {
		return fmt.Errorf("repository transaction active plan requires at least one changed target")
	}
	return nil
}

func verifyCreatedDirectories(root *os.Root, plan Plan) error {
	directorySet := map[string]struct{}{}
	for _, operation := range plan.Operations {
		missing, err := inspectParentDirectories(root, path.Dir(operation.Path))
		if err != nil {
			return err
		}
		for _, directory := range missing {
			directorySet[directory] = struct{}{}
		}
	}
	want := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		want = append(want, directory)
	}
	sort.Strings(want)
	if !slices.Equal(plan.CreatedDirectories, want) {
		return fmt.Errorf("repository transaction created directories do not match the target snapshot")
	}
	return nil
}

func changedOperationIndexes(plan Plan) []int {
	indexes := []int{}
	for index, operation := range plan.Operations {
		if operation.Action != ActionUnchanged {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func changedCount(plan Plan) int {
	return len(changedOperationIndexes(plan))
}
