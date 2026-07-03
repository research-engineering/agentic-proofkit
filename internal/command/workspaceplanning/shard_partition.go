package workspaceplanning

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func BuildShardPartition(raw any) (map[string]any, int, error) {
	input, err := admitShardInput(raw)
	if err != nil {
		return nil, 1, err
	}
	report := buildShardPartition(input)
	exitCode := 0
	if len(stringArrayFromAny(report["failures"])) > 0 {
		exitCode = 1
	}
	return report, exitCode, nil
}

func buildShardPartition(input shardInput) map[string]any {
	rootNames := packageNodeNames(input.Roots)
	rootSet := toSet(rootNames)
	seenRoots := map[string]struct{}{}
	seenExecutions := map[string]struct{}{}
	failures := []string{}
	if _, err := nodeMap(input.Packages); err != nil {
		failures = append(failures, err.Error())
	}
	if duplicate := firstDuplicate(rootNames); duplicate != "" {
		failures = append(failures, "workspace shard root package must be unique: "+duplicate)
	}
	shards := []map[string]any{}
	for index := 0; index < input.ShardTotal; index++ {
		roots, err := selectShardRoots(input.Roots, index, input.ShardTotal)
		if err != nil {
			failures = append(failures, err.Error())
		}
		if len(roots) == 0 {
			failures = append(failures, fmt.Sprintf("Shard %d/%d has no owned packages", index+1, input.ShardTotal))
		}
		closure, closureFailures := safeNodeList(func() ([]dependencyNode, error) { return dependencyClosure(input.Packages, roots) })
		failures = append(failures, closureFailures...)
		executionTargets, executionFailures := safeNodeList(func() ([]dependencyNode, error) { return topological(roots) })
		failures = append(failures, executionFailures...)
		closureNames := toSet(packageNodeNames(closure))
		for _, target := range roots {
			if _, ok := rootSet[target.Name]; !ok {
				failures = append(failures, fmt.Sprintf("shard %d owns unknown package %s", index, target.Name))
			}
			if _, ok := seenRoots[target.Name]; ok {
				failures = append(failures, fmt.Sprintf("package %s appears in multiple shards", target.Name))
			}
			if _, ok := closureNames[target.Name]; !ok {
				failures = append(failures, fmt.Sprintf("shard %d dependency closure omits owned package %s", index, target.Name))
			}
			seenRoots[target.Name] = struct{}{}
		}
		for _, target := range executionTargets {
			if _, ok := seenExecutions[target.Name]; ok {
				failures = append(failures, fmt.Sprintf("package %s executes in multiple roots-only shards", target.Name))
			}
			seenExecutions[target.Name] = struct{}{}
		}
		shards = append(shards, map[string]any{
			"dependencyClosurePackageNames": stringsToAny(packageNodeNames(closure)),
			"executionPackageNames":         stringsToAny(packageNodeNames(executionTargets)),
			"rootPackageNames":              stringsToAny(packageNodeNames(roots)),
			"shardIndex":                    index,
			"shardLabel":                    fmt.Sprintf("%d-of-%d", index+1, input.ShardTotal),
			"shardTotal":                    input.ShardTotal,
		})
	}
	if len(seenRoots) != len(rootSet) {
		failures = append(failures, fmt.Sprintf("sharded package coverage %d did not match %d", len(seenRoots), len(rootSet)))
	}
	if len(seenExecutions) != len(rootSet) {
		failures = append(failures, fmt.Sprintf("sharded package execution %d did not match %d", len(seenExecutions), len(rootSet)))
	}
	failures = uniqueInOrder(failures)
	matrix := []any{}
	for _, shard := range shards {
		matrix = append(matrix, map[string]any{
			"shard_index": shard["shardIndex"],
			"shard_label": shard["shardLabel"],
			"shard_total": shard["shardTotal"],
		})
	}
	return map[string]any{
		"failures":         stringsToAny(failures),
		"packageShards":    map[string]any{"include": matrix},
		"rootPackageCount": len(rootSet),
		"rootPackageNames": stringsToAny(keysInObservedOrder(rootNames)),
		"schemaVersion":    1,
		"shardTotal":       input.ShardTotal,
		"shards":           mapsToAny(shards),
	}
}

func admitShardInput(raw any) (shardInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return shardInput{}, fmt.Errorf("workspace shard partition input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"packages", "roots", "schemaVersion", "shardTotal"}, "workspace shard partition input"); err != nil {
		return shardInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return shardInput{}, fmt.Errorf("workspace shard partition schemaVersion must be 1")
	}
	packages, err := dependencyNodeInputs(require(record, "packages"))
	if err != nil {
		return shardInput{}, err
	}
	roots, err := dependencyNodeInputs(require(record, "roots"))
	if err != nil {
		return shardInput{}, err
	}
	shardTotal, err := admit.PositiveInteger(require(record, "shardTotal"), "workspace shard total")
	if err != nil {
		return shardInput{}, err
	}
	return shardInput{Packages: packages, Roots: roots, ShardTotal: shardTotal}, nil
}

func selectShardRoots(roots []dependencyNode, index int, total int) ([]dependencyNode, error) {
	if total <= 0 {
		return nil, fmt.Errorf("workspace shard total must be positive")
	}
	if index < 0 || index >= total {
		return nil, fmt.Errorf("workspace shard index must be less than workspace shard total")
	}
	result := []dependencyNode{}
	for rootIndex, root := range roots {
		if rootIndex%total == index {
			result = append(result, root)
		}
	}
	return result, nil
}

func safeNodeList(fn func() ([]dependencyNode, error)) ([]dependencyNode, []string) {
	values, err := fn()
	if err != nil {
		return []dependencyNode{}, []string{err.Error()}
	}
	return values, []string{}
}
