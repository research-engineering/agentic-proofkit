package workspaceplanning

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func sortedRepoPaths(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, value := range values {
		pathValue, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, pathValue)
	}
	return sortStrings(result), nil
}

func require(record map[string]any, key string) any {
	return record[key]
}

func stringArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a string array", context)
		}
		result = append(result, text)
	}
	return result, nil
}

func stringArrayFromAny(raw any) []string {
	values, ok := raw.([]any)
	if !ok {
		return []string{}
	}
	result := []string{}
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func pathNodesJSON(values []packagePathNode) []any {
	result := []any{}
	for _, item := range values {
		result = append(result, map[string]any{"dirName": item.DirName, "name": item.Name, "workspaceDependencies": stringsToAny(item.WorkspaceDependencies)})
	}
	return result
}

func packageNames(values []packagePathNode) []string {
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, item.Name)
	}
	return result
}

func packageNodeNames(values []dependencyNode) []string {
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, item.Name)
	}
	return result
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func firstDuplicate(values []string) string {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return values[index]
		}
	}
	return ""
}

func uniqueInOrder(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func keysInObservedOrder(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func sortStrings(values []string) []string {
	sort.Strings(values)
	return values
}
