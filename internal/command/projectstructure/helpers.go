package projectstructure

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func object(raw any, context string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	return record, nil
}

func mapValue(raw any) map[string]any {
	if record, ok := raw.(map[string]any); ok {
		return record
	}
	return map[string]any{}
}

func anyArray(raw any) []any {
	if values, ok := raw.([]any); ok {
		return values
	}
	return []any{}
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func safePath(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be a repository-relative POSIX path", context)
	}
	return admit.SafeRepoRelativePath(strings.TrimSpace(value), context)
}

func stringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func stringTrim(value string) string {
	return strings.TrimSpace(value)
}

func containsString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func takeMaps(values []map[string]any, limit int) []map[string]any {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func contextRefIDs(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value["refId"])
	}
	return result
}

func commandIDs(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value["commandId"])
	}
	return result
}

func omittedCount(values []map[string]any) int {
	count := 0
	for _, value := range values {
		if itemCount, ok := value["omittedCount"].(int); ok {
			count += itemCount
		}
	}
	return count
}
