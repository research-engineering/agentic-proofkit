package requirementcoverageview

import (
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"sort"
)

func mapSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
func anyArray(raw any) []any {
	if values, ok := raw.([]any); ok {
		return values
	}
	return nil
}
func stringArray(raw any) []string {
	values := anyArray(raw)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
func intValue(raw any) int {
	if value, ok := raw.(int); ok {
		return value
	}
	return 0
}
func stringValue(raw any) string {
	if value, ok := raw.(string); ok {
		return value
	}
	return ""
}
func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		value, err := admit.RuleID(item, context)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return admit.PreserveSortedText(result, context, allowEmpty)
}
func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return admit.PreserveSortedText(values, context, allowEmpty)
}
func assertUnique(values []string, context string) error {
	_, err := admit.PreserveSortedText(values, context, true)
	return err
}
func literal(raw any, expected string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || value != expected {
		return "", fmt.Errorf("%s must be %s", context, expected)
	}
	return value, nil
}
func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
			previous = value
		}
	}
	return append([]string{}, result...)
}
