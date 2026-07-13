package requirementcontext

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func admitSliceQuery(raw any) (SliceQuery, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return SliceQuery{}, fmt.Errorf("requirement context slice query must be an object")
	}
	if err := admit.KnownKeys(record, []string{"lifecycleStates", "maxDepth", "maxNodes", "maxRequirements", "nodeIds", "ownerIds", "profile", "requirementIds"}, "requirement context slice query"); err != nil {
		return SliceQuery{}, err
	}
	profile, err := admit.Enum(record["profile"], map[string]struct{}{"coverage": {}, "proof": {}, "review": {}, "routing": {}, "specification": {}}, "requirement context slice profile")
	if err != nil {
		return SliceQuery{}, err
	}
	nodeIDs, err := admittedIDs(record["nodeIds"], "requirement context slice nodeIds")
	if err != nil {
		return SliceQuery{}, err
	}
	requirementIDs, err := admittedIDs(record["requirementIds"], "requirement context slice requirementIds")
	if err != nil {
		return SliceQuery{}, err
	}
	ownerIDs, err := admittedIDs(record["ownerIds"], "requirement context slice ownerIds")
	if err != nil {
		return SliceQuery{}, err
	}
	lifecycleStates, err := admittedEnums(record["lifecycleStates"], map[string]struct{}{"active": {}, "deprecated": {}, "removed": {}, "superseded": {}}, "requirement context slice lifecycleStates")
	if err != nil {
		return SliceQuery{}, err
	}
	maxNodes, err := optionalPositiveInteger(record["maxNodes"], 256, "requirement context slice maxNodes")
	if err != nil || maxNodes > 4096 {
		return SliceQuery{}, fmt.Errorf("requirement context slice maxNodes must be between 1 and 4096")
	}
	maxRequirements, err := optionalPositiveInteger(record["maxRequirements"], 2048, "requirement context slice maxRequirements")
	if err != nil || maxRequirements > 16384 {
		return SliceQuery{}, fmt.Errorf("requirement context slice maxRequirements must be between 1 and 16384")
	}
	var maxDepth *int
	if record["maxDepth"] != nil {
		if len(nodeIDs) == 0 {
			return SliceQuery{}, fmt.Errorf("requirement context slice maxDepth requires nodeIds")
		}
		depth, err := nonNegativeInteger(record["maxDepth"], "requirement context slice maxDepth")
		if err != nil || depth > 512 {
			return SliceQuery{}, fmt.Errorf("requirement context slice maxDepth must be between 0 and 512")
		}
		maxDepth = &depth
	}
	if len(nodeIDs)+len(requirementIDs)+len(ownerIDs)+len(lifecycleStates) == 0 && profile != "routing" {
		return SliceQuery{}, fmt.Errorf("requirement context slice requires a selector outside routing profile")
	}
	return SliceQuery{MaxDepth: maxDepth, MaxNodes: maxNodes, MaxRequirements: maxRequirements, NodeIDs: nodeIDs, OwnerIDs: ownerIDs, Profile: profile, RequirementIDs: requirementIDs, LifecycleStates: lifecycleStates}, nil
}

func admittedIDs(raw any, context string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		id, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func admittedEnums(raw any, allowed map[string]struct{}, context string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		item, err := admit.Enum(value, allowed, context)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[item]; ok {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result, nil
}

func optionalPositiveInteger(raw any, fallback int, context string) (int, error) {
	if raw == nil {
		return fallback, nil
	}
	return admit.PositiveInteger(raw, context)
}
func nonNegativeInteger(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	value, err := strconv.Atoi(number.String())
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	return value, nil
}
