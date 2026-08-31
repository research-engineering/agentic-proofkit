package changeworkflowplan

import "sort"

func leastClosure(input admittedInput) (closureResult, error) {
	byID := make(map[string]contextRef, len(input.ContextRefs))
	for _, ref := range input.ContextRefs {
		byID[ref.RefID] = ref
	}
	seeds := make([]string, 0, len(input.RequiredContextRefIDs)+maxFindings+2)
	seeds = append(seeds, input.RequiredContextRefIDs...)
	if input.GoverningAuthorityRefID != nil {
		seeds = append(seeds, *input.GoverningAuthorityRefID)
	}
	if input.Checkpoint != nil && input.Checkpoint.State != "not_started" {
		seeds = append(seeds, input.Checkpoint.SubjectRefID)
		seeds = append(seeds, input.Checkpoint.FindingRefs...)
	}
	sort.Strings(seeds)
	selected := make(map[string]struct{}, len(seeds))
	pending := append([]string{}, seeds...)
	for len(pending) > 0 {
		id := pending[0]
		pending = pending[1:]
		if _, exists := selected[id]; exists {
			continue
		}
		ref, exists := byID[id]
		if !exists {
			return closureResult{}, reject("proofkit.workflow.context_seed_missing", "a closure seed does not resolve")
		}
		selected[id] = struct{}{}
		pending = append(pending, ref.DependencyRefIDs...)
	}
	result := closureResult{Omitted: []contextRef{}, Retained: []contextRef{}}
	retainedPathBytes := 0
	for _, ref := range input.ContextRefs {
		if _, ok := selected[ref.RefID]; ok {
			result.Retained = append(result.Retained, ref)
			retainedPathBytes += len(ref.ArtifactPath)
			continue
		}
		result.Omitted = append(result.Omitted, ref)
	}
	if retainedPathBytes > maxRetainedPathBytes {
		return closureResult{}, reject("proofkit.workflow.retained_path_bytes_exceeded", "retained context paths exceed the byte limit")
	}
	if len(result.Retained) > maxRetainedContextRefs {
		return closureResult{}, reject("proofkit.workflow.retained_context_limit_exceeded", "retained context exceeds the reference limit")
	}
	return result, nil
}

func contextRefIDs(refs []contextRef) []string {
	result := make([]string, len(refs))
	for index, ref := range refs {
		result[index] = ref.RefID
	}
	return result
}

func contextRefPaths(refs []contextRef) []string {
	result := make([]string, len(refs))
	for index, ref := range refs {
		result[index] = ref.ArtifactPath
	}
	return result
}

func contextRefsValue(refs []contextRef) []any {
	result := make([]any, 0, len(refs))
	for _, ref := range refs {
		result = append(result, map[string]any{
			"artifactPath":     ref.ArtifactPath,
			"dependencyRefIds": stringsValue(ref.DependencyRefIDs),
			"refId":            ref.RefID,
			"refKind":          ref.RefKind,
			"subjectDigest":    ref.SubjectDigest,
		})
	}
	return result
}

func stringsValue(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
