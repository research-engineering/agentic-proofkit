package selectivegateplan

import "github.com/research-engineering/agentic-proofkit/internal/kernel/admit"

func commandsJSON(values commandAccumulator) []any {
	result := make([]any, 0, len(values.order))
	for _, key := range values.order {
		result = append(result, commandJSON(values.byKey[key]))
	}
	return result
}

func commandJSON(item command) map[string]any {
	value := map[string]any{"command": item.Command, "id": item.ID, "reason": item.Reason}
	if item.SourcePath != nil {
		value["sourcePath"] = *item.SourcePath
	}
	return value
}

func fallbackCoverageJSON(values []fallbackCoverage) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{"command": commandJSON(item.Command), "edgeClasses": admit.StringSliceToAny(item.EdgeClasses), "reason": item.Reason})
	}
	return result
}

func unknownEdgesJSON(values []unknownEdgeAssessment) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{
			"coverageState":      item.CoverageState,
			"edgeClass":          item.EdgeClass,
			"edgeId":             item.EdgeID,
			"fallbackCommandIds": admit.StringSliceToAny(item.FallbackCommandIDs),
			"path":               item.Path,
			"reason":             item.Reason,
		})
	}
	return result
}

func generatedArtifactObligationsJSON(values []generatedArtifactObligation) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{"generator": item.Generator, "path": item.Path, "reason": item.Reason, "sourceOfTruth": admit.StringSliceToAny(item.SourceOfTruth)})
	}
	return result
}

func artifactIntegrityJSON(values []artifactIntegrityObligation) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{"command": item.Command, "path": item.Path, "policy": item.Policy})
	}
	return result
}

func witnessObligationsJSON(values []witnessObligation) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{"commands": admit.StringSliceToAny(item.Commands), "path": item.Path, "requirementIds": admit.StringSliceToAny(item.RequirementIDs)})
	}
	return result
}

func skippedGatesJSON(values []skippedGate) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{"id": item.ID, "reason": item.Reason})
	}
	return result
}
