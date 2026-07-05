package selectivegateplan

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

var outputEdgeCoverageStateSet = proofvocab.SelectiveEdgeCoverageStateSet()

type EvidencePlanProjection struct {
	PlanState        string
	RequiredCommands []map[string]any
	Failures         []string
	ChangedPaths     []string
	Generated        []any
	Raw              map[string]any
}

func AdmitEvidencePlan(raw any) (EvidencePlanProjection, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return EvidencePlanProjection{}, fmt.Errorf("selective gate plan output must be an object")
	}
	if err := admit.KnownKeys(record, []string{"artifactIntegrity", "changedPaths", "failures", "fallbackCoverage", "generatedArtifacts", "nonClaims", "planState", "privatePathExclusions", "proofLikePaths", "publicApiContractTouched", "requiredCommands", "schemaVersion", "secretScan", "skippedGates", "touchedRequirementWitnesses", "unknownEdges"}, "selective gate plan output"); err != nil {
		return EvidencePlanProjection{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return EvidencePlanProjection{}, fmt.Errorf("selective gate plan output schemaVersion must be 1")
	}
	state, ok := record["planState"].(string)
	if !ok || (state != "ok" && state != "fail_closed") {
		return EvidencePlanProjection{}, fmt.Errorf("selective gate plan output planState must be ok or fail_closed")
	}
	publicAPITouched, ok := record["publicApiContractTouched"].(bool)
	if !ok {
		return EvidencePlanProjection{}, fmt.Errorf("selective gate plan output publicApiContractTouched must be boolean")
	}
	commands, err := outputCommandRecords(record["requiredCommands"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	failures, err := sortedTextArray(record["failures"], "selective gate plan output failures", true)
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	changedPaths, err := sortedPaths(record["changedPaths"], "selective gate plan output changedPaths", true)
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	generated, err := outputGeneratedArtifactRecords(record["generatedArtifacts"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	fallbackCoverage, err := outputFallbackCoverageRecords(record["fallbackCoverage"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	unknownEdges, err := outputUnknownEdgeRecords(record["unknownEdges"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	touchedWitnesses, err := outputTouchedWitnessRecords(record["touchedRequirementWitnesses"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	artifactIntegrity, err := outputArtifactIntegrityRecords(record["artifactIntegrity"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	proofLikePaths, err := sortedPaths(record["proofLikePaths"], "selective gate plan output proofLikePaths", true)
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	privateExclusions, err := outputPrivatePathExclusionsRecord(record["privatePathExclusions"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	secretScan, err := outputSecretScanRecord(record["secretScan"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	skippedGates, err := outputSkippedGateRecords(record["skippedGates"])
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	nonClaims, err := sortedTextArray(record["nonClaims"], "selective gate plan output nonClaims", true)
	if err != nil {
		return EvidencePlanProjection{}, err
	}
	normalized := map[string]any{}
	for key, value := range record {
		normalized[key] = value
	}
	normalized["artifactIntegrity"] = artifactIntegrity
	normalized["changedPaths"] = admit.StringSliceToAny(changedPaths)
	normalized["failures"] = admit.StringSliceToAny(failures)
	normalized["fallbackCoverage"] = fallbackCoverage
	normalized["generatedArtifacts"] = generated
	normalized["nonClaims"] = admit.StringSliceToAny(nonClaims)
	normalized["privatePathExclusions"] = privateExclusions
	normalized["proofLikePaths"] = admit.StringSliceToAny(proofLikePaths)
	normalized["publicApiContractTouched"] = publicAPITouched
	normalized["requiredCommands"] = mapsToAny(commands)
	normalized["schemaVersion"] = 1
	normalized["secretScan"] = secretScan
	normalized["skippedGates"] = skippedGates
	normalized["touchedRequirementWitnesses"] = touchedWitnesses
	normalized["unknownEdges"] = unknownEdges
	return EvidencePlanProjection{PlanState: state, RequiredCommands: commands, Failures: failures, ChangedPaths: changedPaths, Generated: generated, Raw: normalized}, nil
}

func outputCommandRecords(raw any) ([]map[string]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output requiredCommands")
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(records))
	for _, record := range records {
		item, err := outputCommandRecord(record, "selective gate plan output required command")
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return outputCommandKey(result[left]) < outputCommandKey(result[right])
	})
	return result, nil
}

func outputCommandRecord(raw any, context string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"command", "id", "reason", "sourcePath"}, context); err != nil {
		return nil, err
	}
	id, err := admit.RuleID(record["id"], context+" id")
	if err != nil {
		return nil, err
	}
	commandText, err := admit.DisplayOnlyCommandText(record["command"], context+" command")
	if err != nil {
		return nil, err
	}
	reason, err := admit.NonEmptyText(record["reason"], context+" reason")
	if err != nil {
		return nil, err
	}
	item := map[string]any{"command": commandText, "id": id, "reason": reason}
	if rawSource, ok := record["sourcePath"]; ok {
		source, err := safePath(rawSource, context+" sourcePath")
		if err != nil {
			return nil, err
		}
		item["sourcePath"] = source
	}
	return item, nil
}

func outputGeneratedArtifactRecords(raw any) ([]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output generatedArtifacts")
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"generator", "path", "reason", "sourceOfTruth"}, "selective gate plan output generated artifact"); err != nil {
			return nil, err
		}
		path, err := safePath(record["path"], "selective gate plan output generated artifact path")
		if err != nil {
			return nil, err
		}
		generator, err := admit.NonEmptyText(record["generator"], "selective gate plan output generated artifact generator")
		if err != nil {
			return nil, err
		}
		source, err := sortedPaths(record["sourceOfTruth"], "selective gate plan output generated artifact sourceOfTruth", true)
		if err != nil {
			return nil, err
		}
		reason, err := admit.Enum(record["reason"], map[string]struct{}{"generated_artifact_changed": {}, "source_changed": {}}, "selective gate plan output generated artifact reason")
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"generator": generator, "path": path, "reason": reason, "sourceOfTruth": admit.StringSliceToAny(source)})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].(map[string]any)["path"].(string) < result[right].(map[string]any)["path"].(string)
	})
	return result, nil
}

func outputFallbackCoverageRecords(raw any) ([]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output fallbackCoverage")
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"command", "edgeClasses", "reason"}, "selective gate plan output fallbackCoverage"); err != nil {
			return nil, err
		}
		command, err := outputCommandRecord(record["command"], "selective gate plan output fallbackCoverage command")
		if err != nil {
			return nil, err
		}
		edgeClasses, err := outputEdgeClasses(record["edgeClasses"], "selective gate plan output fallbackCoverage edgeClasses")
		if err != nil {
			return nil, err
		}
		reason, err := admit.NonEmptyText(record["reason"], "selective gate plan output fallbackCoverage reason")
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"command": command, "edgeClasses": admit.StringSliceToAny(edgeClasses), "reason": reason})
	}
	sort.Slice(result, func(left int, right int) bool {
		leftCommand := result[left].(map[string]any)["command"].(map[string]any)
		rightCommand := result[right].(map[string]any)["command"].(map[string]any)
		return leftCommand["id"].(string) < rightCommand["id"].(string)
	})
	return result, nil
}

func outputUnknownEdgeRecords(raw any) ([]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output unknownEdges")
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"coverageState", "edgeClass", "edgeId", "fallbackCommandIds", "path", "reason"}, "selective gate plan output unknownEdge"); err != nil {
			return nil, err
		}
		edgeID, err := admit.RuleID(record["edgeId"], "selective gate plan output unknownEdge edgeId")
		if err != nil {
			return nil, err
		}
		edgeClass, err := admit.Enum(record["edgeClass"], edgeClassSet, "selective gate plan output unknownEdge edgeClass")
		if err != nil {
			return nil, err
		}
		path, err := safePath(record["path"], "selective gate plan output unknownEdge path")
		if err != nil {
			return nil, err
		}
		reason, err := admit.NonEmptyText(record["reason"], "selective gate plan output unknownEdge reason")
		if err != nil {
			return nil, err
		}
		coverageState, err := admit.Enum(record["coverageState"], outputEdgeCoverageStateSet, "selective gate plan output unknownEdge coverageState")
		if err != nil {
			return nil, err
		}
		fallbackIDs, err := sortedTextArray(record["fallbackCommandIds"], "selective gate plan output unknownEdge fallbackCommandIds", true)
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"coverageState": coverageState, "edgeClass": edgeClass, "edgeId": edgeID, "fallbackCommandIds": admit.StringSliceToAny(fallbackIDs), "path": path, "reason": reason})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].(map[string]any)["edgeId"].(string) < result[right].(map[string]any)["edgeId"].(string)
	})
	return result, nil
}

func outputTouchedWitnessRecords(raw any) ([]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output touchedRequirementWitnesses")
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"commands", "path", "requirementIds"}, "selective gate plan output touchedRequirementWitness"); err != nil {
			return nil, err
		}
		path, err := safePath(record["path"], "selective gate plan output touchedRequirementWitness path")
		if err != nil {
			return nil, err
		}
		requirements, err := sortedTextArray(record["requirementIds"], "selective gate plan output touchedRequirementWitness requirementIds", true)
		if err != nil {
			return nil, err
		}
		commands, err := sortedDisplayCommandArray(record["commands"], "selective gate plan output touchedRequirementWitness commands", true)
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"commands": admit.StringSliceToAny(commands), "path": path, "requirementIds": admit.StringSliceToAny(requirements)})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].(map[string]any)["path"].(string) < result[right].(map[string]any)["path"].(string)
	})
	return result, nil
}

func outputArtifactIntegrityRecords(raw any) ([]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output artifactIntegrity")
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"command", "path", "policy"}, "selective gate plan output artifactIntegrity"); err != nil {
			return nil, err
		}
		command, err := admit.DisplayOnlyCommandText(record["command"], "selective gate plan output artifactIntegrity command")
		if err != nil {
			return nil, err
		}
		path, err := safePath(record["path"], "selective gate plan output artifactIntegrity path")
		if err != nil {
			return nil, err
		}
		policy, err := admit.NonEmptyText(record["policy"], "selective gate plan output artifactIntegrity policy")
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"command": command, "path": path, "policy": policy})
	}
	sort.Slice(result, func(left int, right int) bool {
		l := result[left].(map[string]any)
		r := result[right].(map[string]any)
		return l["path"].(string)+"\x00"+l["command"].(string) < r["path"].(string)+"\x00"+r["command"].(string)
	})
	return result, nil
}

func outputPrivatePathExclusionsRecord(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("selective gate plan output privatePathExclusions must be an object")
	}
	if err := admit.KnownKeys(record, []string{"appliesTo", "pathPrefixes"}, "selective gate plan output privatePathExclusions"); err != nil {
		return nil, err
	}
	appliesTo, err := sortedTextArray(record["appliesTo"], "selective gate plan output privatePathExclusions appliesTo", true)
	if err != nil {
		return nil, err
	}
	prefixes, err := sortedPrefixes(record["pathPrefixes"])
	if err != nil {
		return nil, err
	}
	return map[string]any{"appliesTo": admit.StringSliceToAny(appliesTo), "pathPrefixes": admit.StringSliceToAny(prefixes)}, nil
}

func outputSecretScanRecord(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("selective gate plan output secretScan must be an object")
	}
	if err := admit.KnownKeys(record, []string{"changedArchiveOrBinaryPaths", "command", "mode", "required"}, "selective gate plan output secretScan"); err != nil {
		return nil, err
	}
	mode, err := admit.Enum(record["mode"], map[string]struct{}{"diff-scoped": {}}, "selective gate plan output secretScan mode")
	if err != nil {
		return nil, err
	}
	changed, err := sortedPaths(record["changedArchiveOrBinaryPaths"], "selective gate plan output secretScan changedArchiveOrBinaryPaths", true)
	if err != nil {
		return nil, err
	}
	required, err := admit.Bool(record["required"], "selective gate plan output secretScan required")
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, fmt.Errorf("selective gate plan output secretScan required must be true")
	}
	command, err := admit.DisplayOnlyCommandText(record["command"], "selective gate plan output secretScan command")
	if err != nil {
		return nil, err
	}
	return map[string]any{"changedArchiveOrBinaryPaths": admit.StringSliceToAny(changed), "command": command, "mode": mode, "required": required}, nil
}

func outputSkippedGateRecords(raw any) ([]any, error) {
	records, err := outputArrayOfRecords(raw, "selective gate plan output skippedGates")
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(records))
	for _, record := range records {
		if err := admit.KnownKeys(record, []string{"id", "reason"}, "selective gate plan output skippedGate"); err != nil {
			return nil, err
		}
		id, err := admit.RuleID(record["id"], "selective gate plan output skippedGate id")
		if err != nil {
			return nil, err
		}
		reason, err := admit.NonEmptyText(record["reason"], "selective gate plan output skippedGate reason")
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"id": id, "reason": reason})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].(map[string]any)["id"].(string) < result[right].(map[string]any)["id"].(string)
	})
	return result, nil
}

func outputEdgeClasses(raw any, context string) ([]string, error) {
	values, err := sortedEdgeClasses(raw, context)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	return values, nil
}

func outputArrayOfRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		result = append(result, record)
	}
	return result, nil
}

func outputCommandKey(command map[string]any) string {
	source := ""
	if value, ok := command["sourcePath"].(string); ok {
		source = value
	}
	return command["id"].(string) + "\x00" + command["command"].(string) + "\x00" + source
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
