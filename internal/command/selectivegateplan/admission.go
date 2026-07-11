package selectivegateplan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
)

var selectiveGatePlanNonClaims = []string{
	"Selective gate plans classify caller-owned change and policy facts only.",
	"Selective gate plans do not execute commands, authenticate receipts, approve merge, or prove proof freshness.",
	"Selective gate plans do not decide consumer fallback policy for unknown edges or unbound proof-like paths.",
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("selective gate plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"archiveOrBinaryPathPatterns", "artifactIntegrityPolicies", "baseCommands", "changedPaths", "dependencyFreshness", "fallbackCoverage", "fullWorkspaceCommand", "generatedArtifactRules", "ignoredProofLikePaths", "nonClaims", "packageCommands", "pathTriggeredCommands", "preexistingFailures", "privatePathPrefixes", "proofLikePathPatterns", "publicApi", "requirementImpact", "scanObligation", "schemaVersion", "touchedRequirementWitnesses", "unknownEdges"}, "selective gate plan input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("selective gate plan schemaVersion must be 1")
	}
	changedPaths, err := sortedPaths(record["changedPaths"], "selective gate changedPaths", true)
	if err != nil {
		return input{}, err
	}
	preexistingFailures, err := sortedTextArray(record["preexistingFailures"], "selective gate preexistingFailures", true)
	if err != nil {
		return input{}, err
	}
	baseCommands, err := commandArray(record["baseCommands"], "baseCommands", true)
	if err != nil {
		return input{}, err
	}
	packageCommands, err := commandArray(record["packageCommands"], "packageCommands", true)
	if err != nil {
		return input{}, err
	}
	privatePrefixes, err := sortedPrefixes(record["privatePathPrefixes"])
	if err != nil {
		return input{}, err
	}
	scanObligation, err := admitScanObligation(record)
	if err != nil {
		return input{}, err
	}
	dependency, ok := record["dependencyFreshness"].(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("selective gate dependencyFreshness must be an object")
	}
	if err := admit.KnownKeys(dependency, []string{"command", "paths"}, "selective gate dependencyFreshness"); err != nil {
		return input{}, err
	}
	dependencyCommand, err := admit.DisplayOnlyCommandText(dependency["command"], "dependency freshness command")
	if err != nil {
		return input{}, err
	}
	dependencyPaths, err := sortedPaths(dependency["paths"], "selective gate dependencyFreshness.paths", true)
	if err != nil {
		return input{}, err
	}
	publicAPI, ok := record["publicApi"].(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("selective gate publicApi must be an object")
	}
	if err := admit.KnownKeys(publicAPI, []string{"command", "touched"}, "selective gate publicApi"); err != nil {
		return input{}, err
	}
	publicCommand, err := admit.DisplayOnlyCommandText(publicAPI["command"], "public API command")
	if err != nil {
		return input{}, err
	}
	publicTouched, ok := publicAPI["touched"].(bool)
	if !ok {
		return input{}, fmt.Errorf("public API touched must be boolean")
	}
	requirementImpact, ok := record["requirementImpact"].(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("selective gate requirementImpact must be an object")
	}
	if err := admit.KnownKeys(requirementImpact, []string{"command", "touched"}, "selective gate requirementImpact"); err != nil {
		return input{}, err
	}
	requirementCommand, err := admit.DisplayOnlyCommandText(requirementImpact["command"], "requirement impact command")
	if err != nil {
		return input{}, err
	}
	requirementTouched, ok := requirementImpact["touched"].(bool)
	if !ok {
		return input{}, fmt.Errorf("requirement impact touched must be boolean")
	}
	var fullWorkspaceCommand *command
	if rawCommand, exists := record["fullWorkspaceCommand"]; exists {
		commandValue, err := admitCommand(rawCommand)
		if err != nil {
			return input{}, err
		}
		fullWorkspaceCommand = &commandValue
	}
	pathTriggered, err := pathTriggeredCommandArray(record["pathTriggeredCommands"])
	if err != nil {
		return input{}, err
	}
	fallbackCoverage, err := fallbackCoverageArray(record["fallbackCoverage"])
	if err != nil {
		return input{}, err
	}
	unknownEdges, err := unknownEdgeArray(record["unknownEdges"])
	if err != nil {
		return input{}, err
	}
	generatedRules, err := generatedArtifactRules(record["generatedArtifactRules"])
	if err != nil {
		return input{}, err
	}
	artifactPolicies, err := artifactPolicies(record["artifactIntegrityPolicies"])
	if err != nil {
		return input{}, err
	}
	witnesses, err := witnessObligations(record["touchedRequirementWitnesses"])
	if err != nil {
		return input{}, err
	}
	archivePatterns, err := compiledPatterns(record["archiveOrBinaryPathPatterns"], "selective gate archiveOrBinaryPathPatterns", true)
	if err != nil {
		return input{}, err
	}
	ignoredProofLike, err := sortedPaths(record["ignoredProofLikePaths"], "selective gate ignoredProofLikePaths", true)
	if err != nil {
		return input{}, err
	}
	proofLikePatterns, err := compiledPatterns(record["proofLikePathPatterns"], "selective gate proofLikePathPatterns", true)
	if err != nil {
		return input{}, err
	}
	nonClaims, err := sortedTextArray(record["nonClaims"], "selective gate nonClaims", false)
	if err != nil {
		return input{}, err
	}
	nonClaims, err = admit.MergeNonClaims(selectiveGatePlanNonClaims, nonClaims, "selective gate")
	if err != nil {
		return input{}, err
	}
	return input{
		ArchiveOrBinaryPathPatterns: archivePatterns,
		ArtifactIntegrityPolicies:   artifactPolicies,
		BaseCommands:                baseCommands,
		ChangedPaths:                changedPaths,
		DependencyCommand:           dependencyCommand,
		DependencyPaths:             dependencyPaths,
		FallbackCoverage:            fallbackCoverage,
		FullWorkspaceCommand:        fullWorkspaceCommand,
		GeneratedArtifactRules:      generatedRules,
		IgnoredProofLikePaths:       ignoredProofLike,
		NonClaims:                   nonClaims,
		PackageCommands:             packageCommands,
		PathTriggeredCommands:       pathTriggered,
		PreexistingFailures:         preexistingFailures,
		PrivatePathPrefixes:         privatePrefixes,
		ProofLikePathPatterns:       proofLikePatterns,
		PublicAPICommand:            publicCommand,
		PublicAPITouched:            publicTouched,
		RequirementImpactCommand:    requirementCommand,
		RequirementImpactTouched:    requirementTouched,
		ScanObligation:              scanObligation,
		TouchedRequirementWitnesses: witnesses,
		UnknownEdges:                unknownEdges,
	}, nil
}

func admitScanObligation(record map[string]any) (scanObligation, error) {
	if raw, ok := record["scanObligation"]; ok {
		scan, ok := raw.(map[string]any)
		if !ok {
			return scanObligation{}, fmt.Errorf("selective gate scanObligation must be an object")
		}
		if err := admit.KnownKeys(scan, []string{"command", "commandId", "commandOwnership", "mode", "reason", "required"}, "selective gate scanObligation"); err != nil {
			return scanObligation{}, err
		}
		commandID, err := admit.RuleID(scan["commandId"], "selective gate scanObligation commandId")
		if err != nil {
			return scanObligation{}, err
		}
		commandOwnership, err := admit.Enum(scan["commandOwnership"], map[string]struct{}{"caller_owned_external": {}, "proofkit_secret_scan": {}, "proofkit_text_policy": {}}, "selective gate scanObligation commandOwnership")
		if err != nil {
			return scanObligation{}, err
		}
		reason, err := admit.Enum(scan["reason"], map[string]struct{}{"external_secret_scan": {}, "secret_scan": {}, "text_policy": {}}, "selective gate scanObligation reason")
		if err != nil {
			return scanObligation{}, err
		}
		mode, err := admit.Enum(scan["mode"], map[string]struct{}{"diff-scoped": {}}, "selective gate scanObligation mode")
		if err != nil {
			return scanObligation{}, err
		}
		required, err := admit.Bool(scan["required"], "selective gate scanObligation required")
		if err != nil {
			return scanObligation{}, err
		}
		if !required {
			return scanObligation{}, fmt.Errorf("selective gate scanObligation required must be true")
		}
		commandText, err := admit.DisplayOnlyCommandText(scan["command"], "selective gate scanObligation command")
		if err != nil {
			return scanObligation{}, err
		}
		obligation := scanObligation{
			Command:          commandText,
			CommandID:        commandID,
			CommandOwnership: commandOwnership,
			Mode:             mode,
			Reason:           reason,
			Required:         required,
		}
		if err := validateScanObligation(obligation, "selective gate scanObligation"); err != nil {
			return scanObligation{}, err
		}
		return obligation, nil
	}
	return scanObligation{}, fmt.Errorf("selective gate scanObligation must be an object")
}

func validateScanObligation(value scanObligation, context string) error {
	switch value.CommandOwnership {
	case "proofkit_text_policy":
		if value.CommandID != "text-policy" || value.Reason != "text_policy" {
			return fmt.Errorf("%s proofkit_text_policy requires commandId text-policy and reason text_policy", context)
		}
	case "proofkit_secret_scan":
		if value.CommandID != "secret-scan" || value.Reason != "secret_scan" {
			return fmt.Errorf("%s proofkit_secret_scan requires commandId secret-scan and reason secret_scan", context)
		}
	case "caller_owned_external":
		if value.Reason != "external_secret_scan" {
			return fmt.Errorf("%s caller_owned_external requires reason external_secret_scan", context)
		}
		if value.CommandID == "text-policy" || value.CommandID == "secret-scan" {
			return fmt.Errorf("%s caller_owned_external must not reuse Proofkit-owned commandId %s", context, value.CommandID)
		}
	default:
		return fmt.Errorf("%s commandOwnership is unsupported", context)
	}
	return nil
}

func commandArray(raw any, context string, allowEmpty bool) ([]command, error) {
	values, ok := raw.([]any)
	if !ok || (!allowEmpty && len(values) == 0) {
		return nil, fmt.Errorf("selective gate %s must be an array", context)
	}
	result := make([]command, 0, len(values))
	for _, value := range values {
		item, err := admitCommand(value)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func admitCommand(raw any) (command, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return command{}, fmt.Errorf("selective gate command must be an object")
	}
	if err := admit.KnownKeys(record, []string{"command", "id", "reason", "sourcePath"}, "selective gate command"); err != nil {
		return command{}, err
	}
	id, err := admit.RuleID(record["id"], "selective gate command id")
	if err != nil {
		return command{}, err
	}
	commandText, err := admit.DisplayOnlyCommandText(record["command"], id+" command")
	if err != nil {
		return command{}, err
	}
	reason, err := admit.RuleID(record["reason"], id+" reason")
	if err != nil {
		return command{}, err
	}
	var sourcePath *string
	if rawSource, ok := record["sourcePath"]; ok {
		source, ok := rawSource.(string)
		if !ok {
			return command{}, fmt.Errorf("%s sourcePath must be a repository-relative POSIX path", id)
		}
		pathValue, err := admit.SafeRepoRelativePath(source, id+" sourcePath")
		if err != nil {
			return command{}, err
		}
		sourcePath = &pathValue
	}
	return command{ID: id, Command: commandText, Reason: reason, SourcePath: sourcePath}, nil
}

func generatedArtifactRules(raw any) ([]generatedArtifactRule, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("selective gate generatedArtifactRules must be an array")
	}
	result := make([]generatedArtifactRule, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("generated artifact rule must be an object")
		}
		if err := admit.KnownKeys(record, []string{"command", "generator", "path", "sourceOfTruthPatterns"}, "generated artifact rule"); err != nil {
			return nil, err
		}
		pathValue, err := safePath(record["path"], "generated artifact path")
		if err != nil {
			return nil, err
		}
		generator, err := nonEmpty(record["generator"], "generated artifact "+pathValue+" generator")
		if err != nil {
			return nil, err
		}
		commandText, err := admit.DisplayOnlyCommandText(record["command"], "generated artifact "+pathValue+" command")
		if err != nil {
			return nil, err
		}
		sourcePatterns, err := compiledPatterns(record["sourceOfTruthPatterns"], "generated artifact "+pathValue+" sourceOfTruthPatterns", true)
		if err != nil {
			return nil, err
		}
		result = append(result, generatedArtifactRule{Command: commandText, Generator: generator, Path: pathValue, SourceOfTruthPatterns: sourcePatterns})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].Path < result[right].Path
	})
	return result, nil
}

func artifactPolicies(raw any) ([]artifactIntegrityPolicy, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("selective gate artifactIntegrityPolicies must be an array")
	}
	result := make([]artifactIntegrityPolicy, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("artifact integrity policy must be an object")
		}
		if err := admit.KnownKeys(record, []string{"command", "pathPattern", "policy"}, "artifact integrity policy"); err != nil {
			return nil, err
		}
		commandText, err := admit.DisplayOnlyCommandText(record["command"], "artifact integrity command")
		if err != nil {
			return nil, err
		}
		pathPatternValue, err := safePath(record["pathPattern"], "artifact integrity pathPattern")
		if err != nil {
			return nil, err
		}
		pathPattern, err := pathpattern.Compile(pathPatternValue, "artifact integrity pathPattern")
		if err != nil {
			return nil, err
		}
		policy, err := admit.RuleID(record["policy"], "artifact integrity policy")
		if err != nil {
			return nil, err
		}
		result = append(result, artifactIntegrityPolicy{Command: commandText, PathPattern: pathPattern, Policy: policy})
	}
	return result, nil
}

func witnessObligations(raw any) ([]witnessObligation, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("selective gate touchedRequirementWitnesses must be an array")
	}
	result := make([]witnessObligation, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement witness must be an object")
		}
		if err := admit.KnownKeys(record, []string{"commands", "path", "requirementIds"}, "requirement witness"); err != nil {
			return nil, err
		}
		pathValue, err := safePath(record["path"], "requirement witness path")
		if err != nil {
			return nil, err
		}
		requirementIDs, err := sortedRuleIDs(record["requirementIds"], "requirement witness "+pathValue+" requirementIds")
		if err != nil {
			return nil, err
		}
		commands, err := sortedDisplayCommandArray(record["commands"], "requirement witness "+pathValue+" commands", false)
		if err != nil {
			return nil, err
		}
		result = append(result, witnessObligation{Commands: commands, Path: pathValue, RequirementIDs: requirementIDs})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].Path < result[right].Path
	})
	return result, nil
}

func pathTriggeredCommandArray(raw any) ([]pathTriggeredCommand, error) {
	if raw == nil {
		return []pathTriggeredCommand{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("selective gate pathTriggeredCommands must be an array")
	}
	result := make([]pathTriggeredCommand, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("pathTriggeredCommands must contain objects")
		}
		if err := admit.KnownKeys(record, []string{"command", "pathPatterns"}, "pathTriggeredCommands item"); err != nil {
			return nil, err
		}
		commandValue, err := admitCommand(record["command"])
		if err != nil {
			return nil, err
		}
		patterns, err := compiledPatterns(record["pathPatterns"], commandValue.ID+" pathTriggeredCommands pathPatterns", false)
		if err != nil {
			return nil, err
		}
		result = append(result, pathTriggeredCommand{Command: commandValue, PathPatterns: patterns})
	}
	return result, nil
}

func fallbackCoverageArray(raw any) ([]fallbackCoverage, error) {
	if raw == nil {
		return []fallbackCoverage{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("selective gate fallbackCoverage must be an array")
	}
	result := make([]fallbackCoverage, 0, len(values))
	ids := map[string]struct{}{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("fallbackCoverage must contain objects")
		}
		if err := admit.KnownKeys(record, []string{"command", "edgeClasses", "reason"}, "fallbackCoverage item"); err != nil {
			return nil, err
		}
		commandValue, err := admitCommand(record["command"])
		if err != nil {
			return nil, err
		}
		classes, err := sortedEdgeClasses(record["edgeClasses"], commandValue.ID+" fallbackCoverage edgeClasses")
		if err != nil {
			return nil, err
		}
		if len(classes) == 0 {
			return nil, fmt.Errorf("%s fallbackCoverage edgeClasses must not be empty", commandValue.ID)
		}
		reason, err := nonEmpty(record["reason"], commandValue.ID+" fallbackCoverage reason")
		if err != nil {
			return nil, err
		}
		if _, ok := ids[commandValue.ID]; ok {
			return nil, fmt.Errorf("selective gate fallbackCoverage command id must be unique: %s", commandValue.ID)
		}
		ids[commandValue.ID] = struct{}{}
		result = append(result, fallbackCoverage{Command: commandValue, EdgeClasses: classes, Reason: reason})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].Command.ID+"\x00"+result[left].Command.Command < result[right].Command.ID+"\x00"+result[right].Command.Command
	})
	return result, nil
}

func unknownEdgeArray(raw any) ([]unknownEdge, error) {
	if raw == nil {
		return []unknownEdge{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("selective gate unknownEdges must be an array")
	}
	result := make([]unknownEdge, 0, len(values))
	ids := map[string]struct{}{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unknownEdges must contain objects")
		}
		if err := admit.KnownKeys(record, []string{"edgeClass", "edgeId", "path", "reason"}, "unknownEdges item"); err != nil {
			return nil, err
		}
		edgeID, err := admit.RuleID(record["edgeId"], "selective gate unknown edge edgeId")
		if err != nil {
			return nil, err
		}
		edgeClass, err := admit.Enum(record["edgeClass"], edgeClassSet, "selective gate unknown edge "+edgeID+" edgeClass")
		if err != nil {
			return nil, err
		}
		pathValue, err := safePath(record["path"], "selective gate unknown edge "+edgeID+" path")
		if err != nil {
			return nil, err
		}
		reason, err := nonEmpty(record["reason"], "selective gate unknown edge "+edgeID+" reason")
		if err != nil {
			return nil, err
		}
		if _, ok := ids[edgeID]; ok {
			return nil, fmt.Errorf("selective gate unknown edge edgeId must be unique: %s", edgeID)
		}
		ids[edgeID] = struct{}{}
		result = append(result, unknownEdge{EdgeClass: edgeClass, EdgeID: edgeID, Path: pathValue, Reason: reason})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].EdgeID < result[right].EdgeID
	})
	return result, nil
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := textArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		pathValue, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, pathValue)
	}
	sort.Strings(result)
	return unique(result, context, allowEmpty)
}

func compiledPatterns(raw any, context string, allowEmpty bool) ([]pathpattern.Pattern, error) {
	values, err := sortedPaths(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return pathpattern.CompileAll(values, context)
}

func sortedPrefixes(raw any) ([]string, error) {
	values, err := textArray(raw, "private path prefix", true)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := nonEmpty(value, "private path prefix")
		if err != nil {
			return nil, err
		}
		if !strings.HasSuffix(prefix, "/") {
			return nil, fmt.Errorf("private path prefix must identify a repository-relative directory prefix: %s", prefix)
		}
		withoutSlash := strings.TrimSuffix(prefix, "/")
		normalized, err := admit.SafeRepoRelativePath(withoutSlash, "private path prefix")
		if err != nil {
			return nil, err
		}
		if normalized != withoutSlash {
			return nil, fmt.Errorf("private path prefix must not escape the repository root")
		}
		result = append(result, prefix)
	}
	sort.Strings(result)
	result, err = unique(result, "private path prefix", true)
	if err != nil {
		return nil, err
	}
	for _, value := range result {
		if !strings.HasSuffix(value, "/") {
			return nil, fmt.Errorf("private path prefix must identify a repository-relative directory prefix: %s", value)
		}
	}
	return result, nil
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	values, err := textArray(raw, context, false)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		id, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	sort.Strings(result)
	return unique(result, context, false)
}

func sortedEdgeClasses(raw any, context string) ([]string, error) {
	values, err := textArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := admit.Enum(value, edgeClassSet, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Strings(result)
	return unique(result, context, true)
}

func sortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := textArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		text, err := nonEmpty(value, context)
		if err != nil {
			return nil, err
		}
		values[index] = text
	}
	sort.Strings(values)
	return unique(values, context, allowEmpty)
}

func sortedDisplayCommandArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := textArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		text, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		values[index] = text
	}
	sort.Strings(values)
	return unique(values, context, allowEmpty)
}

func textArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be an array", context)
		}
		result = append(result, text)
	}
	return result, nil
}

func nonEmpty(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func safePath(raw any, context string) (string, error) {
	value, err := nonEmpty(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func unique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}
