package selectivegateplan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

func buildPlan(input input) map[string]any {
	failures := append([]string{}, input.PreexistingFailures...)
	commands := commandAccumulator{byKey: map[string]command{}}
	push := func(item command) {
		key := commandKey(item)
		if previous, ok := commands.byKey[key]; ok && previous.Reason != item.Reason {
			failures = append(failures, fmt.Sprintf("selective gate command reason collision for %s", item.ID))
			return
		}
		if _, ok := commands.byKey[key]; !ok {
			commands.order = append(commands.order, key)
		}
		commands.byKey[key] = item
	}
	for _, item := range input.BaseCommands {
		push(item)
	}
	scanOwnership := input.ScanObligation.CommandOwnership
	push(command{ID: input.ScanObligation.CommandID, Command: input.ScanObligation.Command, CommandOwnership: &scanOwnership, Reason: input.ScanObligation.Reason})
	if input.FullWorkspaceCommand != nil {
		push(*input.FullWorkspaceCommand)
	}
	for _, item := range input.PackageCommands {
		push(item)
	}
	for _, item := range pathTriggeredCommands(input.PathTriggeredCommands, input.ChangedPaths) {
		push(item)
	}
	unknownEdges := assessUnknownEdges(input.UnknownEdges, input.FallbackCoverage, &failures)
	for _, edge := range unknownEdges {
		if edge.CoverageState != proofvocab.SelectiveEdgeCoverageCoveredByFallback() {
			continue
		}
		for _, coverage := range input.FallbackCoverage {
			if contains(edge.FallbackCommandIDs, coverage.Command.ID) {
				push(coverage.Command)
			}
		}
	}
	generatedArtifacts := generatedArtifactObligations(input.GeneratedArtifactRules, input.ChangedPaths, &failures)
	for _, artifact := range generatedArtifacts {
		for _, rule := range input.GeneratedArtifactRules {
			if rule.Path == artifact.Path {
				sourcePath := artifact.Path
				push(command{ID: "generated-artifact", Command: rule.Command, Reason: "generated_artifact_" + artifact.Reason, SourcePath: &sourcePath})
			}
		}
	}
	ignored := stringSet(input.IgnoredProofLikePaths)
	proofLikePaths := []string{}
	for _, path := range input.ChangedPaths {
		if _, ok := ignored[path]; ok {
			continue
		}
		if matchesAny(input.ProofLikePathPatterns, path) {
			proofLikePaths = append(proofLikePaths, path)
		}
	}
	sort.Strings(proofLikePaths)
	touchedWitnessPaths := map[string]struct{}{}
	for _, witness := range input.TouchedRequirementWitnesses {
		touchedWitnessPaths[witness.Path] = struct{}{}
	}
	requirementImpactTouched := input.RequirementImpactTouched || len(proofLikePaths) > 0
	if requirementImpactTouched {
		push(command{ID: "requirement-impact", Command: input.RequirementImpactCommand, Reason: "changed_requirement_or_proof_surface"})
	}
	for _, witness := range input.TouchedRequirementWitnesses {
		for _, commandText := range witness.Commands {
			sourcePath := witness.Path
			push(command{ID: "requirement-witness", Command: commandText, Reason: "changed_requirement_witness", SourcePath: &sourcePath})
		}
	}
	for _, path := range proofLikePaths {
		if _, ok := touchedWitnessPaths[path]; !ok {
			failures = append(failures, fmt.Sprintf("proof-like path changed without requirement witness binding: %s", path))
		}
	}
	if len(input.DependencyPaths) > 0 {
		push(command{ID: "dependency-freshness", Command: input.DependencyCommand, Reason: "workspace_dependency_surface_changed"})
	}
	if input.PublicAPITouched {
		push(command{ID: "public-api", Command: input.PublicAPICommand, Reason: "public_api_contract_surface_changed"})
	}
	changedArchiveOrBinary := []string{}
	for _, path := range input.ChangedPaths {
		if matchesAny(input.ArchiveOrBinaryPathPatterns, path) && !isPrivatePath(path, input.PrivatePathPrefixes) {
			changedArchiveOrBinary = append(changedArchiveOrBinary, path)
		}
	}
	sort.Strings(changedArchiveOrBinary)
	artifactIntegrity := artifactIntegrityObligations(input.ArtifactIntegrityPolicies, changedArchiveOrBinary, &failures)
	for _, obligation := range artifactIntegrity {
		sourcePath := obligation.Path
		push(command{ID: "artifact-integrity", Command: obligation.Command, Reason: obligation.Policy, SourcePath: &sourcePath})
	}
	requiredCommands := commandsJSON(commands)
	state := "ok"
	failures = uniqueSorted(failures)
	if len(failures) > 0 {
		state = "fail_closed"
	}
	return map[string]any{
		"artifactIntegrity":  artifactIntegrityJSON(artifactIntegrity),
		"changedPaths":       admit.StringSliceToAny(input.ChangedPaths),
		"failures":           admit.StringSliceToAny(failures),
		"fallbackCoverage":   fallbackCoverageJSON(input.FallbackCoverage),
		"generatedArtifacts": generatedArtifactObligationsJSON(generatedArtifacts),
		"nonClaims":          admit.StringSliceToAny(input.NonClaims),
		"planState":          state,
		"privatePathExclusions": map[string]any{
			"appliesTo":    []any{"artifact-integrity"},
			"pathPrefixes": admit.StringSliceToAny(input.PrivatePathPrefixes),
		},
		"proofLikePaths":           admit.StringSliceToAny(proofLikePaths),
		"publicApiContractTouched": input.PublicAPITouched,
		"requiredCommands":         requiredCommands,
		"scanObligation": map[string]any{
			"command":          input.ScanObligation.Command,
			"commandId":        input.ScanObligation.CommandID,
			"commandOwnership": input.ScanObligation.CommandOwnership,
			"mode":             input.ScanObligation.Mode,
			"reason":           input.ScanObligation.Reason,
			"required":         input.ScanObligation.Required,
		},
		"schemaVersion":               1,
		"skippedGates":                skippedGatesJSON(skippedGates(input, generatedArtifacts, artifactIntegrity, requirementImpactTouched)),
		"touchedRequirementWitnesses": witnessObligationsJSON(input.TouchedRequirementWitnesses),
		"unknownEdges":                unknownEdgesJSON(unknownEdges),
	}
}

func assessUnknownEdges(edges []unknownEdge, coverage []fallbackCoverage, failures *[]string) []unknownEdgeAssessment {
	result := make([]unknownEdgeAssessment, 0, len(edges))
	for _, edge := range edges {
		fallbackIDs := []string{}
		for _, item := range coverage {
			if contains(item.EdgeClasses, edge.EdgeClass) {
				fallbackIDs = append(fallbackIDs, item.Command.ID)
			}
		}
		sort.Strings(fallbackIDs)
		if len(fallbackIDs) == 0 {
			*failures = append(*failures, fmt.Sprintf("unknown selective planner edge lacks declared fallback coverage: %s (%s)", edge.EdgeID, edge.EdgeClass))
			result = append(result, unknownEdgeAssessment{unknownEdge: edge, CoverageState: proofvocab.SelectiveEdgeCoverageUncovered(), FallbackCommandIDs: []string{}})
			continue
		}
		result = append(result, unknownEdgeAssessment{unknownEdge: edge, CoverageState: proofvocab.SelectiveEdgeCoverageCoveredByFallback(), FallbackCommandIDs: fallbackIDs})
	}
	return result
}

func generatedArtifactObligations(rules []generatedArtifactRule, changedPaths []string, failures *[]string) []generatedArtifactObligation {
	changed := stringSet(changedPaths)
	result := []generatedArtifactObligation{}
	for _, rule := range rules {
		sourceChanged := false
		for _, pattern := range rule.SourceOfTruthPattern {
			for _, path := range changedPaths {
				if pathpattern.Match(pattern, path) {
					sourceChanged = true
				}
			}
		}
		_, generatedChanged := changed[rule.Path]
		if generatedChanged && !sourceChanged {
			*failures = append(*failures, "changed generated artifact without source change: "+rule.Path)
		}
		if sourceChanged || generatedChanged {
			reason := "generated_artifact_changed"
			if sourceChanged {
				reason = "source_changed"
			}
			result = append(result, generatedArtifactObligation{Generator: rule.Generator, Path: rule.Path, Reason: reason, SourceOfTruth: rule.SourceOfTruthPattern})
		}
	}
	return result
}

func artifactIntegrityObligations(policies []artifactIntegrityPolicy, paths []string, failures *[]string) []artifactIntegrityObligation {
	result := []artifactIntegrityObligation{}
	for _, path := range paths {
		var matched *artifactIntegrityPolicy
		for _, policy := range policies {
			if pathpattern.Match(policy.PathPattern, path) {
				policyCopy := policy
				matched = &policyCopy
				break
			}
		}
		if matched == nil {
			*failures = append(*failures, "changed archive or binary path has no artifact integrity policy: "+path)
			continue
		}
		result = append(result, artifactIntegrityObligation{Command: matched.Command, Path: path, Policy: matched.Policy})
	}
	return result
}

func pathTriggeredCommands(rules []pathTriggeredCommand, changedPaths []string) []command {
	result := []command{}
	for _, rule := range rules {
		for _, pattern := range rule.PathPatterns {
			for _, path := range changedPaths {
				if pathpattern.Match(pattern, path) {
					result = append(result, rule.Command)
					goto nextRule
				}
			}
		}
	nextRule:
	}
	sort.Slice(result, func(left int, right int) bool {
		return commandKey(result[left]) < commandKey(result[right])
	})
	return result
}

func skippedGates(input input, generated []generatedArtifactObligation, artifactIntegrity []artifactIntegrityObligation, requirementImpactTouched bool) []skippedGate {
	result := []skippedGate{}
	if len(input.PackageCommands) == 0 && input.FullWorkspaceCommand == nil {
		result = append(result, skippedGate{ID: "package-gates", Reason: "no_changed_package_roots"})
	}
	if !requirementImpactTouched {
		result = append(result, skippedGate{ID: "requirement-impact", Reason: "no_changed_requirement_or_proof_like_paths"})
	}
	if len(generated) == 0 {
		result = append(result, skippedGate{ID: "generated-artifacts", Reason: "no_generated_artifact_source_or_output_changed"})
	}
	if len(input.DependencyPaths) == 0 {
		result = append(result, skippedGate{ID: "dependency-freshness", Reason: "no_changed_workspace_dependency_surface"})
	}
	if !input.PublicAPITouched {
		result = append(result, skippedGate{ID: "public-api", Reason: "no_public_api_contract_surface_changed"})
	}
	if len(artifactIntegrity) == 0 {
		result = append(result, skippedGate{ID: "artifact-integrity", Reason: "no_changed_archive_or_external_artifact"})
	}
	return result
}

func commandKey(item command) string {
	source := ""
	if item.SourcePath != nil {
		source = *item.SourcePath
	}
	return item.ID + "\x00" + item.Command + "\x00" + source
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func matchesAny(patterns []string, path string) bool {
	return pathpattern.MatchAny(patterns, path)
}

func isPrivatePath(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
