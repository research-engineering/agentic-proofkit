package impact

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
)

type obligationBase struct {
	BlockingStatus             string
	Commands                   []string
	Preconditioned             bool
	ProofContractState         string
	RecordID                   string
	RequiredEnvironmentClasses []string
	ScenarioID                 string
	SurfaceID                  string
}

type witnessCoverage struct {
	Path     string
	RecordID []string
}

type generatedArtifactRule struct {
	GeneratedPath      string
	SourcePathPatterns []string
}

type input struct {
	BaseCommit                  string
	BaseRef                     string
	ChangedBindingRecordIDs     []string
	ChangedPaths                []string
	ChangedRecordIDs            []string
	ChangedWitnessPathCoverage  []witnessCoverage
	GeneratedArtifactRules      []generatedArtifactRule
	HeadCommit                  *string
	HeadRef                     string
	IgnoredProofLikePaths       []string
	NonClaims                   []string
	ObligationCatalog           []obligationBase
	PreexistingFailures         []string
	ProofLikePaths              []string
	UnboundProofChangeRationale string
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	result, exitCode := build(input)
	return result, exitCode, nil
}

func build(input input) (map[string]any, int) {
	failures := sortedFailureText(input.PreexistingFailures)
	catalog, err := buildCatalog(input.ObligationCatalog)
	if err != nil {
		failures = append(failures, err.Error())
		catalog = map[string]obligationBase{}
	}
	reasonsByRecordID := map[string]map[string]struct{}{}
	for _, recordID := range input.ChangedRecordIDs {
		addReason(reasonsByRecordID, recordID, "record_changed")
	}
	for _, recordID := range input.ChangedBindingRecordIDs {
		addReason(reasonsByRecordID, recordID, "proof_binding_changed")
	}
	changedWitnessCoverage := append([]witnessCoverage{}, input.ChangedWitnessPathCoverage...)
	sort.Slice(changedWitnessCoverage, func(left int, right int) bool {
		return changedWitnessCoverage[left].Path < changedWitnessCoverage[right].Path
	})
	parentedProofPaths := map[string]struct{}{}
	changedPathSet := stringSet(input.ChangedPaths)
	for _, coverage := range changedWitnessCoverage {
		if _, ok := changedPathSet[coverage.Path]; !ok {
			continue
		}
		parentedProofPaths[coverage.Path] = struct{}{}
		for _, recordID := range coverage.RecordID {
			addReason(reasonsByRecordID, recordID, "proof_witness_changed")
		}
	}
	obligations := []map[string]any{}
	recordIDs := sortedMapKeys(reasonsByRecordID)
	for _, recordID := range recordIDs {
		base, ok := catalog[recordID]
		if !ok {
			failures = append(failures, fmt.Sprintf("changed proof record has no obligation catalog entry: %s", recordID))
			continue
		}
		reasons := sortedSetValues(reasonsByRecordID[recordID])
		obligations = append(obligations, map[string]any{
			"blockingStatus":             base.BlockingStatus,
			"changeReasons":              stringsToAny(reasons),
			"commands":                   stringsToAny(base.Commands),
			"preconditioned":             base.Preconditioned,
			"proofContractState":         base.ProofContractState,
			"recordId":                   base.RecordID,
			"requiredEnvironmentClasses": stringsToAny(base.RequiredEnvironmentClasses),
			"scenarioId":                 base.ScenarioID,
			"surfaceId":                  base.SurfaceID,
		})
	}
	ignoredProofLikePaths := stringSet(input.IgnoredProofLikePaths)
	unboundProofChanges := []any{}
	for _, proofPath := range input.ProofLikePaths {
		if _, ok := parentedProofPaths[proofPath]; ok {
			continue
		}
		if _, ok := ignoredProofLikePaths[proofPath]; ok {
			continue
		}
		unboundProofChanges = append(unboundProofChanges, map[string]any{
			"path":      proofPath,
			"rationale": strings.TrimSpace(input.UnboundProofChangeRationale),
		})
	}
	if len(unboundProofChanges) > 0 && strings.TrimSpace(input.UnboundProofChangeRationale) == "" {
		paths := make([]string, 0, len(unboundProofChanges))
		for _, value := range unboundProofChanges {
			paths = append(paths, value.(map[string]any)["path"].(string))
		}
		failures = append(failures, fmt.Sprintf("proof changes without parent record need a rationale: %s", strings.Join(paths, ", ")))
	}
	failures = append(failures, generatedMirrorFailures(input.GeneratedArtifactRules, input.ChangedPaths)...)
	failures = sortedUniqueFailures(failures)
	impactState := "ok"
	exitCode := 0
	if len(failures) > 0 {
		impactState = "failed"
		exitCode = 1
	}
	var headCommit any
	if input.HeadCommit == nil {
		headCommit = nil
	} else {
		headCommit = *input.HeadCommit
	}
	return map[string]any{
		"baseCommit":          input.BaseCommit,
		"baseRef":             input.BaseRef,
		"changedPaths":        stringsToAny(input.ChangedPaths),
		"changedRecordIds":    stringsToAny(input.ChangedRecordIDs),
		"failures":            stringsToAny(failures),
		"headCommit":          headCommit,
		"headRef":             input.HeadRef,
		"impactState":         impactState,
		"nonClaims":           stringsToAny(input.NonClaims),
		"obligations":         mapsToAny(obligations),
		"schemaVersion":       1,
		"unboundProofChanges": unboundProofChanges,
	}, exitCode
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("proof impact report input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baseCommit", "baseRef", "changedBindingRecordIds", "changedPaths", "changedRecordIds", "changedWitnessPathCoverage", "generatedArtifactRules", "headCommit", "headRef", "ignoredProofLikePaths", "nonClaims", "obligationCatalog", "preexistingFailures", "proofLikePaths", "schemaVersion", "unboundProofChangeRationale"}, "proof impact report input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("proof impact report schemaVersion must be 1")
	}
	changedPaths, err := sortedSafePaths(requireField(record, "changedPaths"), "proof impact changedPaths")
	if err != nil {
		return input{}, err
	}
	changedRecordIDs, err := sortedRuleIDs(requireField(record, "changedRecordIds"), "proof impact changedRecordIds")
	if err != nil {
		return input{}, err
	}
	changedBindingRecordIDs, err := sortedRuleIDs(requireField(record, "changedBindingRecordIds"), "proof impact changedBindingRecordIds")
	if err != nil {
		return input{}, err
	}
	proofLikePaths, err := sortedSafePaths(requireField(record, "proofLikePaths"), "proof impact proofLikePaths")
	if err != nil {
		return input{}, err
	}
	ignoredProofLikePaths, err := sortedSafePaths(requireField(record, "ignoredProofLikePaths"), "proof impact ignoredProofLikePaths")
	if err != nil {
		return input{}, err
	}
	preexistingFailures, err := failureText(requireField(record, "preexistingFailures"))
	if err != nil {
		return input{}, err
	}
	nonClaims, err := optionalFailureText(record["nonClaims"])
	if err != nil {
		return input{}, err
	}
	obligationCatalog, err := obligationCatalog(requireField(record, "obligationCatalog"))
	if err != nil {
		return input{}, err
	}
	changedWitnessCoverage, err := witnessCoverageRecords(requireField(record, "changedWitnessPathCoverage"))
	if err != nil {
		return input{}, err
	}
	generatedRules, err := generatedArtifactRules(requireField(record, "generatedArtifactRules"))
	if err != nil {
		return input{}, err
	}
	baseCommit, err := nonEmptyText(requireField(record, "baseCommit"), "proof impact baseCommit")
	if err != nil {
		return input{}, err
	}
	baseRef, err := nonEmptyText(requireField(record, "baseRef"), "proof impact baseRef")
	if err != nil {
		return input{}, err
	}
	headRaw, exists := record["headCommit"]
	if !exists {
		return input{}, fmt.Errorf("proof impact headCommit must be non-empty text")
	}
	var headCommit *string
	if headRaw != nil {
		value, err := nonEmptyText(headRaw, "proof impact headCommit")
		if err != nil {
			return input{}, err
		}
		headCommit = &value
	}
	headRef, err := nonEmptyText(requireField(record, "headRef"), "proof impact headRef")
	if err != nil {
		return input{}, err
	}
	rationale := ""
	if rawRationale, ok := record["unboundProofChangeRationale"]; ok {
		rationale, err = nonEmptyText(rawRationale, "proof impact unboundProofChangeRationale")
		if err != nil {
			return input{}, err
		}
	}
	return input{
		BaseCommit:                  baseCommit,
		BaseRef:                     baseRef,
		ChangedBindingRecordIDs:     changedBindingRecordIDs,
		ChangedPaths:                changedPaths,
		ChangedRecordIDs:            changedRecordIDs,
		ChangedWitnessPathCoverage:  changedWitnessCoverage,
		GeneratedArtifactRules:      generatedRules,
		HeadCommit:                  headCommit,
		HeadRef:                     headRef,
		IgnoredProofLikePaths:       ignoredProofLikePaths,
		NonClaims:                   nonClaims,
		ObligationCatalog:           obligationCatalog,
		PreexistingFailures:         preexistingFailures,
		ProofLikePaths:              proofLikePaths,
		UnboundProofChangeRationale: rationale,
	}, nil
}

func requireField(record map[string]any, key string) any {
	value, ok := record[key]
	if !ok {
		return nil
	}
	return value
}

func obligationCatalog(raw any) ([]obligationBase, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proof impact obligationCatalog must be an array")
	}
	result := make([]obligationBase, 0, len(values))
	for _, value := range values {
		item, err := admitObligationBase(value)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func admitObligationBase(raw any) (obligationBase, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return obligationBase{}, fmt.Errorf("proof impact obligation record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"blockingStatus", "commands", "preconditioned", "proofContractState", "recordId", "requiredEnvironmentClasses", "scenarioId", "surfaceId"}, "proof impact obligation record"); err != nil {
		return obligationBase{}, err
	}
	recordID, err := admit.RuleID(record["recordId"], "proof impact obligation recordId")
	if err != nil {
		return obligationBase{}, err
	}
	blockingStatus, err := admit.RuleID(record["blockingStatus"], fmt.Sprintf("proof impact %s blockingStatus", recordID))
	if err != nil {
		return obligationBase{}, err
	}
	commands, err := sortedDisplayCommandText(record["commands"], fmt.Sprintf("proof impact %s commands", recordID))
	if err != nil {
		return obligationBase{}, err
	}
	preconditioned, ok := record["preconditioned"].(bool)
	if !ok {
		return obligationBase{}, fmt.Errorf("proof impact %s preconditioned must be a boolean", recordID)
	}
	proofContractState, err := admit.RuleID(record["proofContractState"], fmt.Sprintf("proof impact %s proofContractState", recordID))
	if err != nil {
		return obligationBase{}, err
	}
	requiredEnvironmentClasses, err := sortedNonEmptyText(record["requiredEnvironmentClasses"], fmt.Sprintf("proof impact %s requiredEnvironmentClasses", recordID))
	if err != nil {
		return obligationBase{}, err
	}
	scenarioID, err := nonEmptyText(record["scenarioId"], fmt.Sprintf("proof impact %s scenarioId", recordID))
	if err != nil {
		return obligationBase{}, err
	}
	surfaceID, err := admit.RuleID(record["surfaceId"], fmt.Sprintf("proof impact %s surfaceId", recordID))
	if err != nil {
		return obligationBase{}, err
	}
	return obligationBase{
		BlockingStatus:             blockingStatus,
		Commands:                   commands,
		Preconditioned:             preconditioned,
		ProofContractState:         proofContractState,
		RecordID:                   recordID,
		RequiredEnvironmentClasses: requiredEnvironmentClasses,
		ScenarioID:                 scenarioID,
		SurfaceID:                  surfaceID,
	}, nil
}

func witnessCoverageRecords(raw any) ([]witnessCoverage, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proof impact changedWitnessPathCoverage must be an array")
	}
	result := make([]witnessCoverage, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proof impact witness coverage must be an object")
		}
		if err := admit.KnownKeys(record, []string{"path", "recordIds"}, "proof impact witness coverage"); err != nil {
			return nil, err
		}
		witnessPath, err := safePath(record["path"], "proof impact witness path")
		if err != nil {
			return nil, err
		}
		recordIDs, err := sortedRuleIDs(record["recordIds"], fmt.Sprintf("proof impact witness coverage %s", record["path"]))
		if err != nil {
			return nil, err
		}
		result = append(result, witnessCoverage{Path: witnessPath, RecordID: recordIDs})
	}
	return result, nil
}

func generatedArtifactRules(raw any) ([]generatedArtifactRule, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proof impact generatedArtifactRules must be an array")
	}
	result := make([]generatedArtifactRule, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proof impact generated artifact rule must be an object")
		}
		if err := admit.KnownKeys(record, []string{"generatedPath", "sourcePathPatterns"}, "proof impact generated artifact rule"); err != nil {
			return nil, err
		}
		generatedPath, err := safePath(record["generatedPath"], "proof impact generated artifact path")
		if err != nil {
			return nil, err
		}
		sourcePatterns, err := sortedSafePaths(record["sourcePathPatterns"], fmt.Sprintf("proof impact generated artifact %s sources", generatedPath))
		if err != nil {
			return nil, err
		}
		result = append(result, generatedArtifactRule{GeneratedPath: generatedPath, SourcePathPatterns: sourcePatterns})
	}
	return result, nil
}

func buildCatalog(obligations []obligationBase) (map[string]obligationBase, error) {
	sort.Slice(obligations, func(left int, right int) bool {
		return obligations[left].RecordID < obligations[right].RecordID
	})
	result := map[string]obligationBase{}
	for _, obligation := range obligations {
		if _, ok := result[obligation.RecordID]; ok {
			return nil, fmt.Errorf("proof impact obligationCatalog has duplicate recordId: %s", obligation.RecordID)
		}
		result[obligation.RecordID] = obligation
	}
	return result, nil
}

func generatedMirrorFailures(rules []generatedArtifactRule, changedPaths []string) []string {
	changed := stringSet(changedPaths)
	failures := []string{}
	for _, rule := range rules {
		if _, ok := changed[rule.GeneratedPath]; !ok {
			continue
		}
		sourceChanged := false
		for _, changedPath := range changedPaths {
			for _, pattern := range rule.SourcePathPatterns {
				if pathpattern.Match(pattern, changedPath) {
					sourceChanged = true
					break
				}
			}
			if sourceChanged {
				break
			}
		}
		if !sourceChanged {
			failures = append(failures, fmt.Sprintf("changed generated mirror without source change: %s", rule.GeneratedPath))
		}
	}
	sort.Strings(failures)
	return failures
}

func addReason(values map[string]map[string]struct{}, rawRecordID string, reason string) {
	recordID, err := admit.RuleID(rawRecordID, "proof impact changed recordId")
	if err != nil {
		return
	}
	if _, ok := values[recordID]; !ok {
		values[recordID] = map[string]struct{}{reason: {}}
		return
	}
	values[recordID][reason] = struct{}{}
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, ruleID)
	}
	sort.Strings(result)
	return assertSortedUnique(result, context)
}

func sortedSafePaths(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := safePath(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Strings(result)
	return assertSortedUnique(result, context)
}

func sortedNonEmptyText(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := nonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return assertSortedUnique(result, context)
}

func sortedDisplayCommandText(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return assertSortedUnique(result, context)
}

func sortedFailureText(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func failureText(raw any) ([]string, error) {
	values, err := stringArray(raw, "proof impact preexisting failure")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, "proof impact preexisting failure")
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	sort.Strings(result)
	return result, nil
}

func optionalFailureText(raw any) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	values, err := stringArray(raw, "proof impact nonClaims")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, "proof impact nonClaims")
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	sort.Strings(result)
	return assertSortedUnique(result, "proof impact nonClaims")
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

func nonEmptyText(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	return value, nil
}

func safePath(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a repository-relative POSIX path", context)
	}
	return admit.SafeRepoRelativePath(value, context)
}

func assertSortedUnique(values []string, context string) ([]string, error) {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func sortedUniqueFailures(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSetValues(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
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
