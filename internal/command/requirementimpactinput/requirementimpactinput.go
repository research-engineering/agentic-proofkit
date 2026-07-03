package requirementimpactinput

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/changedpathset"
	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type input struct {
	BaseCommit                  string
	BaseCompactProofContract    *compactproofcontract.Contract
	BaseRef                     string
	BaseRequirements            map[string]requirementsourceadmission.Requirement
	ChangedPathSources          []changedpathset.SourceInput
	CurrentCompactProofContract compactproofcontract.Contract
	CurrentRequirements         map[string]requirementsourceadmission.Requirement
	GeneratedArtifactPolicy     generatedArtifactPolicy
	GeneratedArtifactRules      []generatedArtifactRule
	HeadCommit                  *string
	HeadRef                     string
	LocalEnvironmentClasses     []string
	NonClaims                   []string
	PreexistingFailures         []string
	ProofBindingSourcePaths     []string
	ProofLikePolicy             proofLikePolicy
	UnboundProofChangeRationale string
}

type generatedArtifactPolicy struct {
	Source                  string
	State                   string
	UncoveredGeneratedPaths []string
}

type generatedArtifactRule struct {
	GeneratedPath      string
	SourcePathPatterns []string
}

type proofLikePolicy struct {
	IgnoredProofLikePaths []string
	NonClaims             []string
	ProofLikePathPatterns []string
}

type bindingRecord struct {
	BlockingStatus             string
	Commands                   []string
	FalsificationSelector      string
	Fingerprint                string
	Identity                   string
	PositiveSelector           string
	Preconditioned             bool
	ProofContractState         string
	RequirementID              string
	RequiredEnvironmentClasses []string
	ScenarioID                 string
	SurfaceID                  string
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	output, err := compose(input)
	if err != nil {
		return nil, 1, err
	}
	if _, _, err := impact.Build(output); err != nil {
		return nil, 1, err
	}
	return output, 0, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("requirement impact input compose input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baseCommit", "baseCompactProofContract", "baseRef", "baseRequirementSources", "changedPathSources", "composerInputId", "currentCompactProofContract", "currentRequirementSources", "generatedArtifactPolicyState", "generatedArtifactRules", "headCommit", "headRef", "localEnvironmentPolicy", "nonClaims", "preexistingFailures", "proofBindingSourcePaths", "proofLikePathPolicy", "schemaVersion", "unboundProofChangeRationale"}, "requirement impact input compose input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("requirement impact input compose schemaVersion must be 1")
	}
	if _, err := admit.RuleID(record["composerInputId"], "requirement impact input compose composerInputId"); err != nil {
		return input{}, err
	}
	baseRef, err := admit.NonEmptyText(record["baseRef"], "requirement impact input compose baseRef")
	if err != nil {
		return input{}, err
	}
	baseCommit, err := admit.NonEmptyText(record["baseCommit"], "requirement impact input compose baseCommit")
	if err != nil {
		return input{}, err
	}
	headRef, err := admit.NonEmptyText(record["headRef"], "requirement impact input compose headRef")
	if err != nil {
		return input{}, err
	}
	headCommit, err := admit.NullableText(record["headCommit"], "requirement impact input compose headCommit")
	if err != nil {
		return input{}, err
	}
	currentRequirements, err := admitRequirementSources(record["currentRequirementSources"], "currentRequirementSources", false)
	if err != nil {
		return input{}, err
	}
	baseRequirements, err := admitRequirementSources(record["baseRequirementSources"], "baseRequirementSources", true)
	if err != nil {
		return input{}, err
	}
	currentContract, err := compactproofcontract.Admit(record["currentCompactProofContract"])
	if err != nil {
		return input{}, err
	}
	var baseContract *compactproofcontract.Contract
	if record["baseCompactProofContract"] != nil {
		contract, err := compactproofcontract.Admit(record["baseCompactProofContract"])
		if err != nil {
			return input{}, err
		}
		baseContract = &contract
	}
	if (len(baseRequirements) == 0) != (baseContract == nil) {
		return input{}, fmt.Errorf("requirement impact input compose baseRequirementSources and baseCompactProofContract must both be present or both be null for new-adoption baselines")
	}
	changedPathSources, err := changedPathSources(record["changedPathSources"])
	if err != nil {
		return input{}, err
	}
	proofBindingSourcePaths, err := admit.PreserveSortedPathArray(record["proofBindingSourcePaths"], "requirement impact input compose proofBindingSourcePaths", true)
	if err != nil {
		return input{}, err
	}
	localEnvironmentClasses, err := localEnvironmentClasses(record["localEnvironmentPolicy"])
	if err != nil {
		return input{}, err
	}
	proofLikePolicy, err := admitProofLikePolicy(record["proofLikePathPolicy"])
	if err != nil {
		return input{}, err
	}
	generatedPolicy, err := admitGeneratedArtifactPolicy(record["generatedArtifactPolicyState"])
	if err != nil {
		return input{}, err
	}
	generatedRules, err := admitGeneratedArtifactRules(record["generatedArtifactRules"])
	if err != nil {
		return input{}, err
	}
	preexistingFailures, err := admit.PreserveSortedTextArray(record["preexistingFailures"], "requirement impact input compose preexistingFailures", true)
	if err != nil {
		return input{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement impact input compose nonClaims", false)
	if err != nil {
		return input{}, err
	}
	rationale := ""
	if rawRationale, ok := record["unboundProofChangeRationale"]; ok {
		rationale, err = admit.NonEmptyText(rawRationale, "requirement impact input compose unboundProofChangeRationale")
		if err != nil {
			return input{}, err
		}
	}
	return input{
		BaseCommit:                  baseCommit,
		BaseCompactProofContract:    baseContract,
		BaseRef:                     baseRef,
		BaseRequirements:            baseRequirements,
		ChangedPathSources:          changedPathSources,
		CurrentCompactProofContract: currentContract,
		CurrentRequirements:         currentRequirements,
		GeneratedArtifactPolicy:     generatedPolicy,
		GeneratedArtifactRules:      generatedRules,
		HeadCommit:                  headCommit,
		HeadRef:                     headRef,
		LocalEnvironmentClasses:     localEnvironmentClasses,
		NonClaims:                   nonClaims,
		PreexistingFailures:         preexistingFailures,
		ProofBindingSourcePaths:     proofBindingSourcePaths,
		ProofLikePolicy:             proofLikePolicy,
		UnboundProofChangeRationale: rationale,
	}, nil
}

func compose(input input) (map[string]any, error) {
	changed, err := changedpathset.Build(map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.requirement-impact-input.changed-path-set",
		"preexistingFailures": []any{},
		"nonClaims":           []any{"Requirement impact input composition uses changed-path admission as route input only."},
		"sources":             changedPathSourceValues(input.ChangedPathSources),
	})
	if err != nil {
		return nil, err
	}
	if changed.ExitCode != 0 {
		return nil, fmt.Errorf("requirement impact input compose requires passed changed-path source admission")
	}
	failures := append([]string{}, input.PreexistingFailures...)
	failures = append(failures, generatedPolicyFailures(input.GeneratedArtifactPolicy)...)
	currentByRequirement, currentByIdentity, err := impactBindings(input.CurrentCompactProofContract, input.LocalEnvironmentClasses, true)
	if err != nil {
		return nil, err
	}
	baseByIdentity := map[string]bindingRecord{}
	if input.BaseCompactProofContract != nil {
		_, baseByIdentity, err = impactBindings(*input.BaseCompactProofContract, input.LocalEnvironmentClasses, false)
		if err != nil {
			return nil, err
		}
	}
	failures = append(failures, unknownBindingRequirementFailures(currentByRequirement, input.CurrentRequirements)...)
	failures = append(failures, missingCurrentActiveBlockingBindingFailures(input.CurrentRequirements, currentByRequirement)...)
	changedRequirements, requirementFailures := changedRequirementIDs(input.BaseRequirements, input.CurrentRequirements)
	failures = append(failures, requirementFailures...)
	changedRecordIDs := []string{}
	for _, requirementID := range changedRequirements {
		requirement, ok := input.CurrentRequirements[requirementID]
		if !ok || !isActiveBlocking(requirement) {
			continue
		}
		if _, ok := currentByRequirement[requirementID]; !ok {
			continue
		}
		changedRecordIDs = append(changedRecordIDs, requirementID)
	}
	changedBindingIDs, bindingFailures := changedBindingRequirementIDs(input.BaseCompactProofContract != nil, baseByIdentity, currentByIdentity, input.CurrentRequirements, changed.ChangedPaths, input.ProofBindingSourcePaths)
	failures = append(failures, bindingFailures...)
	changedWitnessCoverage := changedWitnessPathCoverage(input.CurrentCompactProofContract, changed.ChangedPaths)
	proofLikePaths := proofLikeChangedPaths(changed.ChangedPaths, input.ProofLikePolicy.ProofLikePathPatterns, input.ProofLikePolicy.IgnoredProofLikePaths)
	impactedRequirementIDs := sortedUnion(changedRecordIDs, changedBindingIDs, witnessCoverageRequirementIDs(changedWitnessCoverage))
	obligations := []any{}
	for _, requirementID := range impactedRequirementIDs {
		binding, ok := currentByRequirement[requirementID]
		if !ok {
			failures = append(failures, fmt.Sprintf("impacted requirement has no current proof binding: %s", requirementID))
			continue
		}
		obligations = append(obligations, map[string]any{
			"blockingStatus":             binding.BlockingStatus,
			"commands":                   stringsToAny(binding.Commands),
			"preconditioned":             binding.Preconditioned,
			"proofContractState":         binding.ProofContractState,
			"recordId":                   binding.RequirementID,
			"requiredEnvironmentClasses": stringsToAny(binding.RequiredEnvironmentClasses),
			"scenarioId":                 binding.ScenarioID,
			"surfaceId":                  binding.SurfaceID,
		})
	}
	sort.Strings(failures)
	failures = uniqueStrings(failures)
	output := map[string]any{
		"schemaVersion":              json.Number("1"),
		"baseRef":                    input.BaseRef,
		"baseCommit":                 input.BaseCommit,
		"headRef":                    input.HeadRef,
		"headCommit":                 nullableTextValue(input.HeadCommit),
		"changedPaths":               stringsToAny(changed.ChangedPaths),
		"changedRecordIds":           stringsToAny(uniqueSorted(changedRecordIDs)),
		"changedBindingRecordIds":    stringsToAny(uniqueSorted(changedBindingIDs)),
		"changedWitnessPathCoverage": witnessCoverageValues(changedWitnessCoverage),
		"generatedArtifactRules":     generatedArtifactRuleValues(input.GeneratedArtifactRules),
		"ignoredProofLikePaths":      stringsToAny(input.ProofLikePolicy.IgnoredProofLikePaths),
		"nonClaims":                  stringsToAny(uniqueSorted(append(append([]string{}, input.NonClaims...), input.ProofLikePolicy.NonClaims...))),
		"obligationCatalog":          obligations,
		"preexistingFailures":        stringsToAny(failures),
		"proofLikePaths":             stringsToAny(proofLikePaths),
	}
	if input.UnboundProofChangeRationale != "" {
		output["unboundProofChangeRationale"] = input.UnboundProofChangeRationale
	}
	return output, nil
}

func admitRequirementSources(raw any, context string, nullable bool) (map[string]requirementsourceadmission.Requirement, error) {
	if raw == nil && nullable {
		return map[string]requirementsourceadmission.Requirement{}, nil
	}
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement impact input compose %s must be a non-empty array", context)
	}
	byID := map[string]requirementsourceadmission.Requirement{}
	for index, value := range values {
		result, err := requirementsourceadmission.Evaluate(value)
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("requirement impact input compose %s item %d must pass requirement source admission", context, index+1)
		}
		for _, requirement := range result.Source.Requirements {
			if _, exists := byID[requirement.RequirementID]; exists {
				return nil, fmt.Errorf("requirement impact input compose duplicate requirementId across %s: %s", context, requirement.RequirementID)
			}
			byID[requirement.RequirementID] = requirement
		}
	}
	return byID, nil
}

func changedPathSources(raw any) ([]changedpathset.SourceInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement impact input compose changedPathSources must be a non-empty array")
	}
	result := make([]changedpathset.SourceInput, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement impact input compose changedPathSources item %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"paths", "sourceId"}, "requirement impact input compose changedPathSources item"); err != nil {
			return nil, err
		}
		sourceID, err := admit.RuleID(record["sourceId"], "requirement impact input compose changedPathSources sourceId")
		if err != nil {
			return nil, err
		}
		paths, err := admit.TextArray(record["paths"], "requirement impact input compose changedPathSources paths", true)
		if err != nil {
			return nil, err
		}
		result = append(result, changedpathset.SourceInput{Paths: paths, SourceID: sourceID})
	}
	return result, nil
}

func localEnvironmentClasses(raw any) ([]string, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement impact input compose localEnvironmentPolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"localEnvironmentClasses"}, "requirement impact input compose localEnvironmentPolicy"); err != nil {
		return nil, err
	}
	return sortedRuleIDs(record["localEnvironmentClasses"], "requirement impact input compose localEnvironmentClasses", true)
}

func admitProofLikePolicy(raw any) (proofLikePolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return proofLikePolicy{}, fmt.Errorf("requirement impact input compose proofLikePathPolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"ignoredProofLikePaths", "nonClaims", "proofLikePathPatterns"}, "requirement impact input compose proofLikePathPolicy"); err != nil {
		return proofLikePolicy{}, err
	}
	patterns, err := admit.PreserveSortedPathArray(record["proofLikePathPatterns"], "requirement impact input compose proofLikePathPatterns", true)
	if err != nil {
		return proofLikePolicy{}, err
	}
	ignored, err := admit.PreserveSortedPathArray(record["ignoredProofLikePaths"], "requirement impact input compose ignoredProofLikePaths", true)
	if err != nil {
		return proofLikePolicy{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement impact input compose proofLikePathPolicy nonClaims", false)
	if err != nil {
		return proofLikePolicy{}, err
	}
	return proofLikePolicy{IgnoredProofLikePaths: ignored, NonClaims: nonClaims, ProofLikePathPatterns: patterns}, nil
}

func admitGeneratedArtifactPolicy(raw any) (generatedArtifactPolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return generatedArtifactPolicy{}, fmt.Errorf("requirement impact input compose generatedArtifactPolicyState must be an object")
	}
	if err := admit.KnownKeys(record, []string{"source", "state", "uncoveredGeneratedPaths"}, "requirement impact input compose generatedArtifactPolicyState"); err != nil {
		return generatedArtifactPolicy{}, err
	}
	state, err := admit.RuleID(record["state"], "requirement impact input compose generatedArtifactPolicyState state")
	if err != nil {
		return generatedArtifactPolicy{}, err
	}
	source, err := admit.RuleID(record["source"], "requirement impact input compose generatedArtifactPolicyState source")
	if err != nil {
		return generatedArtifactPolicy{}, err
	}
	uncovered, err := admit.PreserveSortedPathArray(record["uncoveredGeneratedPaths"], "requirement impact input compose uncoveredGeneratedPaths", true)
	if err != nil {
		return generatedArtifactPolicy{}, err
	}
	return generatedArtifactPolicy{Source: source, State: state, UncoveredGeneratedPaths: uncovered}, nil
}

func admitGeneratedArtifactRules(raw any) ([]generatedArtifactRule, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement impact input compose generatedArtifactRules must be an array")
	}
	result := make([]generatedArtifactRule, 0, len(values))
	paths := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement impact input compose generatedArtifactRules item %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"generatedPath", "sourcePathPatterns"}, "requirement impact input compose generatedArtifactRules item"); err != nil {
			return nil, err
		}
		path, err := safePath(record["generatedPath"], "requirement impact input compose generatedArtifactRules generatedPath")
		if err != nil {
			return nil, err
		}
		sources, err := admit.PreserveSortedPathArray(record["sourcePathPatterns"], "requirement impact input compose generatedArtifactRules sourcePathPatterns", true)
		if err != nil {
			return nil, err
		}
		result = append(result, generatedArtifactRule{GeneratedPath: path, SourcePathPatterns: sources})
		paths = append(paths, path)
	}
	if _, err := admit.PreserveSortedText(paths, "requirement impact input compose generatedArtifactRules generated paths", true); err != nil {
		return nil, err
	}
	return result, nil
}

func impactBindings(contract compactproofcontract.Contract, localClasses []string, requireUniqueRequirement bool) (map[string]bindingRecord, map[string]bindingRecord, error) {
	surfaces := map[string]compactproofcontract.Surface{}
	for _, surface := range contract.Surfaces {
		surfaces[surface.SurfaceID] = surface
	}
	byRequirement := map[string]bindingRecord{}
	byIdentity := map[string]bindingRecord{}
	for _, binding := range contract.Bindings {
		identity := bindingIdentity(binding)
		record := bindingRecord{
			BlockingStatus:             binding.BlockingStatus,
			Commands:                   append([]string{}, binding.VerifyCommands...),
			FalsificationSelector:      binding.FalsificationWitness.Selector,
			Fingerprint:                fullBindingFingerprint(binding),
			Identity:                   identity,
			PositiveSelector:           binding.PositiveWitness.Selector,
			Preconditioned:             preconditioned(surfaces[binding.SurfaceID], binding.RequiredEnvironmentClasses, localClasses),
			ProofContractState:         binding.ProofContractState,
			RequirementID:              binding.RequirementID,
			RequiredEnvironmentClasses: append([]string{}, binding.RequiredEnvironmentClasses...),
			ScenarioID:                 binding.ScenarioID,
			SurfaceID:                  binding.SurfaceID,
		}
		byIdentity[identity] = record
		if _, exists := byRequirement[binding.RequirementID]; exists && requireUniqueRequirement {
			return nil, nil, fmt.Errorf("requirement impact input compose current compact proof contract has multiple bindings for requirementId: %s", binding.RequirementID)
		}
		if _, exists := byRequirement[binding.RequirementID]; !exists {
			byRequirement[binding.RequirementID] = record
		}
	}
	return byRequirement, byIdentity, nil
}

func changedRequirementIDs(base map[string]requirementsourceadmission.Requirement, current map[string]requirementsourceadmission.Requirement) ([]string, []string) {
	ids := unionKeys(base, current)
	changed := []string{}
	failures := []string{}
	for _, id := range ids {
		baseRecord, baseOK := base[id]
		currentRecord, currentOK := current[id]
		if baseOK && !currentOK {
			changed = append(changed, id)
			failures = append(failures, "removed requirement record: "+id)
			continue
		}
		if !baseOK || requirementFingerprint(baseRecord) != requirementFingerprint(currentRecord) {
			changed = append(changed, id)
		}
	}
	return changed, failures
}

func changedBindingRequirementIDs(hasBase bool, base map[string]bindingRecord, current map[string]bindingRecord, currentRequirements map[string]requirementsourceadmission.Requirement, changedPaths []string, sourcePaths []string) ([]string, []string) {
	if !hasBase {
		return []string{}, []string{}
	}
	contractChanged := bindingSetFingerprint(base) != bindingSetFingerprint(current)
	sourceChanged := intersects(changedPaths, sourcePaths)
	if contractChanged && !sourceChanged {
		return []string{}, []string{"proof binding payload changed without changed proof-binding source path evidence"}
	}
	if !contractChanged {
		return []string{}, []string{}
	}
	changed := []string{}
	failures := []string{}
	for _, identity := range unionKeys(base, current) {
		baseRecord, baseOK := base[identity]
		currentRecord, currentOK := current[identity]
		if currentOK {
			if !baseOK || bindingFingerprint(baseRecord) != bindingFingerprint(currentRecord) {
				changed = append(changed, currentRecord.RequirementID)
			}
			continue
		}
		requirement, requirementOK := currentRequirements[baseRecord.RequirementID]
		if requirementOK && isActiveBlocking(requirement) {
			failures = append(failures, "removed proof binding for active blocking requirement: "+baseRecord.RequirementID)
		}
	}
	return uniqueSorted(changed), failures
}

func unknownBindingRequirementFailures(bindings map[string]bindingRecord, requirements map[string]requirementsourceadmission.Requirement) []string {
	failures := []string{}
	for _, requirementID := range sortedMapKeys(bindings) {
		if _, ok := requirements[requirementID]; !ok {
			failures = append(failures, "current compact proof binding references unknown current requirement: "+requirementID)
		}
	}
	return failures
}

func missingCurrentActiveBlockingBindingFailures(requirements map[string]requirementsourceadmission.Requirement, bindings map[string]bindingRecord) []string {
	failures := []string{}
	for _, requirementID := range sortedMapKeys(requirements) {
		requirement := requirements[requirementID]
		if !isActiveBlocking(requirement) {
			continue
		}
		if _, ok := bindings[requirementID]; !ok {
			failures = append(failures, "current active blocking requirement has no current proof binding: "+requirementID)
		}
	}
	return failures
}

func changedWitnessPathCoverage(contract compactproofcontract.Contract, changedPaths []string) []map[string][]string {
	changedSet := mapSet(changedPaths)
	byPath := map[string]map[string]struct{}{}
	for _, binding := range contract.Bindings {
		for _, selector := range []string{binding.PositiveWitness.Selector, binding.FalsificationWitness.Selector} {
			path := strings.Split(selector, "::")[0]
			if _, ok := changedSet[path]; !ok {
				continue
			}
			if byPath[path] == nil {
				byPath[path] = map[string]struct{}{}
			}
			byPath[path][binding.RequirementID] = struct{}{}
		}
	}
	paths := sortedMapKeys(byPath)
	result := make([]map[string][]string, 0, len(paths))
	for _, path := range paths {
		result = append(result, map[string][]string{path: sortedSetValues(byPath[path])})
	}
	return result
}

func proofLikeChangedPaths(changedPaths []string, patterns []string, ignored []string) []string {
	ignoredSet := mapSet(ignored)
	result := []string{}
	for _, changedPath := range changedPaths {
		if _, ok := ignoredSet[changedPath]; ok {
			continue
		}
		for _, pattern := range patterns {
			if pathpattern.Match(pattern, changedPath) {
				result = append(result, changedPath)
				break
			}
		}
	}
	return uniqueSorted(result)
}

func generatedPolicyFailures(policy generatedArtifactPolicy) []string {
	failures := []string{}
	if policy.State != "complete" {
		failures = append(failures, "generated artifact policy is not complete: "+policy.State)
	}
	for _, path := range policy.UncoveredGeneratedPaths {
		failures = append(failures, "uncovered generated artifact path: "+path)
	}
	return failures
}

func preconditioned(surface compactproofcontract.Surface, required []string, localClasses []string) bool {
	if len(surface.PreconditionedEnvironmentClasses) > 0 {
		return true
	}
	local := mapSet(localClasses)
	for _, class := range required {
		if _, ok := local[class]; !ok {
			return true
		}
	}
	return false
}

func isActiveBlocking(requirement requirementsourceadmission.Requirement) bool {
	return requirement.ClaimLevel == "blocking" && requirement.Lifecycle.State == "active"
}

func requirementFingerprint(requirement requirementsourceadmission.Requirement) string {
	return stableFingerprint(map[string]any{
		"claimLevel":       requirement.ClaimLevel,
		"deferral":         deferralValue(requirement.Deferral),
		"invariant":        requirement.Invariant,
		"lifecycle":        lifecycleValue(requirement.Lifecycle),
		"nonClaimRefs":     stringsToAny(requirement.NonClaimRefs),
		"nonClaims":        stringsToAny(requirement.NonClaims),
		"ownerId":          requirement.OwnerID,
		"proofBindingRefs": stringsToAny(requirement.ProofBindingRefs),
		"requirementId":    requirement.RequirementID,
		"riskClass":        requirement.RiskClass,
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  requirement.UpdatePolicy.RequiresImpactDeclaration,
			"requiresProofBindingReview": requirement.UpdatePolicy.RequiresProofBindingReview,
			"reviewOwnerId":              requirement.UpdatePolicy.ReviewOwnerID,
		},
	})
}

func bindingFingerprint(binding bindingRecord) string {
	return binding.Fingerprint
}

func fullBindingFingerprint(binding compactproofcontract.Binding) string {
	return stableFingerprint(map[string]any{
		"blockingStatus":             binding.BlockingStatus,
		"falsificationWitness":       witnessFingerprintValue(binding.FalsificationWitness),
		"invariantRole":              binding.InvariantRole,
		"mutationResistanceState":    binding.MutationResistanceState,
		"ownedInvariant":             binding.OwnedInvariant,
		"positiveWitness":            witnessFingerprintValue(binding.PositiveWitness),
		"proofContractState":         binding.ProofContractState,
		"requirementId":              binding.RequirementID,
		"requiredEnvironmentClasses": stringsToAny(binding.RequiredEnvironmentClasses),
		"scenarioId":                 binding.ScenarioID,
		"surfaceId":                  binding.SurfaceID,
		"verifyCommands":             stringsToAny(binding.VerifyCommands),
	})
}

func witnessFingerprintValue(witness compactproofcontract.Witness) map[string]any {
	return map[string]any{
		"environmentClasses":   stringsToAny(witness.EnvironmentClasses),
		"resolutionOrderIndex": witness.ResolutionOrderIndex,
		"selector":             witness.Selector,
		"verifyCommands":       stringsToAny(witness.VerifyCommands),
	}
}

func bindingSetFingerprint(bindings map[string]bindingRecord) string {
	rows := []any{}
	for _, key := range sortedMapKeys(bindings) {
		rows = append(rows, map[string]any{"identity": key, "fingerprint": bindingFingerprint(bindings[key])})
	}
	return stableFingerprint(rows)
}

func bindingIdentity(binding compactproofcontract.Binding) string {
	return binding.RequirementID + "\x00" + binding.SurfaceID + "\x00" + binding.ScenarioID
}

func stableFingerprint(value any) string {
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func deferralValue(deferral *requirementsourceadmission.Deferral) any {
	if deferral == nil {
		return nil
	}
	return map[string]any{
		"evidenceRefs":    stringsToAny(deferral.EvidenceRefs),
		"expiryRef":       deferral.ExpiryRef,
		"mergePolicy":     deferral.MergePolicy,
		"ownerId":         deferral.OwnerID,
		"reviewCondition": deferral.ReviewCondition,
		"riskAcceptedBy":  deferral.RiskAcceptedBy,
	}
}

func lifecycleValue(lifecycle requirementsourceadmission.Lifecycle) map[string]any {
	return map[string]any{
		"evidenceRefs":              stringsToAny(lifecycle.EvidenceRefs),
		"replacementRequirementIds": stringsToAny(lifecycle.ReplacementRequirementIDs),
		"state":                     lifecycle.State,
	}
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if _, err := admit.RuleID(value, context); err != nil {
			return nil, err
		}
	}
	return admit.PreserveSortedText(values, context, allowEmpty)
}

func safePath(raw any, context string) (string, error) {
	text, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(text, context)
}

func changedPathSourceValues(sources []changedpathset.SourceInput) []any {
	result := make([]any, 0, len(sources))
	for _, source := range sources {
		result = append(result, map[string]any{"sourceId": source.SourceID, "paths": stringsToAny(source.Paths)})
	}
	return result
}

func generatedArtifactRuleValues(rules []generatedArtifactRule) []any {
	result := make([]any, 0, len(rules))
	for _, rule := range rules {
		result = append(result, map[string]any{
			"generatedPath":      rule.GeneratedPath,
			"sourcePathPatterns": stringsToAny(rule.SourcePathPatterns),
		})
	}
	return result
}

func witnessCoverageValues(coverage []map[string][]string) []any {
	result := []any{}
	for _, item := range coverage {
		for path, requirementIDs := range item {
			result = append(result, map[string]any{"path": path, "recordIds": stringsToAny(requirementIDs)})
		}
	}
	return result
}

func witnessCoverageRequirementIDs(coverage []map[string][]string) []string {
	result := []string{}
	for _, item := range coverage {
		for _, requirementIDs := range item {
			result = append(result, requirementIDs...)
		}
	}
	return result
}

func nullableTextValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func intersects(left []string, right []string) bool {
	set := mapSet(left)
	for _, value := range right {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}

func mapSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func unionKeys[T any](left map[string]T, right map[string]T) []string {
	values := map[string]struct{}{}
	for key := range left {
		values[key] = struct{}{}
	}
	for key := range right {
		values[key] = struct{}{}
	}
	return sortedSetValues(values)
}

func sortedUnion(groups ...[]string) []string {
	values := []string{}
	for _, group := range groups {
		values = append(values, group...)
	}
	return uniqueSorted(values)
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	return uniqueStrings(values)
}

func uniqueStrings(values []string) []string {
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
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
