package impact

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
)

type obligationBase struct {
	BindingRecordID                   string
	BlockingStatus                    string
	Commands                          []string
	DeclaredMutationResistanceClaimID string
	DeclaredWitnessRoutes             []declaredWitnessRoute
	Preconditioned                    bool
	RequirementID                     string
	RequiredEnvironmentClasses        []string
	ScenarioID                        string
	SurfaceID                         string
}

type witnessCoverage struct {
	Path   string
	Routes []witnessRoute
}

type witnessRoute struct {
	BindingRecordID      string
	ResolutionOrderIndex int
	Role                 string
	Selector             string
	WitnessRouteID       string
}

type declaredWitnessRoute struct {
	BindingRecordID      string
	EnvironmentClasses   []string
	ResolutionOrderIndex int
	Role                 string
	Selector             string
	VerifyCommands       []string
	WitnessRouteID       string
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
	ChangedRequirementIDs       []string
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

var impactNonClaims = []string{
	"Impact reports classify caller-owned changed paths and proof records only.",
	"Impact reports do not run git, scan repositories, execute witnesses, authenticate receipts, approve merge, or prove proof freshness.",
	"Impact reports do not decide the consuming repository fallback policy for unbound or unknown proof changes.",
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
	witnessRoutesByRecordID := map[string]map[string]witnessRoute{}
	bindingsByRequirementID := map[string][]string{}
	for _, obligation := range input.ObligationCatalog {
		bindingsByRequirementID[obligation.RequirementID] = append(bindingsByRequirementID[obligation.RequirementID], obligation.BindingRecordID)
	}
	for _, requirementID := range input.ChangedRequirementIDs {
		bindingRecordIDs := bindingsByRequirementID[requirementID]
		if len(bindingRecordIDs) == 0 {
			failures = append(failures, fmt.Sprintf("changed requirement has no obligation catalog binding: %s", requirementID))
			continue
		}
		for _, bindingRecordID := range bindingRecordIDs {
			addReason(reasonsByRecordID, bindingRecordID, "requirement_changed")
		}
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
		for _, route := range coverage.Routes {
			addReason(reasonsByRecordID, route.BindingRecordID, "proof_witness_changed")
			if witnessRoutesByRecordID[route.BindingRecordID] == nil {
				witnessRoutesByRecordID[route.BindingRecordID] = map[string]witnessRoute{}
			}
			witnessRoutesByRecordID[route.BindingRecordID][route.WitnessRouteID] = route
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
			"bindingRecordId":                   base.BindingRecordID,
			"blockingStatus":                    base.BlockingStatus,
			"changeReasons":                     stringsToAny(reasons),
			"commands":                          stringsToAny(base.Commands),
			"declaredMutationResistanceClaimId": base.DeclaredMutationResistanceClaimID,
			"declaredWitnessRoutes":             declaredWitnessRouteValues(base.DeclaredWitnessRoutes),
			"preconditioned":                    base.Preconditioned,
			"requirementId":                     base.RequirementID,
			"requiredEnvironmentClasses":        stringsToAny(base.RequiredEnvironmentClasses),
			"scenarioId":                        base.ScenarioID,
			"surfaceId":                         base.SurfaceID,
			"witnessRoutes":                     witnessRouteValues(witnessRoutesByRecordID[recordID]),
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
		"baseCommit":            input.BaseCommit,
		"baseRef":               input.BaseRef,
		"changedPaths":          stringsToAny(input.ChangedPaths),
		"changedRequirementIds": stringsToAny(input.ChangedRequirementIDs),
		"failures":              stringsToAny(failures),
		"headCommit":            headCommit,
		"headRef":               input.HeadRef,
		"impactState":           impactState,
		"nonClaims":             stringsToAny(input.NonClaims),
		"obligations":           mapsToAny(obligations),
		"schemaVersion":         2,
		"unboundProofChanges":   unboundProofChanges,
	}, exitCode
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("proof impact report input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baseCommit", "baseRef", "changedBindingRecordIds", "changedPaths", "changedRequirementIds", "changedWitnessPathCoverage", "generatedArtifactRules", "headCommit", "headRef", "ignoredProofLikePaths", "nonClaims", "obligationCatalog", "preexistingFailures", "proofLikePaths", "schemaVersion", "unboundProofChangeRationale"}, "proof impact report input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 2) {
		return input{}, fmt.Errorf("proof impact report schemaVersion must be 2")
	}
	changedPaths, err := sortedSafePaths(requireField(record, "changedPaths"), "proof impact changedPaths")
	if err != nil {
		return input{}, err
	}
	changedRequirementIDs, err := sortedRuleIDs(requireField(record, "changedRequirementIds"), "proof impact changedRequirementIds")
	if err != nil {
		return input{}, err
	}
	changedBindingRecordIDs, err := sortedSHA256Refs(requireField(record, "changedBindingRecordIds"), "proof impact changedBindingRecordIds")
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
	nonClaims, err = admit.MergeNonClaims(impactNonClaims, nonClaims, "proof impact")
	if err != nil {
		return input{}, err
	}
	obligationCatalog, err := obligationCatalog(requireField(record, "obligationCatalog"))
	if err != nil {
		return input{}, err
	}
	catalog, err := buildCatalog(append([]obligationBase{}, obligationCatalog...))
	if err != nil {
		return input{}, err
	}
	changedWitnessCoverage, err := witnessCoverageRecords(requireField(record, "changedWitnessPathCoverage"), catalog)
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
		ChangedRequirementIDs:       changedRequirementIDs,
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
	if err := admit.KnownKeys(record, []string{"bindingRecordId", "blockingStatus", "commands", "declaredMutationResistanceClaimId", "declaredWitnessRoutes", "preconditioned", "requiredEnvironmentClasses", "requirementId", "scenarioId", "surfaceId"}, "proof impact obligation record"); err != nil {
		return obligationBase{}, err
	}
	bindingRecordID, err := admit.SHA256Ref(record["bindingRecordId"], "proof impact obligation bindingRecordId")
	if err != nil {
		return obligationBase{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], fmt.Sprintf("proof impact %s requirementId", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	blockingStatus, err := admit.RuleID(record["blockingStatus"], fmt.Sprintf("proof impact %s blockingStatus", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	commands, err := sortedDisplayCommandText(record["commands"], fmt.Sprintf("proof impact %s commands", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	preconditioned, ok := record["preconditioned"].(bool)
	if !ok {
		return obligationBase{}, fmt.Errorf("proof impact %s preconditioned must be a boolean", bindingRecordID)
	}
	declaredMutationResistanceClaimID, err := admit.RuleID(record["declaredMutationResistanceClaimId"], fmt.Sprintf("proof impact %s declaredMutationResistanceClaimId", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	requiredEnvironmentClasses, err := sortedNonEmptyText(record["requiredEnvironmentClasses"], fmt.Sprintf("proof impact %s requiredEnvironmentClasses", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	scenarioID, err := nonEmptyText(record["scenarioId"], fmt.Sprintf("proof impact %s scenarioId", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	surfaceID, err := admit.RuleID(record["surfaceId"], fmt.Sprintf("proof impact %s surfaceId", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	scenarioID, scenarioSurfaceID, err := compactproofcontract.AdmitScenarioID(scenarioID, fmt.Sprintf("proof impact %s scenarioId", bindingRecordID))
	if err != nil {
		return obligationBase{}, err
	}
	if scenarioSurfaceID != surfaceID {
		return obligationBase{}, fmt.Errorf("proof impact %s scenarioId must be scoped under surfaceId %s", bindingRecordID, surfaceID)
	}
	expectedBindingRecordID, err := compactproofcontract.BindingRecordID(compactproofcontract.BindingIdentity{
		RequirementID: requirementID,
		ScenarioID:    scenarioID,
		SurfaceID:     surfaceID,
	})
	if err != nil {
		return obligationBase{}, err
	}
	if bindingRecordID != expectedBindingRecordID {
		return obligationBase{}, fmt.Errorf("proof impact obligation bindingRecordId does not match its requirement, surface, and scenario identity")
	}
	declaredWitnessRoutes, err := admitDeclaredWitnessRoutes(record["declaredWitnessRoutes"], bindingRecordID)
	if err != nil {
		return obligationBase{}, err
	}
	if !containsAll(commands, declaredWitnessRouteCommands(declaredWitnessRoutes)) {
		return obligationBase{}, fmt.Errorf("proof impact %s commands must include every declared witness route command", bindingRecordID)
	}
	if !containsAll(requiredEnvironmentClasses, declaredWitnessRouteEnvironments(declaredWitnessRoutes)) {
		return obligationBase{}, fmt.Errorf("proof impact %s requiredEnvironmentClasses must include every declared witness route environment", bindingRecordID)
	}
	return obligationBase{
		BindingRecordID:                   bindingRecordID,
		BlockingStatus:                    blockingStatus,
		Commands:                          commands,
		DeclaredMutationResistanceClaimID: declaredMutationResistanceClaimID,
		DeclaredWitnessRoutes:             declaredWitnessRoutes,
		Preconditioned:                    preconditioned,
		RequirementID:                     requirementID,
		RequiredEnvironmentClasses:        requiredEnvironmentClasses,
		ScenarioID:                        scenarioID,
		SurfaceID:                         surfaceID,
	}, nil
}

func admitDeclaredWitnessRoutes(raw any, bindingRecordID string) ([]declaredWitnessRoute, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != 2 {
		return nil, fmt.Errorf("proof impact %s declaredWitnessRoutes must contain exactly two routes", bindingRecordID)
	}
	routes := make([]declaredWitnessRoute, 0, len(values))
	previousRouteID := ""
	roles := map[string]struct{}{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proof impact %s declaredWitnessRoutes item %d must be an object", bindingRecordID, index+1)
		}
		context := fmt.Sprintf("proof impact %s declaredWitnessRoutes item %d", bindingRecordID, index+1)
		if err := admit.KnownKeys(record, []string{"bindingRecordId", "environmentClasses", "resolutionOrderIndex", "role", "selector", "verifyCommands", "witnessRouteId"}, context); err != nil {
			return nil, err
		}
		routeBindingID, err := admit.SHA256Ref(record["bindingRecordId"], context+" bindingRecordId")
		if err != nil {
			return nil, err
		}
		if routeBindingID != bindingRecordID {
			return nil, fmt.Errorf("%s bindingRecordId must equal its obligation bindingRecordId", context)
		}
		role, err := admit.Enum(record["role"], map[string]struct{}{
			compactproofcontract.FalsificationWitnessRole: {},
			compactproofcontract.PositiveWitnessRole:      {},
		}, context+" role")
		if err != nil {
			return nil, err
		}
		if _, duplicate := roles[role]; duplicate {
			return nil, fmt.Errorf("proof impact %s declaredWitnessRoutes must contain one route per role", bindingRecordID)
		}
		roles[role] = struct{}{}
		selectorText, err := nonEmptyText(record["selector"], context+" selector")
		if err != nil {
			return nil, err
		}
		selector, err := compactproofcontract.AdmitWitnessSelector(selectorText, context+" selector")
		if err != nil {
			return nil, err
		}
		resolutionOrderIndex, err := compactproofcontract.AdmitProjectedResolutionOrderIndex(record["resolutionOrderIndex"], context+" resolutionOrderIndex")
		if err != nil {
			return nil, err
		}
		environmentClasses, err := sortedRuleIDs(record["environmentClasses"], context+" environmentClasses")
		if err != nil {
			return nil, err
		}
		verifyCommands, err := sortedOptionalDisplayCommandText(record["verifyCommands"], context+" verifyCommands")
		if err != nil {
			return nil, err
		}
		witnessRouteID, err := admit.SHA256Ref(record["witnessRouteId"], context+" witnessRouteId")
		if err != nil {
			return nil, err
		}
		expectedRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, role, selector)
		if err != nil {
			return nil, err
		}
		if witnessRouteID != expectedRouteID {
			return nil, fmt.Errorf("%s witnessRouteId does not match its binding, role, and selector identity", context)
		}
		if previousRouteID != "" && previousRouteID >= witnessRouteID {
			return nil, fmt.Errorf("proof impact %s declaredWitnessRoutes must be sorted and unique by witnessRouteId", bindingRecordID)
		}
		previousRouteID = witnessRouteID
		routes = append(routes, declaredWitnessRoute{
			BindingRecordID: routeBindingID, EnvironmentClasses: environmentClasses,
			ResolutionOrderIndex: resolutionOrderIndex, Role: role, Selector: selector,
			VerifyCommands: verifyCommands, WitnessRouteID: witnessRouteID,
		})
	}
	return routes, nil
}

func witnessCoverageRecords(raw any, catalog map[string]obligationBase) ([]witnessCoverage, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proof impact changedWitnessPathCoverage must be an array")
	}
	result := make([]witnessCoverage, 0, len(values))
	previousPath := ""
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proof impact witness coverage must be an object")
		}
		if err := admit.KnownKeys(record, []string{"path", "routes"}, "proof impact witness coverage"); err != nil {
			return nil, err
		}
		witnessPath, err := safePath(record["path"], "proof impact witness path")
		if err != nil {
			return nil, err
		}
		if previousPath != "" && previousPath >= witnessPath {
			return nil, fmt.Errorf("proof impact changedWitnessPathCoverage must be sorted and unique by path")
		}
		previousPath = witnessPath
		routes, err := admitWitnessRoutes(record["routes"], witnessPath, catalog)
		if err != nil {
			return nil, err
		}
		result = append(result, witnessCoverage{Path: witnessPath, Routes: routes})
	}
	return result, nil
}

func admitWitnessRoutes(raw any, witnessPath string, catalog map[string]obligationBase) ([]witnessRoute, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("proof impact witness coverage %s routes must be a non-empty array", witnessPath)
	}
	routes := make([]witnessRoute, 0, len(values))
	previousRouteID := ""
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proof impact witness coverage %s route #%d must be an object", witnessPath, index+1)
		}
		context := fmt.Sprintf("proof impact witness coverage %s route #%d", witnessPath, index+1)
		if err := admit.KnownKeys(record, []string{"bindingRecordId", "resolutionOrderIndex", "role", "selector", "witnessRouteId"}, context); err != nil {
			return nil, err
		}
		bindingRecordID, err := admit.SHA256Ref(record["bindingRecordId"], context+" bindingRecordId")
		if err != nil {
			return nil, err
		}
		obligation, ok := catalog[bindingRecordID]
		if !ok {
			return nil, fmt.Errorf("%s references unknown obligation bindingRecordId", context)
		}
		role, err := admit.Enum(record["role"], map[string]struct{}{
			compactproofcontract.FalsificationWitnessRole: {},
			compactproofcontract.PositiveWitnessRole:      {},
		}, context+" role")
		if err != nil {
			return nil, err
		}
		selectorText, err := nonEmptyText(record["selector"], context+" selector")
		if err != nil {
			return nil, err
		}
		selector, err := compactproofcontract.AdmitWitnessSelector(selectorText, context+" selector")
		if err != nil {
			return nil, err
		}
		if strings.SplitN(selector, "::", 2)[0] != witnessPath {
			return nil, fmt.Errorf("%s selector path must equal its coverage path", context)
		}
		resolutionOrderIndex, err := compactproofcontract.AdmitProjectedResolutionOrderIndex(record["resolutionOrderIndex"], context+" resolutionOrderIndex")
		if err != nil {
			return nil, err
		}
		witnessRouteID, err := admit.SHA256Ref(record["witnessRouteId"], context+" witnessRouteId")
		if err != nil {
			return nil, err
		}
		expectedRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, role, selector)
		if err != nil {
			return nil, err
		}
		if witnessRouteID != expectedRouteID {
			return nil, fmt.Errorf("%s witnessRouteId does not match its binding, role, and selector identity", context)
		}
		route := witnessRoute{
			BindingRecordID: bindingRecordID, ResolutionOrderIndex: resolutionOrderIndex,
			Role: role, Selector: selector, WitnessRouteID: witnessRouteID,
		}
		if !matchesDeclaredWitnessRoute(route, obligation.DeclaredWitnessRoutes) {
			return nil, fmt.Errorf("%s does not match an obligation catalog declared witness route", context)
		}
		if previousRouteID != "" && previousRouteID >= witnessRouteID {
			return nil, fmt.Errorf("proof impact witness coverage %s routes must be sorted and unique by witnessRouteId", witnessPath)
		}
		previousRouteID = witnessRouteID
		routes = append(routes, route)
	}
	return routes, nil
}

func matchesDeclaredWitnessRoute(route witnessRoute, declared []declaredWitnessRoute) bool {
	for _, candidate := range declared {
		if candidate.BindingRecordID == route.BindingRecordID &&
			candidate.Role == route.Role &&
			candidate.Selector == route.Selector &&
			candidate.ResolutionOrderIndex == route.ResolutionOrderIndex &&
			candidate.WitnessRouteID == route.WitnessRouteID {
			return true
		}
	}
	return false
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
		return obligations[left].BindingRecordID < obligations[right].BindingRecordID
	})
	result := map[string]obligationBase{}
	for _, obligation := range obligations {
		if _, ok := result[obligation.BindingRecordID]; ok {
			return nil, fmt.Errorf("proof impact obligationCatalog has duplicate bindingRecordId: %s", obligation.BindingRecordID)
		}
		result[obligation.BindingRecordID] = obligation
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

func addReason(values map[string]map[string]struct{}, recordID string, reason string) {
	if _, ok := values[recordID]; !ok {
		values[recordID] = map[string]struct{}{reason: {}}
		return
	}
	values[recordID][reason] = struct{}{}
}

func witnessRouteValues(routes map[string]witnessRoute) []any {
	ids := sortedMapKeys(routes)
	result := make([]any, 0, len(ids))
	for _, routeID := range ids {
		route := routes[routeID]
		result = append(result, map[string]any{
			"bindingRecordId":      route.BindingRecordID,
			"resolutionOrderIndex": route.ResolutionOrderIndex,
			"role":                 route.Role,
			"selector":             route.Selector,
			"witnessRouteId":       route.WitnessRouteID,
		})
	}
	return result
}

func declaredWitnessRouteValues(routes []declaredWitnessRoute) []any {
	result := make([]any, 0, len(routes))
	for _, route := range routes {
		result = append(result, map[string]any{
			"bindingRecordId":      route.BindingRecordID,
			"environmentClasses":   stringsToAny(route.EnvironmentClasses),
			"resolutionOrderIndex": route.ResolutionOrderIndex,
			"role":                 route.Role,
			"selector":             route.Selector,
			"verifyCommands":       stringsToAny(route.VerifyCommands),
			"witnessRouteId":       route.WitnessRouteID,
		})
	}
	return result
}

func declaredWitnessRouteCommands(routes []declaredWitnessRoute) []string {
	values := []string{}
	for _, route := range routes {
		values = append(values, route.VerifyCommands...)
	}
	return sortedSetValues(stringSet(values))
}

func declaredWitnessRouteEnvironments(routes []declaredWitnessRoute) []string {
	values := []string{}
	for _, route := range routes {
		values = append(values, route.EnvironmentClasses...)
	}
	return sortedSetValues(stringSet(values))
}

func containsAll(haystack []string, needles []string) bool {
	set := stringSet(haystack)
	for _, needle := range needles {
		if _, ok := set[needle]; !ok {
			return false
		}
	}
	return true
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

func sortedSHA256Refs(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		ref, err := admit.SHA256Ref(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, ref)
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
	result, err := sortedOptionalDisplayCommandText(raw, context)
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return result, nil
}

func sortedOptionalDisplayCommandText(raw any, context string) ([]string, error) {
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
