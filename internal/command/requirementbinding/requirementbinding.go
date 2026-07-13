package requirementbinding

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

var claimLevels = map[string]struct{}{
	"advisory": {},
	"blocking": {},
	"deferred": {},
}

var proofStates = map[string]struct{}{
	"explicitly_deferred": {},
	"not_bound":           {},
	"witness_backed":      {},
}

var witnessKinds = map[string]struct{}{
	"contract":      {},
	"falsification": {},
	"technical":     {},
}

var defaultNonClaims = []string{
	"Requirement proof binding reports do not execute native witnesses.",
	"Requirement proof binding reports do not prove command pass evidence.",
	"Evidence graphs and proof slices are lookup projections only.",
	"Consuming repositories own requirement meaning, proof freshness, and rollout policy.",
}

type Input struct {
	BindingID       string
	Requirements    []Requirement
	Bindings        []Binding
	WitnessCommands []WitnessCommand
	Selection       Selection
	NonClaims       []string
}

type Requirement struct {
	RequirementID string
	OwnerID       string
	SpecPath      string
	ClaimLevel    string
	ProofState    string
	NonClaims     []string
}

type Binding struct {
	RequirementID      string
	ScenarioID         string
	WitnessID          string
	WitnessKind        string
	WitnessPath        string
	CommandIDs         []string
	EnvironmentClasses []string
}

type WitnessCommand struct {
	CommandID          string
	Command            string
	EnvironmentClasses []string
}

type Selection struct {
	ChangedPaths   []string
	OwnerIDs       []string
	RequirementIDs []string
}

type Result struct {
	Record report.Record
	Graph  map[string]any
	Input  Input
	Slice  map[string]any
}

type ResolverOptions struct {
	LocalEnvironmentClasses []string
}

type CompactFalsificationRoute struct {
	FalsificationSelector string
	OwnedInvariant        string
	RequirementID         string
	SurfaceID             string
	VerifyCommands        []string
}

// SelectRequirements returns a reference-closed owner projection containing
// only the selected requirements, bindings, and commands they reference.
func SelectRequirements(input Input, selected map[string]struct{}) Input {
	result := Input{
		BindingID: input.BindingID,
		NonClaims: append([]string{}, input.NonClaims...),
	}
	selectedOwned := map[string]struct{}{}
	commandIDs := map[string]struct{}{}
	for _, requirement := range input.Requirements {
		if _, ok := selected[requirement.RequirementID]; ok {
			result.Requirements = append(result.Requirements, requirement)
			selectedOwned[requirement.RequirementID] = struct{}{}
		}
	}
	result.Selection = Selection{RequirementIDs: sortedSetKeys(selectedOwned)}
	for _, binding := range input.Bindings {
		if _, ok := selected[binding.RequirementID]; !ok {
			continue
		}
		result.Bindings = append(result.Bindings, binding)
		for _, commandID := range binding.CommandIDs {
			commandIDs[commandID] = struct{}{}
		}
	}
	for _, command := range input.WitnessCommands {
		if _, ok := commandIDs[command.CommandID]; ok {
			result.WitnessCommands = append(result.WitnessCommands, command)
		}
	}
	return result
}

// SelectionFragmentValue returns a lookup-only subset. It deliberately does
// not retain the complete binding identity, so consumers cannot re-admit a
// bounded fragment as the caller-owned proof-binding source.
func SelectionFragmentValue(input Input, selected map[string]struct{}) map[string]any {
	projected := SelectRequirements(input, selected)
	value := InputValue(projected)
	delete(value, "bindingId")
	value["authority"] = "lookup_fragment_only"
	value["projectionKind"] = "proofkit.requirement-binding-fragment"
	value["sourceBindingId"] = input.BindingID
	return value
}

func sortedSetKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func BuildResolver(raw any, options ResolverOptions) (any, int, error) {
	contract, err := compactproofcontract.Admit(raw)
	if err != nil {
		return nil, 1, err
	}
	projection, err := contract.ResolverProjection(compactproofcontract.ResolverOptions{
		LocalEnvironmentClasses: options.LocalEnvironmentClasses,
	})
	if err != nil {
		return nil, 1, err
	}
	return projection, 0, nil
}

func CompactFalsificationRoutes(raw any) ([]CompactFalsificationRoute, error) {
	contract, err := compactproofcontract.Admit(raw)
	if err != nil {
		return nil, err
	}
	kernelRoutes := contract.FalsificationRoutes()
	routes := make([]CompactFalsificationRoute, 0, len(kernelRoutes))
	for _, route := range kernelRoutes {
		routes = append(routes, CompactFalsificationRoute{
			FalsificationSelector: route.FalsificationSelector,
			OwnedInvariant:        route.OwnedInvariant,
			RequirementID:         route.RequirementID,
			SurfaceID:             route.SurfaceID,
			VerifyCommands:        append([]string{}, route.VerifyCommands...),
		})
	}
	return routes, nil
}

func BuildReport(raw any) (report.Record, int, error) {
	result, err := Build(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	if result.Record.State == "passed" {
		return result.Record, 0, nil
	}
	return result.Record, 1, nil
}

func BuildEvidenceGraph(raw any) (any, int, error) {
	result, err := Build(raw)
	if err != nil {
		return nil, 1, err
	}
	if result.Record.State != "passed" {
		return nil, 1, fmt.Errorf("cannot build evidence graph from failed requirement proof bindings: %s", failureMessages(result.Record))
	}
	return result.Graph, 0, nil
}

func BuildProofSlice(raw any) (any, int, error) {
	result, err := Build(raw)
	if err != nil {
		return nil, 1, err
	}
	if result.Record.State != "passed" {
		return nil, 1, fmt.Errorf("cannot build proof slice from failed requirement proof bindings: %s", failureMessages(result.Record))
	}
	return result.Slice, 0, nil
}

func Build(raw any) (Result, error) {
	failures := []string{}
	input, err := admitInput(raw, &failures)
	if err != nil {
		return Result{}, err
	}
	failures = append(failures, semanticFailures(input)...)
	failures = sortedUnique(failures)
	graph := buildGraph(input)
	slice := buildSlice(input, graph)
	record := buildReport(input, graph, slice, failures)
	return Result{Record: record, Graph: graph, Input: input, Slice: slice}, nil
}

func InputValue(input Input) map[string]any {
	requirements := make([]any, 0, len(input.Requirements))
	for _, requirement := range input.Requirements {
		requirements = append(requirements, map[string]any{
			"claimLevel":    requirement.ClaimLevel,
			"nonClaims":     admit.StringSliceToAny(requirement.NonClaims),
			"ownerId":       requirement.OwnerID,
			"proofState":    requirement.ProofState,
			"requirementId": requirement.RequirementID,
			"specPath":      requirement.SpecPath,
		})
	}
	bindings := make([]any, 0, len(input.Bindings))
	for _, binding := range input.Bindings {
		bindings = append(bindings, map[string]any{
			"commandIds":         admit.StringSliceToAny(binding.CommandIDs),
			"environmentClasses": admit.StringSliceToAny(binding.EnvironmentClasses),
			"requirementId":      binding.RequirementID,
			"scenarioId":         binding.ScenarioID,
			"witnessId":          binding.WitnessID,
			"witnessKind":        binding.WitnessKind,
			"witnessPath":        binding.WitnessPath,
		})
	}
	witnessCommands := make([]any, 0, len(input.WitnessCommands))
	for _, command := range input.WitnessCommands {
		witnessCommands = append(witnessCommands, map[string]any{
			"command":            command.Command,
			"commandId":          command.CommandID,
			"environmentClasses": admit.StringSliceToAny(command.EnvironmentClasses),
		})
	}
	return map[string]any{
		"schemaVersion":   json.Number("1"),
		"bindingId":       input.BindingID,
		"requirements":    requirements,
		"bindings":        bindings,
		"witnessCommands": witnessCommands,
		"selection": map[string]any{
			"changedPaths":   admit.StringSliceToAny(input.Selection.ChangedPaths),
			"ownerIds":       admit.StringSliceToAny(input.Selection.OwnerIDs),
			"requirementIds": admit.StringSliceToAny(input.Selection.RequirementIDs),
		},
		"nonClaims": admit.StringSliceToAny(callerOwnedNonClaims(input.NonClaims)),
	}
}

func callerOwnedNonClaims(values []string) []string {
	defaults := map[string]struct{}{}
	for _, value := range defaultNonClaims {
		defaults[value] = struct{}{}
	}
	out := []string{}
	for _, value := range values {
		if _, ok := defaults[value]; ok {
			continue
		}
		out = append(out, value)
	}
	return out
}

func BuildWitnessPlanInput(raw any, vocabularyRaw any) (map[string]any, error) {
	failures := []string{}
	input, err := admitInput(raw, &failures)
	if err != nil {
		return nil, err
	}
	failures = append(failures, semanticFailures(input)...)
	failures = sortedUnique(failures)
	if len(failures) > 0 {
		return nil, fmt.Errorf("cannot project witness-plan input from failed requirement proof bindings: %s", strings.Join(failures, "; "))
	}
	vocabulary, err := witnesscommand.AdmitVocabulary(vocabularyRaw)
	if err != nil {
		return nil, err
	}
	commands, err := witnessCommandsToPlanInput(input.WitnessCommands, vocabulary)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"commands":   commands,
		"vocabulary": vocabularyRaw,
	}, nil
}

func witnessCommandsToPlanInput(commands []WitnessCommand, vocabulary witnesscommand.Vocabulary) ([]any, error) {
	out := make([]any, 0, len(commands))
	for _, command := range commands {
		argv, err := displayCommandArgv(command.Command)
		if err != nil {
			return nil, fmt.Errorf("witness command %s cannot be projected to argv: %w", command.CommandID, err)
		}
		if len(vocabulary.ParallelGroups) != 1 {
			return nil, fmt.Errorf("binding-derived witness-plan projection requires exactly one parallelGroup; provide an explicit witness-plan command catalog")
		}
		policy, err := conservativeWitnessPolicy(command.EnvironmentClasses, vocabulary)
		if err != nil {
			return nil, fmt.Errorf("witness command %s policy projection failed: %w", command.CommandID, err)
		}
		out = append(out, map[string]any{
			"schemaVersion":   json.Number("1"),
			"id":              command.CommandID,
			"cwd":             ".",
			"argv":            admit.StringSliceToAny(argv),
			"timeoutMs":       json.Number(fmt.Sprintf("%d", vocabulary.MaxTimeoutMs)),
			"networkPolicy":   policy.network,
			"credentialClass": policy.credential,
			"cachePolicy":     policy.cache,
			"parallelGroup":   vocabulary.ParallelGroups[0],
			"environment": map[string]any{
				"inherit":   "none",
				"allowlist": []any{},
				"classes":   admit.StringSliceToAny(command.EnvironmentClasses),
			},
			"expectedArtifacts": []any{},
			"exitCodePolicy": map[string]any{
				"kind":         "zero",
				"successCodes": []any{json.Number("0")},
			},
		})
	}
	return out, nil
}

type projectedWitnessPolicy struct {
	cache      string
	credential string
	network    string
}

func conservativeWitnessPolicy(environmentClasses []string, vocabulary witnesscommand.Vocabulary) (projectedWitnessPolicy, error) {
	byClass := map[string]witnesscommand.EnvironmentClassPolicy{}
	for _, policy := range vocabulary.EnvironmentClassPolicies {
		byClass[policy.EnvironmentClass] = policy
	}
	for _, environmentClass := range environmentClasses {
		policy, ok := byClass[environmentClass]
		if !ok {
			return projectedWitnessPolicy{}, fmt.Errorf("environment class %s must declare a policy", environmentClass)
		}
		if !contains(policy.NetworkPolicies, "none") {
			return projectedWitnessPolicy{}, fmt.Errorf("environment class %s must admit networkPolicy none for binding-derived projection", environmentClass)
		}
		if !contains(policy.CredentialClasses, "none") {
			return projectedWitnessPolicy{}, fmt.Errorf("environment class %s must admit credentialClass none for binding-derived projection", environmentClass)
		}
		if !contains(policy.CachePolicies, "disabled") {
			return projectedWitnessPolicy{}, fmt.Errorf("environment class %s must admit cachePolicy disabled for binding-derived projection", environmentClass)
		}
	}
	return projectedWitnessPolicy{cache: "disabled", credential: "none", network: "none"}, nil
}

func displayCommandArgv(command string) ([]string, error) {
	if _, err := admit.DisplayOnlyCommandText(command, "binding-derived display command"); err != nil {
		return nil, err
	}
	if strings.ContainsAny(command, `'"\\`) {
		return nil, fmt.Errorf("display command contains quoting or escaping; provide an explicit witness-plan command catalog")
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, fmt.Errorf("display command is empty")
	}
	for _, field := range fields {
		if strings.TrimSpace(field) == "" || admit.ContainsSecretLikeValue(field) {
			return nil, fmt.Errorf("display command contains unsafe argv token")
		}
	}
	return fields, nil
}

func admitInput(raw any, failures *[]string) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("requirement proof binding input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bindingId", "bindings", "nonClaims", "requirements", "schemaVersion", "selection", "witnessCommands"}, "requirement proof binding input"); err != nil {
		return Input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Input{}, fmt.Errorf("requirement proof binding input schemaVersion must be 1")
	}
	bindingID, err := admit.RuleID(record["bindingId"], "requirement proof bindingId")
	if err != nil {
		return Input{}, err
	}
	requirements, err := admitRequirements(record["requirements"])
	if err != nil {
		return Input{}, err
	}
	bindings, err := admitBindings(record["bindings"])
	if err != nil {
		return Input{}, err
	}
	witnessCommands, err := admitWitnessCommands(record["witnessCommands"])
	if err != nil {
		return Input{}, err
	}
	collectDuplicateFailures(requirementIDs(requirements), "requirementId", failures)
	collectDuplicateFailures(bindingKeys(bindings), "binding scenario/witness", failures)
	collectDuplicateFailures(commandIDs(witnessCommands), "commandId", failures)
	selection, err := admitSelection(record["selection"])
	if err != nil {
		return Input{}, err
	}
	nonClaimValues, err := array(record["nonClaims"], "nonClaims")
	if err != nil {
		return Input{}, err
	}
	nonClaims, err := sortedTextFromAny(append(anyStrings(defaultNonClaims), nonClaimValues...), "nonClaims")
	if err != nil {
		return Input{}, err
	}
	return Input{
		BindingID:       bindingID,
		Requirements:    requirements,
		Bindings:        bindings,
		WitnessCommands: witnessCommands,
		Selection:       selection,
		NonClaims:       nonClaims,
	}, nil
}

func admitRequirements(raw any) ([]Requirement, error) {
	values, err := array(raw, "requirements")
	if err != nil {
		return nil, err
	}
	requirements := make([]Requirement, 0, len(values))
	for _, item := range values {
		requirement, err := admitRequirement(item)
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, requirement)
	}
	sort.Slice(requirements, func(left, right int) bool {
		return requirements[left].RequirementID < requirements[right].RequirementID
	})
	return requirements, nil
}

func admitRequirement(raw any) (Requirement, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Requirement{}, fmt.Errorf("requirement record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"claimLevel", "nonClaims", "ownerId", "proofState", "requirementId", "specPath"}, "requirement record"); err != nil {
		return Requirement{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "requirementId")
	if err != nil {
		return Requirement{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], "ownerId")
	if err != nil {
		return Requirement{}, err
	}
	specText, err := text(record["specPath"], "specPath")
	if err != nil {
		return Requirement{}, err
	}
	specPath, err := admit.SafeRepoRelativePath(specText, "specPath")
	if err != nil {
		return Requirement{}, err
	}
	claimLevel, err := enum(record["claimLevel"], claimLevels, "claimLevel")
	if err != nil {
		return Requirement{}, err
	}
	proofState, err := enum(record["proofState"], proofStates, "proofState")
	if err != nil {
		return Requirement{}, err
	}
	nonClaimValues, err := array(record["nonClaims"], "requirement nonClaims")
	if err != nil {
		return Requirement{}, err
	}
	nonClaims, err := sortedTextFromAny(nonClaimValues, "requirement nonClaims")
	if err != nil {
		return Requirement{}, err
	}
	return Requirement{
		RequirementID: requirementID,
		OwnerID:       ownerID,
		SpecPath:      specPath,
		ClaimLevel:    claimLevel,
		ProofState:    proofState,
		NonClaims:     nonClaims,
	}, nil
}

func admitBindings(raw any) ([]Binding, error) {
	values, err := array(raw, "bindings")
	if err != nil {
		return nil, err
	}
	bindings := make([]Binding, 0, len(values))
	for _, item := range values {
		binding, err := admitBinding(item)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(left, right int) bool {
		return bindingSortKey(bindings[left]) < bindingSortKey(bindings[right])
	})
	return bindings, nil
}

func admitBinding(raw any) (Binding, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Binding{}, fmt.Errorf("proof binding record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandIds", "environmentClasses", "requirementId", "scenarioId", "witnessId", "witnessKind", "witnessPath"}, "proof binding record"); err != nil {
		return Binding{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "binding requirementId")
	if err != nil {
		return Binding{}, err
	}
	scenarioID, err := admit.RuleID(record["scenarioId"], "scenarioId")
	if err != nil {
		return Binding{}, err
	}
	witnessID, err := admit.RuleID(record["witnessId"], "witnessId")
	if err != nil {
		return Binding{}, err
	}
	witnessKind, err := enum(record["witnessKind"], witnessKinds, "witnessKind")
	if err != nil {
		return Binding{}, err
	}
	witnessText, err := text(record["witnessPath"], "witnessPath")
	if err != nil {
		return Binding{}, err
	}
	witnessPath, err := admit.SafeRepoRelativePath(witnessText, "witnessPath")
	if err != nil {
		return Binding{}, err
	}
	commandIDs, err := sortedRuleIDs(record["commandIds"], "commandIds")
	if err != nil {
		return Binding{}, err
	}
	environmentClasses, err := sortedRuleIDs(record["environmentClasses"], "environmentClasses")
	if err != nil {
		return Binding{}, err
	}
	return Binding{
		RequirementID:      requirementID,
		ScenarioID:         scenarioID,
		WitnessID:          witnessID,
		WitnessKind:        witnessKind,
		WitnessPath:        witnessPath,
		CommandIDs:         commandIDs,
		EnvironmentClasses: environmentClasses,
	}, nil
}

func admitWitnessCommands(raw any) ([]WitnessCommand, error) {
	values, err := array(raw, "witnessCommands")
	if err != nil {
		return nil, err
	}
	commands := make([]WitnessCommand, 0, len(values))
	for _, item := range values {
		command, err := admitWitnessCommand(item)
		if err != nil {
			return nil, err
		}
		commands = append(commands, command)
	}
	sort.Slice(commands, func(left, right int) bool {
		return commands[left].CommandID < commands[right].CommandID
	})
	return commands, nil
}

func admitWitnessCommand(raw any) (WitnessCommand, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return WitnessCommand{}, fmt.Errorf("witness command record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"command", "commandId", "environmentClass", "environmentClasses"}, "witness command record"); err != nil {
		return WitnessCommand{}, err
	}
	commandID, err := admit.RuleID(record["commandId"], "commandId")
	if err != nil {
		return WitnessCommand{}, err
	}
	command, err := admit.DisplayOnlyCommandText(record["command"], "command")
	if err != nil {
		return WitnessCommand{}, err
	}
	_, hasEnvironmentClass := record["environmentClass"]
	_, hasEnvironmentClasses := record["environmentClasses"]
	if hasEnvironmentClass && hasEnvironmentClasses {
		return WitnessCommand{}, fmt.Errorf("witness command must use either environmentClass or environmentClasses, not both")
	}
	var environmentClasses []string
	if hasEnvironmentClasses {
		environmentClasses, err = sortedRuleIDs(record["environmentClasses"], "environmentClasses")
		if err != nil {
			return WitnessCommand{}, err
		}
		if len(environmentClasses) == 0 {
			return WitnessCommand{}, fmt.Errorf("environmentClasses must be non-empty")
		}
	} else {
		environmentClass, err := admit.RuleID(record["environmentClass"], "environmentClass")
		if err != nil {
			return WitnessCommand{}, err
		}
		environmentClasses = []string{environmentClass}
	}
	return WitnessCommand{CommandID: commandID, Command: command, EnvironmentClasses: environmentClasses}, nil
}

func admitSelection(raw any) (Selection, error) {
	if raw == nil {
		return Selection{ChangedPaths: []string{}, OwnerIDs: []string{}, RequirementIDs: []string{}}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return Selection{}, fmt.Errorf("selection must be an object")
	}
	if err := admit.KnownKeys(record, []string{"changedPaths", "ownerIds", "requirementIds"}, "selection"); err != nil {
		return Selection{}, err
	}
	changedPaths, err := sortedPaths(valueOrEmptyArray(record["changedPaths"]), "selection changedPaths")
	if err != nil {
		return Selection{}, err
	}
	ownerIDs, err := sortedRuleIDs(valueOrEmptyArray(record["ownerIds"]), "selection ownerIds")
	if err != nil {
		return Selection{}, err
	}
	requirementIDs, err := sortedRuleIDs(valueOrEmptyArray(record["requirementIds"]), "selection requirementIds")
	if err != nil {
		return Selection{}, err
	}
	return Selection{ChangedPaths: changedPaths, OwnerIDs: ownerIDs, RequirementIDs: requirementIDs}, nil
}

func semanticFailures(input Input) []string {
	failures := []string{}
	requirementIDs := map[string]struct{}{}
	for _, requirement := range input.Requirements {
		requirementIDs[requirement.RequirementID] = struct{}{}
	}
	commandIDs := map[string]struct{}{}
	commandEnvironmentsByID := map[string][]string{}
	for _, command := range input.WitnessCommands {
		commandIDs[command.CommandID] = struct{}{}
		commandEnvironmentsByID[command.CommandID] = command.EnvironmentClasses
	}
	referencedCommandIDs := map[string]struct{}{}
	bindingsByRequirement := map[string][]Binding{}
	for _, binding := range input.Bindings {
		if _, ok := requirementIDs[binding.RequirementID]; !ok {
			failures = append(failures, fmt.Sprintf("binding references unknown requirementId=%s", binding.RequirementID))
		}
		if len(binding.CommandIDs) == 0 {
			failures = append(failures, fmt.Sprintf("binding %s must cite at least one commandId", binding.ScenarioID))
		}
		for _, commandID := range binding.CommandIDs {
			referencedCommandIDs[commandID] = struct{}{}
			if _, ok := commandIDs[commandID]; !ok {
				failures = append(failures, fmt.Sprintf("binding %s references unknown commandId=%s", binding.ScenarioID, commandID))
				continue
			}
			for _, environment := range commandEnvironmentsByID[commandID] {
				if !contains(binding.EnvironmentClasses, environment) {
					failures = append(failures, fmt.Sprintf("binding %s omits command environmentClass=%s", binding.ScenarioID, environment))
				}
			}
		}
		bindingsByRequirement[binding.RequirementID] = append(bindingsByRequirement[binding.RequirementID], binding)
	}
	for _, commandID := range mapKeys(commandIDs) {
		if _, ok := referencedCommandIDs[commandID]; !ok {
			failures = append(failures, fmt.Sprintf("witness command is not referenced by any binding commandId: %s", commandID))
		}
	}
	for _, requirement := range input.Requirements {
		bindings := bindingsByRequirement[requirement.RequirementID]
		if requirement.ProofState == "witness_backed" && len(bindings) == 0 {
			failures = append(failures, fmt.Sprintf("witness_backed requirement has no binding: %s", requirement.RequirementID))
		}
		if requirement.ProofState != "witness_backed" && len(bindings) > 0 {
			failures = append(failures, fmt.Sprintf("%s requirement must not have bindings: %s", requirement.ProofState, requirement.RequirementID))
		}
		if requirement.ClaimLevel == "blocking" && requirement.ProofState == "not_bound" {
			failures = append(failures, fmt.Sprintf("blocking requirement is not bound: %s", requirement.RequirementID))
		}
	}
	for _, requirementID := range input.Selection.RequirementIDs {
		if _, ok := requirementIDs[requirementID]; !ok {
			failures = append(failures, fmt.Sprintf("selection references unknown requirementId=%s", requirementID))
		}
	}
	return sortedUnique(failures)
}

func buildGraph(input Input) map[string]any {
	bindingsByRequirement := map[string][]Binding{}
	for _, binding := range input.Bindings {
		bindingsByRequirement[binding.RequirementID] = append(bindingsByRequirement[binding.RequirementID], binding)
	}
	requirements := make([]any, 0, len(input.Requirements))
	for _, requirement := range input.Requirements {
		scenarios := make([]any, 0, len(bindingsByRequirement[requirement.RequirementID]))
		for _, binding := range bindingsByRequirement[requirement.RequirementID] {
			scenarios = append(scenarios, map[string]any{
				"commandIds":         admit.StringSliceToAny(binding.CommandIDs),
				"environmentClasses": admit.StringSliceToAny(binding.EnvironmentClasses),
				"scenarioId":         binding.ScenarioID,
				"witnessId":          binding.WitnessID,
				"witnessKind":        binding.WitnessKind,
				"witnessPath":        binding.WitnessPath,
			})
		}
		requirements = append(requirements, map[string]any{
			"claimLevel":    requirement.ClaimLevel,
			"nonClaims":     admit.StringSliceToAny(requirement.NonClaims),
			"ownerId":       requirement.OwnerID,
			"proofState":    requirement.ProofState,
			"requirementId": requirement.RequirementID,
			"scenarios":     scenarios,
			"specPath":      requirement.SpecPath,
		})
	}
	return map[string]any{
		"bindingCount":     len(input.Bindings),
		"bindingId":        input.BindingID,
		"commandCount":     len(input.WitnessCommands),
		"graphKind":        "proofkit.requirement-evidence-graph",
		"nonClaims":        admit.StringSliceToAny(input.NonClaims),
		"requirementCount": len(input.Requirements),
		"requirements":     requirements,
		"schemaVersion":    1,
	}
}

func buildSlice(input Input, graph map[string]any) map[string]any {
	requirements := graph["requirements"].([]any)
	selected := []any{}
	for index, requirementValue := range requirements {
		requirement := input.Requirements[index]
		if isSelectedRequirement(requirement, input.Bindings, input.Selection) {
			selected = append(selected, requirementValue)
		}
	}
	commandSet := map[string]struct{}{}
	for _, selectedValue := range selected {
		selectedRequirement := selectedValue.(map[string]any)
		for _, scenarioValue := range selectedRequirement["scenarios"].([]any) {
			scenario := scenarioValue.(map[string]any)
			for _, commandID := range scenario["commandIds"].([]any) {
				commandSet[commandID.(string)] = struct{}{}
			}
		}
	}
	selectedCommandIDs := make([]string, 0, len(commandSet))
	for commandID := range commandSet {
		selectedCommandIDs = append(selectedCommandIDs, commandID)
	}
	sort.Strings(selectedCommandIDs)
	return map[string]any{
		"bindingId":                input.BindingID,
		"nonClaims":                admit.StringSliceToAny(input.NonClaims),
		"omittedRequirementCount":  len(input.Requirements) - len(selected),
		"schemaVersion":            1,
		"selectedCommandIds":       admit.StringSliceToAny(selectedCommandIDs),
		"selectedRequirementCount": len(selected),
		"selectedRequirements":     selected,
		"selection": map[string]any{
			"changedPaths":   admit.StringSliceToAny(input.Selection.ChangedPaths),
			"ownerIds":       admit.StringSliceToAny(input.Selection.OwnerIDs),
			"requirementIds": admit.StringSliceToAny(input.Selection.RequirementIDs),
		},
		"sliceKind": "proofkit.requirement-proof-slice",
	}
}

func isSelectedRequirement(requirement Requirement, bindings []Binding, selection Selection) bool {
	if len(selection.ChangedPaths) == 0 && len(selection.OwnerIDs) == 0 && len(selection.RequirementIDs) == 0 {
		return true
	}
	if contains(selection.RequirementIDs, requirement.RequirementID) || contains(selection.OwnerIDs, requirement.OwnerID) {
		return true
	}
	for _, changedPath := range selection.ChangedPaths {
		if changedPath == requirement.SpecPath {
			return true
		}
		for _, binding := range bindings {
			if binding.RequirementID == requirement.RequirementID && changedPath == binding.WitnessPath {
				return true
			}
		}
	}
	return false
}

func buildReport(input Input, graph map[string]any, slice map[string]any, failures []string) report.Record {
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.requirement-proof-bindings",
		ReportID:      input.BindingID,
		State:         state,
		Summary: map[string]any{
			"bindingCount":             graph["bindingCount"],
			"commandCount":             graph["commandCount"],
			"omittedRequirementCount":  slice["omittedRequirementCount"],
			"requirementCount":         graph["requirementCount"],
			"selectedRequirementCount": slice["selectedRequirementCount"],
		},
		Diagnostics: []report.Diagnostic{
			{Key: "selection", Value: slice["selection"]},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.requirement-proof-bindings.accepted",
			Status:      "passed",
			Message:     "requirement proof bindings are deterministic and reference-complete",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.requirement-proof-bindings.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func failureMessages(record report.Record) string {
	messages := []string{}
	for _, result := range record.RuleResults {
		if result.Status == "failed" {
			messages = append(messages, result.Message)
		}
	}
	return strings.Join(messages, "; ")
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	values, err := array(raw, context)
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
	if err := assertSortedUnique(result, context); err != nil {
		return nil, err
	}
	return result, nil
}

func sortedPaths(raw any, context string) ([]string, error) {
	values, err := array(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		pathText, err := text(value, context)
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, context)
		if err != nil {
			return nil, err
		}
		result = append(result, pathValue)
	}
	sort.Strings(result)
	if err := assertSortedUnique(result, context); err != nil {
		return nil, err
	}
	return result, nil
}

func sortedTextFromAny(raw []any, context string) ([]string, error) {
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		textValue, err := text(value, context)
		if err != nil {
			return nil, err
		}
		values = append(values, strings.TrimSpace(textValue))
	}
	sort.Strings(values)
	if err := assertSortedUnique(values, context); err != nil {
		return nil, err
	}
	return values, nil
}

func array(raw any, context string) ([]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	return values, nil
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func enum(raw any, values map[string]struct{}, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, enumList(values))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, enumList(values))
	}
	return value, nil
}

func enumList(values map[string]struct{}) string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return strings.Join(result, ", ")
}

func assertSortedUnique(values []string, context string) error {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func collectDuplicateFailures(values []string, context string, failures *[]string) {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			*failures = append(*failures, fmt.Sprintf("duplicate %s: %s", context, value))
		}
		seen[value] = struct{}{}
	}
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := []string{}
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
		}
		previous = value
	}
	return result
}

func requirementIDs(requirements []Requirement) []string {
	result := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		result = append(result, requirement.RequirementID)
	}
	return result
}

func bindingKeys(bindings []Binding) []string {
	result := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, bindingSortKey(binding))
	}
	return result
}

func commandIDs(commands []WitnessCommand) []string {
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		result = append(result, command.CommandID)
	}
	return result
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func bindingSortKey(binding Binding) string {
	return binding.RequirementID + "\x00" + binding.ScenarioID + "\x00" + binding.WitnessID
}

func anyStrings(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func valueOrEmptyArray(value any) any {
	if value == nil {
		return []any{}
	}
	return value
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
