package compactproofcontract

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	AuthorityState       = "canonical"
	ContractKind         = "requirement_proof_binding"
	NormalizationProfile = "proofkit.compact.v1"
)

var SurfaceColumns = []string{
	"surface_id",
	"required_environment_classes",
	"preconditioned_environment_classes",
}

var BindingColumns = []string{
	"requirement_id",
	"surface_id",
	"scenario_id",
	"invariant_role",
	"owned_invariant",
	"proof_contract_state",
	"blocking_status",
	"required_environment_classes",
	"positive_witness",
	"falsification_witness",
	"verify_commands",
	"mutation_resistance_state",
}

var WitnessColumns = []string{
	"selector",
	"environment_classes",
	"verify_commands",
	"resolution_order_index",
}

type Contract struct {
	ContractID string
	NonClaims  []string
	Surfaces   []Surface
	Bindings   []Binding
}

type Surface struct {
	SurfaceID                        string
	RequiredEnvironmentClasses       []string
	PreconditionedEnvironmentClasses []string
}

type Witness struct {
	Selector             string
	EnvironmentClasses   []string
	VerifyCommands       []string
	ResolutionOrderIndex int
}

type Binding struct {
	RequirementID              string
	SurfaceID                  string
	ScenarioID                 string
	InvariantRole              string
	OwnedInvariant             string
	ProofContractState         string
	BlockingStatus             string
	RequiredEnvironmentClasses []string
	PositiveWitness            Witness
	FalsificationWitness       Witness
	VerifyCommands             []string
	MutationResistanceState    string
}

type ResolverOptions struct {
	LocalEnvironmentClasses []string
}

type FalsificationRoute struct {
	FalsificationSelector string
	OwnedInvariant        string
	RequirementID         string
	SurfaceID             string
	VerifyCommands        []string
}

func Admit(raw any) (Contract, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Contract{}, fmt.Errorf("compact requirement proof contract must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority_state", "binding_columns", "bindings", "contract_id", "contract_kind", "non_claims", "normalization_profile", "schema_version", "surface_columns", "surfaces", "witness_columns"}, "compact requirement proof contract"); err != nil {
		return Contract{}, err
	}
	if !admit.JSONNumberEquals(record["schema_version"], 1) {
		return Contract{}, fmt.Errorf("compact requirement proof contract schema_version must be 1")
	}
	if err := requireLiteral(record["authority_state"], AuthorityState, "compact requirement proof authority_state"); err != nil {
		return Contract{}, err
	}
	if err := requireLiteral(record["contract_kind"], ContractKind, "compact requirement proof contract_kind"); err != nil {
		return Contract{}, err
	}
	if err := requireLiteral(record["normalization_profile"], NormalizationProfile, "compact requirement proof normalization_profile"); err != nil {
		return Contract{}, err
	}
	contractID, err := text(record["contract_id"], "compact requirement proof contract_id")
	if err != nil {
		return Contract{}, err
	}
	surfaceColumns, err := columnIndex(record["surface_columns"], SurfaceColumns, "compact requirement proof surface_columns")
	if err != nil {
		return Contract{}, err
	}
	bindingColumns, err := columnIndex(record["binding_columns"], BindingColumns, "compact requirement proof binding_columns")
	if err != nil {
		return Contract{}, err
	}
	witnessColumns, err := columnIndex(record["witness_columns"], WitnessColumns, "compact requirement proof witness_columns")
	if err != nil {
		return Contract{}, err
	}
	nonClaims, err := stringArray(record["non_claims"], "compact requirement proof non_claims")
	if err != nil {
		return Contract{}, err
	}
	surfaces, err := admitSurfaces(record["surfaces"], surfaceColumns)
	if err != nil {
		return Contract{}, err
	}
	bindings, err := admitBindings(record["bindings"], bindingColumns, witnessColumns)
	if err != nil {
		return Contract{}, err
	}
	contract := Contract{ContractID: contractID, NonClaims: nonClaims, Surfaces: surfaces, Bindings: bindings}
	if err := assertReferentialIntegrity(contract); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

func (contract Contract) ResolverProjection(options ResolverOptions) (map[string]any, error) {
	localClasses, err := AdmitLocalEnvironmentClasses(options.LocalEnvironmentClasses)
	if err != nil {
		return nil, err
	}
	requirements := contract.resolverRequirements(localClasses)
	return map[string]any{
		"commands":                 contract.resolverCommands(requirements),
		"conformanceProofContract": contract.ConformanceProjection(),
		"contractId":               contract.ContractID,
		"environmentClasses":       contract.resolverEnvironmentClasses(requirements),
		"localEnvironmentPolicy":   map[string]any{"authority": "caller_provided", "localEnvironmentClasses": stringSliceToAny(localClasses)},
		"nonClaims":                resolverNonClaims(contract.NonClaims),
		"projectionKind":           "proofkit.requirement-proof-resolver",
		"requirements":             requirements,
		"scenarios":                resolverScenarios(requirements),
		"schemaVersion":            1,
		"surfaces":                 resolverSurfaces(contract.Surfaces, requirements),
		"witnessSelectors":         resolverWitnessSelectors(requirements),
	}, nil
}

func AdmitLocalEnvironmentClass(value string) (string, error) {
	if admit.ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("compact requirement proof local environment class must not contain secret-like values")
	}
	return admit.RuleID(value, "compact requirement proof local environment class")
}

func AdmitLocalEnvironmentClasses(values []string) ([]string, error) {
	admitted := make([]string, 0, len(values))
	for _, value := range values {
		class, err := AdmitLocalEnvironmentClass(value)
		if err != nil {
			return nil, err
		}
		admitted = append(admitted, class)
	}
	sort.Strings(admitted)
	if err := assertSortedUnique(admitted, "compact requirement proof resolver localEnvironmentClasses"); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (contract Contract) FalsificationRoutes() []FalsificationRoute {
	routes := make([]FalsificationRoute, 0, len(contract.Bindings))
	for _, binding := range contract.Bindings {
		routes = append(routes, FalsificationRoute{
			FalsificationSelector: binding.FalsificationWitness.Selector,
			OwnedInvariant:        binding.OwnedInvariant,
			RequirementID:         binding.RequirementID,
			SurfaceID:             binding.SurfaceID,
			VerifyCommands:        append([]string{}, binding.FalsificationWitness.VerifyCommands...),
		})
	}
	return routes
}

func (contract Contract) ConformanceProjection() map[string]any {
	bindings := make([]any, 0, len(contract.Bindings))
	for _, binding := range contract.Bindings {
		bindings = append(bindings, map[string]any{
			"blockingStatus":             binding.BlockingStatus,
			"proofContractState":         binding.ProofContractState,
			"requiredEnvironmentClasses": stringSliceToAny(binding.RequiredEnvironmentClasses),
			"requirementId":              binding.RequirementID,
			"scenarioId":                 binding.ScenarioID,
			"surfaceId":                  binding.SurfaceID,
			"verifyCommands":             stringSliceToAny(binding.VerifyCommands),
			"witnessRefs": []any{
				map[string]any{"role": "falsification", "selector": binding.FalsificationWitness.Selector},
				map[string]any{"role": "positive", "selector": binding.PositiveWitness.Selector},
			},
		})
	}
	surfaces := make([]any, 0, len(contract.Surfaces))
	for _, surface := range contract.Surfaces {
		surfaces = append(surfaces, map[string]any{
			"preconditionedEnvironmentClasses": stringSliceToAny(surface.PreconditionedEnvironmentClasses),
			"requiredEnvironmentClasses":       stringSliceToAny(surface.RequiredEnvironmentClasses),
			"surfaceId":                        surface.SurfaceID,
		})
	}
	return map[string]any{
		"bindings":   bindings,
		"contractId": contract.ContractID,
		"surfaces":   surfaces,
	}
}

func admitSurfaces(raw any, columns map[string]int) ([]Surface, error) {
	values, err := array(raw, "compact requirement proof surfaces")
	if err != nil {
		return nil, err
	}
	surfaces := make([]Surface, 0, len(values))
	for index, value := range values {
		context := fmt.Sprintf("compact requirement proof surface row #%d", index+1)
		row, err := compactRow(value, len(columns), context)
		if err != nil {
			return nil, err
		}
		surfaceID, err := admit.RuleID(column(row, columns, "surface_id"), context+" surface_id")
		if err != nil {
			return nil, err
		}
		required, err := ruleIDArray(column(row, columns, "required_environment_classes"), context+" required_environment_classes")
		if err != nil {
			return nil, err
		}
		preconditioned, err := ruleIDArray(column(row, columns, "preconditioned_environment_classes"), context+" preconditioned_environment_classes")
		if err != nil {
			return nil, err
		}
		surfaces = append(surfaces, Surface{SurfaceID: surfaceID, RequiredEnvironmentClasses: required, PreconditionedEnvironmentClasses: preconditioned})
	}
	sort.Slice(surfaces, func(left, right int) bool { return surfaces[left].SurfaceID < surfaces[right].SurfaceID })
	return surfaces, nil
}

func admitBindings(raw any, bindingColumns map[string]int, witnessColumns map[string]int) ([]Binding, error) {
	values, err := array(raw, "compact requirement proof bindings")
	if err != nil {
		return nil, err
	}
	bindings := make([]Binding, 0, len(values))
	for index, value := range values {
		context := fmt.Sprintf("compact requirement proof binding row #%d", index+1)
		row, err := compactRow(value, len(bindingColumns), context)
		if err != nil {
			return nil, err
		}
		binding, err := admitBinding(row, bindingColumns, witnessColumns, context)
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

func admitBinding(row []any, bindingColumns map[string]int, witnessColumns map[string]int, context string) (Binding, error) {
	requirementID, err := admit.RuleID(column(row, bindingColumns, "requirement_id"), context+" requirement_id")
	if err != nil {
		return Binding{}, err
	}
	surfaceID, err := admit.RuleID(column(row, bindingColumns, "surface_id"), context+" surface_id")
	if err != nil {
		return Binding{}, err
	}
	scenarioID, err := text(column(row, bindingColumns, "scenario_id"), context+" scenario_id")
	if err != nil {
		return Binding{}, err
	}
	scenarioID, err = admitScopedScenarioID(scenarioID, surfaceID, context+" scenario_id")
	if err != nil {
		return Binding{}, err
	}
	invariantRole, err := admit.RuleID(column(row, bindingColumns, "invariant_role"), context+" invariant_role")
	if err != nil {
		return Binding{}, err
	}
	ownedInvariant, err := admit.RuleID(column(row, bindingColumns, "owned_invariant"), context+" owned_invariant")
	if err != nil {
		return Binding{}, err
	}
	proofContractState, err := admit.RuleID(column(row, bindingColumns, "proof_contract_state"), context+" proof_contract_state")
	if err != nil {
		return Binding{}, err
	}
	blockingStatus, err := admit.RuleID(column(row, bindingColumns, "blocking_status"), context+" blocking_status")
	if err != nil {
		return Binding{}, err
	}
	required, err := ruleIDArray(column(row, bindingColumns, "required_environment_classes"), context+" required_environment_classes")
	if err != nil {
		return Binding{}, err
	}
	positive, err := admitWitness(column(row, bindingColumns, "positive_witness"), context+" positive_witness", witnessColumns)
	if err != nil {
		return Binding{}, err
	}
	falsification, err := admitWitness(column(row, bindingColumns, "falsification_witness"), context+" falsification_witness", witnessColumns)
	if err != nil {
		return Binding{}, err
	}
	verifyCommands, err := displayCommandArray(column(row, bindingColumns, "verify_commands"), context+" verify_commands")
	if err != nil {
		return Binding{}, err
	}
	mutationResistanceState, err := admit.RuleID(column(row, bindingColumns, "mutation_resistance_state"), context+" mutation_resistance_state")
	if err != nil {
		return Binding{}, err
	}
	return Binding{RequirementID: requirementID, SurfaceID: surfaceID, ScenarioID: scenarioID, InvariantRole: invariantRole, OwnedInvariant: ownedInvariant, ProofContractState: proofContractState, BlockingStatus: blockingStatus, RequiredEnvironmentClasses: required, PositiveWitness: positive, FalsificationWitness: falsification, VerifyCommands: verifyCommands, MutationResistanceState: mutationResistanceState}, nil
}

func admitWitness(raw any, context string, columns map[string]int) (Witness, error) {
	row, err := compactRow(raw, len(columns), context)
	if err != nil {
		return Witness{}, err
	}
	selector, err := text(column(row, columns, "selector"), context+" selector")
	if err != nil {
		return Witness{}, err
	}
	selector, err = admitWitnessSelector(selector, context+" selector")
	if err != nil {
		return Witness{}, err
	}
	environmentClasses, err := ruleIDArray(column(row, columns, "environment_classes"), context+" environment_classes")
	if err != nil {
		return Witness{}, err
	}
	verifyCommands, err := displayCommandArray(column(row, columns, "verify_commands"), context+" verify_commands")
	if err != nil {
		return Witness{}, err
	}
	order, err := nonNegativeInteger(column(row, columns, "resolution_order_index"), context+" resolution_order_index")
	if err != nil {
		return Witness{}, err
	}
	return Witness{Selector: selector, EnvironmentClasses: environmentClasses, VerifyCommands: verifyCommands, ResolutionOrderIndex: order}, nil
}

func (contract Contract) resolverRequirements(localClasses []string) []any {
	surfaceByID := map[string]Surface{}
	for _, surface := range contract.Surfaces {
		surfaceByID[surface.SurfaceID] = surface
	}
	requirements := make([]any, 0, len(contract.Bindings))
	for _, binding := range contract.Bindings {
		surface := surfaceByID[binding.SurfaceID]
		requirements = append(requirements, map[string]any{
			"blockingStatus": binding.BlockingStatus,
			"invariantRole":  binding.InvariantRole,
			"mutationResistanceContext": map[string]any{
				"checkedWitnessSelectorCount": 2,
				"findingCount":                mutationFindingCount(binding.MutationResistanceState),
				"mutationResistanceState":     binding.MutationResistanceState,
			},
			"ownedInvariant":             binding.OwnedInvariant,
			"preconditioned":             resolverPreconditioned(surface, binding.RequiredEnvironmentClasses, localClasses),
			"proofContractState":         binding.ProofContractState,
			"requiredEnvironmentClasses": stringSliceToAny(binding.RequiredEnvironmentClasses),
			"requirementId":              binding.RequirementID,
			"scenarioId":                 binding.ScenarioID,
			"surfaceId":                  binding.SurfaceID,
			"testWitnesses": map[string]any{
				"falsification": resolverWitness(binding.FalsificationWitness),
				"positive":      resolverWitness(binding.PositiveWitness),
			},
			"verifyCommands": stringSliceToAny(binding.VerifyCommands),
		})
	}
	return requirements
}

func resolverWitness(witness Witness) map[string]any {
	return map[string]any{
		"environmentClasses":   stringSliceToAny(witness.EnvironmentClasses),
		"resolutionOrderIndex": witness.ResolutionOrderIndex,
		"selector":             witness.Selector,
		"verifyCommandRefs":    stringSliceToAny(witness.VerifyCommands),
	}
}

func resolverPreconditioned(surface Surface, required []string, localClasses []string) bool {
	if len(surface.PreconditionedEnvironmentClasses) > 0 {
		return true
	}
	if len(required) == 0 {
		return false
	}
	local := map[string]struct{}{}
	for _, class := range localClasses {
		local[class] = struct{}{}
	}
	for _, class := range required {
		if _, ok := local[class]; !ok {
			return true
		}
	}
	return false
}

func mutationFindingCount(state string) int {
	if state == "no_known_advisory_gap" {
		return 0
	}
	return 1
}

func resolverSurfaces(surfaces []Surface, requirements []any) []any {
	result := make([]any, 0, len(surfaces))
	for _, surface := range surfaces {
		requirementIDs := []string{}
		for _, requirementValue := range requirements {
			requirement := requirementValue.(map[string]any)
			if requirement["surfaceId"] == surface.SurfaceID {
				requirementIDs = append(requirementIDs, requirement["requirementId"].(string))
			}
		}
		sort.Strings(requirementIDs)
		result = append(result, map[string]any{
			"requirementIds": stringSliceToAny(requirementIDs),
			"surfaceId":      surface.SurfaceID,
		})
	}
	return result
}

func resolverScenarios(requirements []any) []any {
	result := make([]any, 0, len(requirements))
	for _, requirementValue := range requirements {
		requirement := requirementValue.(map[string]any)
		result = append(result, map[string]any{
			"requirementId": requirement["requirementId"],
			"scenarioId":    requirement["scenarioId"],
		})
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].(map[string]any)["scenarioId"].(string) < result[right].(map[string]any)["scenarioId"].(string)
	})
	return result
}

func resolverWitnessSelectors(requirements []any) []any {
	bySelector := map[string][]map[string]any{}
	for _, requirementValue := range requirements {
		requirement := requirementValue.(map[string]any)
		witnesses := requirement["testWitnesses"].(map[string]any)
		for _, role := range []string{"positive", "falsification"} {
			witness := witnesses[role].(map[string]any)
			selector := witness["selector"].(string)
			bySelector[selector] = append(bySelector[selector], map[string]any{
				"environmentClasses": witness["environmentClasses"],
				"requirementId":      requirement["requirementId"],
				"scenarioId":         requirement["scenarioId"],
				"selector":           selector,
				"surfaceId":          requirement["surfaceId"],
				"verifyCommandRefs":  witness["verifyCommandRefs"],
				"witnessRole":        role,
			})
		}
	}
	selectors := keys(bySelector)
	result := make([]any, 0, len(selectors))
	for _, selector := range selectors {
		matches := bySelector[selector]
		sort.Slice(matches, func(left, right int) bool {
			leftScenario := matches[left]["scenarioId"].(string)
			rightScenario := matches[right]["scenarioId"].(string)
			if leftScenario != rightScenario {
				return leftScenario < rightScenario
			}
			return matches[left]["witnessRole"].(string) < matches[right]["witnessRole"].(string)
		})
		matchValues := make([]any, 0, len(matches))
		for _, match := range matches {
			matchValues = append(matchValues, match)
		}
		result = append(result, map[string]any{
			"matches":  matchValues,
			"selector": selector,
		})
	}
	return result
}

func (contract Contract) resolverCommands(requirements []any) []any {
	type commandFact struct {
		EnvironmentClasses map[string]struct{}
		RequirementIDs     map[string]struct{}
		ScenarioIDs        map[string]struct{}
		SurfaceIDs         map[string]struct{}
		WitnessSelectors   map[string]struct{}
	}
	byCommand := map[string]*commandFact{}
	factFor := func(command string) *commandFact {
		fact := byCommand[command]
		if fact == nil {
			fact = &commandFact{
				EnvironmentClasses: map[string]struct{}{},
				RequirementIDs:     map[string]struct{}{},
				ScenarioIDs:        map[string]struct{}{},
				SurfaceIDs:         map[string]struct{}{},
				WitnessSelectors:   map[string]struct{}{},
			}
			byCommand[command] = fact
		}
		return fact
	}
	for _, requirementValue := range requirements {
		requirement := requirementValue.(map[string]any)
		for _, command := range stringArrayFromAny(requirement["verifyCommands"]) {
			fact := factFor(command)
			add(fact.RequirementIDs, requirement["requirementId"].(string))
			add(fact.ScenarioIDs, requirement["scenarioId"].(string))
			add(fact.SurfaceIDs, requirement["surfaceId"].(string))
			for _, class := range stringArrayFromAny(requirement["requiredEnvironmentClasses"]) {
				add(fact.EnvironmentClasses, class)
			}
		}
		witnesses := requirement["testWitnesses"].(map[string]any)
		for _, role := range []string{"positive", "falsification"} {
			witness := witnesses[role].(map[string]any)
			for _, command := range stringArrayFromAny(witness["verifyCommandRefs"]) {
				fact := factFor(command)
				add(fact.RequirementIDs, requirement["requirementId"].(string))
				add(fact.ScenarioIDs, requirement["scenarioId"].(string))
				add(fact.SurfaceIDs, requirement["surfaceId"].(string))
				add(fact.WitnessSelectors, witness["selector"].(string))
				for _, class := range stringArrayFromAny(witness["environmentClasses"]) {
					add(fact.EnvironmentClasses, class)
				}
			}
		}
	}
	commands := keys(byCommand)
	out := make([]any, 0, len(commands))
	for _, command := range commands {
		fact := byCommand[command]
		out = append(out, map[string]any{
			"environmentClasses": stringSliceToAny(keys(fact.EnvironmentClasses)),
			"requirementIds":     stringSliceToAny(keys(fact.RequirementIDs)),
			"scenarioIds":        stringSliceToAny(keys(fact.ScenarioIDs)),
			"surfaceIds":         stringSliceToAny(keys(fact.SurfaceIDs)),
			"verifyCommandRef":   command,
			"witnessSelectors":   stringSliceToAny(keys(fact.WitnessSelectors)),
		})
	}
	return out
}

func (contract Contract) resolverEnvironmentClasses(requirements []any) []any {
	type environmentFact struct {
		RequirementIDs   map[string]struct{}
		SurfaceIDs       map[string]struct{}
		WitnessSelectors map[string]struct{}
	}
	byClass := map[string]*environmentFact{}
	factFor := func(class string) *environmentFact {
		fact := byClass[class]
		if fact == nil {
			fact = &environmentFact{
				RequirementIDs:   map[string]struct{}{},
				SurfaceIDs:       map[string]struct{}{},
				WitnessSelectors: map[string]struct{}{},
			}
			byClass[class] = fact
		}
		return fact
	}
	for _, surface := range contract.Surfaces {
		for _, class := range append(append([]string{}, surface.RequiredEnvironmentClasses...), surface.PreconditionedEnvironmentClasses...) {
			fact := factFor(class)
			add(fact.SurfaceIDs, surface.SurfaceID)
		}
	}
	for _, requirementValue := range requirements {
		requirement := requirementValue.(map[string]any)
		for _, class := range stringArrayFromAny(requirement["requiredEnvironmentClasses"]) {
			fact := factFor(class)
			add(fact.RequirementIDs, requirement["requirementId"].(string))
			add(fact.SurfaceIDs, requirement["surfaceId"].(string))
		}
		witnesses := requirement["testWitnesses"].(map[string]any)
		for _, role := range []string{"positive", "falsification"} {
			witness := witnesses[role].(map[string]any)
			for _, class := range stringArrayFromAny(witness["environmentClasses"]) {
				fact := factFor(class)
				add(fact.RequirementIDs, requirement["requirementId"].(string))
				add(fact.SurfaceIDs, requirement["surfaceId"].(string))
				add(fact.WitnessSelectors, witness["selector"].(string))
			}
		}
	}
	classes := keys(byClass)
	out := make([]any, 0, len(classes))
	for _, class := range classes {
		fact := byClass[class]
		out = append(out, map[string]any{
			"environmentClass": class,
			"requirementIds":   stringSliceToAny(keys(fact.RequirementIDs)),
			"surfaceIds":       stringSliceToAny(keys(fact.SurfaceIDs)),
			"witnessSelectors": stringSliceToAny(keys(fact.WitnessSelectors)),
		})
	}
	return out
}

func resolverNonClaims(nonClaims []string) []any {
	merged := append([]string{}, nonClaims...)
	merged = append(merged,
		"Requirement proof resolver projections are lookup-only and do not execute native witnesses.",
		"Consumers own local environment-class policy supplied to preconditioned projection.",
		"Consumers own proof freshness, command pass evidence, rollout approval, and production readiness.",
	)
	return stringSliceToAny(sortedUnique(merged))
}

func admitScopedScenarioID(value string, surfaceID string, context string) (string, error) {
	parts := strings.Split(value, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("%s must use surface_id::stable_anchor scenario identity", context)
	}
	scenarioSurfaceID, err := admit.RuleID(parts[0], context+" surface_id")
	if err != nil {
		return "", err
	}
	if scenarioSurfaceID != surfaceID {
		return "", fmt.Errorf("%s must be scoped under surface_id %s", context, surfaceID)
	}
	anchor, err := admit.RuleID(parts[1], context+" anchor")
	if err != nil {
		return "", err
	}
	return scenarioSurfaceID + "::" + anchor, nil
}

func admitWitnessSelector(value string, context string) (string, error) {
	parts := strings.Split(value, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("%s must use repo/path::stable_anchor selector identity", context)
	}
	sourcePath, err := admit.SafeRepoRelativePath(parts[0], context+" source path")
	if err != nil {
		return "", err
	}
	anchor, err := admit.RuleID(parts[1], context+" anchor")
	if err != nil {
		return "", err
	}
	return sourcePath + "::" + anchor, nil
}

func columnIndex(raw any, required []string, context string) (map[string]int, error) {
	columns, err := orderedStringArray(raw, context)
	if err != nil {
		return nil, err
	}
	if err := assertUniqueStrings(columns, context); err != nil {
		return nil, err
	}
	requiredSet := map[string]struct{}{}
	for _, column := range required {
		requiredSet[column] = struct{}{}
	}
	result := map[string]int{}
	unknown := []string{}
	for index, column := range columns {
		if _, ok := requiredSet[column]; !ok {
			unknown = append(unknown, column)
		}
		result[column] = index
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%s contains unknown projection column(s): %s", context, strings.Join(sortedUnique(unknown), ", "))
	}
	missing := []string{}
	for _, column := range required {
		if _, ok := result[column]; !ok {
			missing = append(missing, column)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s missing required projection column(s): %s", context, strings.Join(missing, ", "))
	}
	if len(columns) != len(required) {
		return nil, fmt.Errorf("%s must contain exactly admitted projection columns", context)
	}
	return result, nil
}

func compactRow(raw any, length int, context string) ([]any, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != length {
		return nil, fmt.Errorf("%s must use the admitted compact row layout", context)
	}
	return values, nil
}

func column(row []any, columns map[string]int, name string) any {
	index, ok := columns[name]
	if !ok || index < 0 || index >= len(row) {
		return nil
	}
	return row[index]
}

func ruleIDArray(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if _, err := admit.RuleID(value, context); err != nil {
			return nil, err
		}
	}
	sort.Strings(values)
	return values, nil
}

func stringArray(raw any, context string) ([]string, error) {
	values, err := orderedStringArray(raw, context)
	if err != nil {
		return nil, err
	}
	sort.Strings(values)
	if err := assertSortedUnique(values, context); err != nil {
		return nil, err
	}
	return values, nil
}

func displayCommandArray(raw any, context string) ([]string, error) {
	values, err := array(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		command, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, command)
	}
	sort.Strings(result)
	if err := assertSortedUnique(result, context); err != nil {
		return nil, err
	}
	return result, nil
}

func orderedStringArray(raw any, context string) ([]string, error) {
	values, err := array(raw, context)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		textValue, err := text(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, textValue)
	}
	return result, nil
}

func nonNegativeInteger(raw any, context string) (int, error) {
	value, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	number, err := value.Int64()
	if err != nil || number < 0 || int64(int(number)) != number {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	return int(number), nil
}

func assertReferentialIntegrity(contract Contract) error {
	surfaceIDs := make([]string, 0, len(contract.Surfaces))
	surfaceSet := map[string]struct{}{}
	for _, surface := range contract.Surfaces {
		surfaceIDs = append(surfaceIDs, surface.SurfaceID)
		surfaceSet[surface.SurfaceID] = struct{}{}
	}
	if err := assertUniqueStrings(surfaceIDs, "compact requirement proof surface_id"); err != nil {
		return err
	}
	bindingIDs := make([]string, 0, len(contract.Bindings))
	for _, binding := range contract.Bindings {
		bindingIDs = append(bindingIDs, bindingSortKey(binding))
		if _, ok := surfaceSet[binding.SurfaceID]; !ok {
			return fmt.Errorf("compact requirement proof binding %s references unknown surfaceId=%s", binding.RequirementID, binding.SurfaceID)
		}
	}
	return assertUniqueStrings(bindingIDs, "compact requirement proof binding identity")
}

func assertUniqueStrings(values []string, context string) error {
	seen := map[string]struct{}{}
	duplicates := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			duplicates = append(duplicates, value)
		}
		seen[value] = struct{}{}
	}
	duplicates = sortedUnique(duplicates)
	if len(duplicates) > 0 {
		return fmt.Errorf("%s must be unique: %s", context, strings.Join(duplicates, ", "))
	}
	return nil
}

func bindingSortKey(binding Binding) string {
	return binding.RequirementID + "\x00" + binding.SurfaceID + "\x00" + binding.ScenarioID
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

func requireLiteral(raw any, expected string, context string) error {
	value, err := text(raw, context)
	if err != nil {
		return err
	}
	if value != expected {
		return fmt.Errorf("%s must be %s", context, expected)
	}
	return nil
}

func assertSortedUnique(values []string, context string) error {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
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

func stringSliceToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func stringArrayFromAny(raw any) []string {
	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func keys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func add(set map[string]struct{}, value string) {
	set[value] = struct{}{}
}
