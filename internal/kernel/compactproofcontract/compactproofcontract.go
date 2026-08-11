package compactproofcontract

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	AuthorityState       = "caller_owned_declaration"
	ContractKind         = "requirement_proof_route_declaration"
	NormalizationProfile = "proofkit.compact.declaration.v2"
	maxJSONSafeInteger   = int64(1<<53 - 1)
)

var surfaceColumns = [...]string{
	"surface_id",
	"required_environment_classes",
	"preconditioned_environment_classes",
}

var bindingColumns = [...]string{
	"requirement_id",
	"surface_id",
	"scenario_id",
	"invariant_role",
	"owned_invariant",
	"blocking_status",
	"required_environment_classes",
	"positive_witness",
	"falsification_witness",
	"verify_commands",
	"declared_mutation_resistance_claim_id",
}

var witnessColumns = [...]string{
	"selector",
	"environment_classes",
	"verify_commands",
	"resolution_order_index",
}

type Contract struct {
	contractID string
	nonClaims  []string
	surfaces   []Surface
	bindings   []Binding
}

type Surface struct {
	surfaceID                        string
	requiredEnvironmentClasses       []string
	preconditionedEnvironmentClasses []string
}

type Witness struct {
	selector             string
	environmentClasses   []string
	verifyCommands       []string
	resolutionOrderIndex int
}

type Binding struct {
	recordID                          string
	requirementID                     string
	surfaceID                         string
	scenarioID                        string
	invariantRole                     string
	ownedInvariant                    string
	blockingStatus                    string
	requiredEnvironmentClasses        []string
	positiveWitness                   Witness
	positiveWitnessRouteID            string
	falsificationWitness              Witness
	falsificationWitnessRouteID       string
	verifyCommands                    []string
	declaredMutationResistanceClaimID string
}

type ResolverOptions struct {
	LocalEnvironmentClasses []string
}

type FalsificationRoute struct {
	BindingRecordID       string
	FalsificationSelector string
	OwnedInvariant        string
	RequirementID         string
	ResolutionOrderIndex  int
	Role                  string
	RouteID               string
	ScenarioID            string
	SurfaceID             string
	VerifyCommands        []string
}

func SurfaceColumns() []string {
	return append([]string{}, surfaceColumns[:]...)
}

func BindingColumns() []string {
	return append([]string{}, bindingColumns[:]...)
}

func WitnessColumns() []string {
	return append([]string{}, witnessColumns[:]...)
}

func (contract Contract) ContractID() string {
	return contract.contractID
}

func (contract Contract) NonClaims() []string {
	return append([]string{}, contract.nonClaims...)
}

func (contract Contract) Surfaces() []Surface {
	result := make([]Surface, 0, len(contract.surfaces))
	for _, surface := range contract.surfaces {
		result = append(result, cloneSurface(surface))
	}
	return result
}

func (contract Contract) Bindings() []Binding {
	result := make([]Binding, 0, len(contract.bindings))
	for _, binding := range contract.bindings {
		result = append(result, cloneBinding(binding))
	}
	return result
}

func (surface Surface) ID() string {
	return surface.surfaceID
}

func (surface Surface) RequiredEnvironmentClasses() []string {
	return append([]string{}, surface.requiredEnvironmentClasses...)
}

func (surface Surface) PreconditionedEnvironmentClasses() []string {
	return append([]string{}, surface.preconditionedEnvironmentClasses...)
}

func (witness Witness) Selector() string {
	return witness.selector
}

func (witness Witness) EnvironmentClasses() []string {
	return append([]string{}, witness.environmentClasses...)
}

func (witness Witness) VerifyCommands() []string {
	return append([]string{}, witness.verifyCommands...)
}

func (witness Witness) ResolutionOrderIndex() int {
	return witness.resolutionOrderIndex
}

func (binding Binding) RecordID() string {
	return binding.recordID
}

func (binding Binding) RequirementID() string {
	return binding.requirementID
}

func (binding Binding) SurfaceID() string {
	return binding.surfaceID
}

func (binding Binding) ScenarioID() string {
	return binding.scenarioID
}

func (binding Binding) InvariantRole() string {
	return binding.invariantRole
}

func (binding Binding) OwnedInvariant() string {
	return binding.ownedInvariant
}

func (binding Binding) BlockingStatus() string {
	return binding.blockingStatus
}

func (binding Binding) RequiredEnvironmentClasses() []string {
	return append([]string{}, binding.requiredEnvironmentClasses...)
}

func (binding Binding) PositiveWitness() Witness {
	return cloneWitness(binding.positiveWitness)
}

func (binding Binding) PositiveWitnessRouteID() string {
	return binding.positiveWitnessRouteID
}

func (binding Binding) FalsificationWitness() Witness {
	return cloneWitness(binding.falsificationWitness)
}

func (binding Binding) FalsificationWitnessRouteID() string {
	return binding.falsificationWitnessRouteID
}

func (binding Binding) VerifyCommands() []string {
	return append([]string{}, binding.verifyCommands...)
}

func (binding Binding) DeclaredEnvironmentClasses() []string {
	values := append([]string{}, binding.requiredEnvironmentClasses...)
	values = append(values, binding.positiveWitness.environmentClasses...)
	values = append(values, binding.falsificationWitness.environmentClasses...)
	return sortedUnique(values)
}

func (binding Binding) DeclaredVerifyCommands() []string {
	values := append([]string{}, binding.verifyCommands...)
	values = append(values, binding.positiveWitness.verifyCommands...)
	values = append(values, binding.falsificationWitness.verifyCommands...)
	return sortedUnique(values)
}

func (binding Binding) DeclaredMutationResistanceClaimID() string {
	return binding.declaredMutationResistanceClaimID
}

func cloneSurface(surface Surface) Surface {
	surface.requiredEnvironmentClasses = append([]string{}, surface.requiredEnvironmentClasses...)
	surface.preconditionedEnvironmentClasses = append([]string{}, surface.preconditionedEnvironmentClasses...)
	return surface
}

func cloneBinding(binding Binding) Binding {
	binding.requiredEnvironmentClasses = append([]string{}, binding.requiredEnvironmentClasses...)
	binding.verifyCommands = append([]string{}, binding.verifyCommands...)
	binding.positiveWitness = cloneWitness(binding.positiveWitness)
	binding.falsificationWitness = cloneWitness(binding.falsificationWitness)
	return binding
}

func cloneWitness(witness Witness) Witness {
	witness.environmentClasses = append([]string{}, witness.environmentClasses...)
	witness.verifyCommands = append([]string{}, witness.verifyCommands...)
	return witness
}

func Admit(raw any) (Contract, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Contract{}, fmt.Errorf("compact requirement proof contract must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority_state", "binding_columns", "bindings", "contract_id", "contract_kind", "non_claims", "normalization_profile", "schema_version", "surface_columns", "surfaces", "witness_columns"}, "compact requirement proof contract"); err != nil {
		return Contract{}, err
	}
	if !admit.JSONNumberEquals(record["schema_version"], 2) {
		return Contract{}, fmt.Errorf("compact requirement proof contract schema_version must be 2")
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
	surfaceColumnIndex, err := columnIndex(record["surface_columns"], surfaceColumns[:], "compact requirement proof surface_columns")
	if err != nil {
		return Contract{}, err
	}
	bindingColumnIndex, err := columnIndex(record["binding_columns"], bindingColumns[:], "compact requirement proof binding_columns")
	if err != nil {
		return Contract{}, err
	}
	witnessColumnIndex, err := columnIndex(record["witness_columns"], witnessColumns[:], "compact requirement proof witness_columns")
	if err != nil {
		return Contract{}, err
	}
	nonClaims, err := stringArray(record["non_claims"], "compact requirement proof non_claims")
	if err != nil {
		return Contract{}, err
	}
	surfaces, err := admitSurfaces(record["surfaces"], surfaceColumnIndex)
	if err != nil {
		return Contract{}, err
	}
	bindings, err := admitBindings(record["bindings"], bindingColumnIndex, witnessColumnIndex)
	if err != nil {
		return Contract{}, err
	}
	contract := Contract{contractID: contractID, nonClaims: nonClaims, surfaces: surfaces, bindings: bindings}
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
	bindings, routes, err := contract.resolverBindings(localClasses)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"bindings":                 bindings,
		"commands":                 contract.resolverCommands(bindings, routes),
		"conformanceProofContract": contract.ConformanceProjection(),
		"contractId":               contract.contractID,
		"environmentClasses":       contract.resolverEnvironmentClasses(bindings, routes),
		"localEnvironmentPolicy":   map[string]any{"authority": "caller_provided", "localEnvironmentClasses": stringSliceToAny(localClasses)},
		"nonClaims":                resolverNonClaims(contract.nonClaims),
		"projectionKind":           "proofkit.requirement-proof-route-resolver",
		"scenarios":                resolverScenarios(bindings),
		"schemaVersion":            2,
		"surfaces":                 resolverSurfaces(contract.surfaces, bindings),
		"witnessRoutes":            witnessRoutesValue(routes),
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
	routes := make([]FalsificationRoute, 0, len(contract.bindings))
	for _, binding := range contract.bindings {
		routes = append(routes, FalsificationRoute{
			BindingRecordID:       binding.recordID,
			FalsificationSelector: binding.falsificationWitness.selector,
			OwnedInvariant:        binding.ownedInvariant,
			RequirementID:         binding.requirementID,
			ResolutionOrderIndex:  binding.falsificationWitness.resolutionOrderIndex,
			Role:                  FalsificationWitnessRole,
			RouteID:               binding.falsificationWitnessRouteID,
			ScenarioID:            binding.scenarioID,
			SurfaceID:             binding.surfaceID,
			VerifyCommands:        append([]string{}, binding.falsificationWitness.verifyCommands...),
		})
	}
	return routes
}

func (contract Contract) ConformanceProjection() map[string]any {
	bindings := make([]any, 0, len(contract.bindings))
	for _, binding := range contract.bindings {
		bindings = append(bindings, map[string]any{
			"bindingRecordId":                   binding.recordID,
			"blockingStatus":                    binding.blockingStatus,
			"declaredMutationResistanceClaimId": binding.declaredMutationResistanceClaimID,
			"invariantRole":                     binding.invariantRole,
			"ownedInvariant":                    binding.ownedInvariant,
			"requiredEnvironmentClasses":        stringSliceToAny(binding.requiredEnvironmentClasses),
			"requirementId":                     binding.requirementID,
			"scenarioId":                        binding.scenarioID,
			"surfaceId":                         binding.surfaceID,
			"verifyCommands":                    stringSliceToAny(binding.verifyCommands),
			"witnessRefs": []any{
				witnessReference(binding.falsificationWitnessRouteID, FalsificationWitnessRole, binding.falsificationWitness),
				witnessReference(binding.positiveWitnessRouteID, PositiveWitnessRole, binding.positiveWitness),
			},
		})
	}
	surfaces := make([]any, 0, len(contract.surfaces))
	for _, surface := range contract.surfaces {
		surfaces = append(surfaces, map[string]any{
			"preconditionedEnvironmentClasses": stringSliceToAny(surface.preconditionedEnvironmentClasses),
			"requiredEnvironmentClasses":       stringSliceToAny(surface.requiredEnvironmentClasses),
			"surfaceId":                        surface.surfaceID,
		})
	}
	return map[string]any{
		"bindings":        bindings,
		"contractId":      contract.contractID,
		"declarationKind": "proofkit.requirement-proof-route-declaration",
		"schemaVersion":   2,
		"surfaces":        surfaces,
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
		surfaces = append(surfaces, Surface{surfaceID: surfaceID, requiredEnvironmentClasses: required, preconditionedEnvironmentClasses: preconditioned})
	}
	sort.Slice(surfaces, func(left, right int) bool { return surfaces[left].surfaceID < surfaces[right].surfaceID })
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
	declaredMutationResistanceClaimID, err := admit.RuleID(column(row, bindingColumns, "declared_mutation_resistance_claim_id"), context+" declared_mutation_resistance_claim_id")
	if err != nil {
		return Binding{}, err
	}
	recordID, err := BindingRecordID(BindingIdentity{RequirementID: requirementID, ScenarioID: scenarioID, SurfaceID: surfaceID})
	if err != nil {
		return Binding{}, fmt.Errorf("%s binding record id: %w", context, err)
	}
	positiveRouteID, err := WitnessRouteID(recordID, PositiveWitnessRole, positive.selector)
	if err != nil {
		return Binding{}, fmt.Errorf("%s positive witness route id: %w", context, err)
	}
	falsificationRouteID, err := WitnessRouteID(recordID, FalsificationWitnessRole, falsification.selector)
	if err != nil {
		return Binding{}, fmt.Errorf("%s falsification witness route id: %w", context, err)
	}
	return Binding{
		recordID:      recordID,
		requirementID: requirementID, surfaceID: surfaceID, scenarioID: scenarioID,
		invariantRole: invariantRole, ownedInvariant: ownedInvariant,
		blockingStatus: blockingStatus, requiredEnvironmentClasses: required,
		positiveWitness: positive, positiveWitnessRouteID: positiveRouteID,
		falsificationWitness: falsification, falsificationWitnessRouteID: falsificationRouteID,
		verifyCommands:                    verifyCommands,
		declaredMutationResistanceClaimID: declaredMutationResistanceClaimID,
	}, nil
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
	selector, err = AdmitWitnessSelector(selector, context+" selector")
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
	order, err := AdmitResolutionOrderIndex(column(row, columns, "resolution_order_index"), context+" resolution_order_index")
	if err != nil {
		return Witness{}, err
	}
	return Witness{selector: selector, environmentClasses: environmentClasses, verifyCommands: verifyCommands, resolutionOrderIndex: order}, nil
}

func witnessReference(routeID, role string, witness Witness) map[string]any {
	return map[string]any{
		"environmentClasses":   stringSliceToAny(witness.environmentClasses),
		"resolutionOrderIndex": witness.resolutionOrderIndex,
		"role":                 role,
		"selector":             witness.selector,
		"verifyCommands":       stringSliceToAny(witness.verifyCommands),
		"witnessRouteId":       routeID,
	}
}

func (contract Contract) resolverBindings(localClasses []string) ([]any, []WitnessRoute, error) {
	surfaceByID := map[string]Surface{}
	for _, surface := range contract.surfaces {
		surfaceByID[surface.surfaceID] = surface
	}
	bindings := make([]any, 0, len(contract.bindings))
	routes := make([]WitnessRoute, 0, len(contract.bindings)*2)
	routeCoordinates := map[string]string{}
	for _, binding := range contract.bindings {
		surface := surfaceByID[binding.surfaceID]
		bindingRoutes, err := binding.WitnessRoutes()
		if err != nil {
			return nil, nil, err
		}
		for _, route := range bindingRoutes {
			coordinate := route.BindingRecordID + "\x00" + route.Role + "\x00" + route.Selector
			if previous, ok := routeCoordinates[route.RouteID]; ok && previous != coordinate {
				return nil, nil, fmt.Errorf("compact requirement proof witness route id collision")
			}
			routeCoordinates[route.RouteID] = coordinate
		}
		routes = append(routes, bindingRoutes...)
		bindings = append(bindings, map[string]any{
			"bindingRecordId":                   binding.recordID,
			"blockingStatus":                    binding.blockingStatus,
			"declaredMutationResistanceClaimId": binding.declaredMutationResistanceClaimID,
			"invariantRole":                     binding.invariantRole,
			"ownedInvariant":                    binding.ownedInvariant,
			"preconditioned":                    resolverPreconditioned(surface, binding.DeclaredEnvironmentClasses(), localClasses),
			"requiredEnvironmentClasses":        stringSliceToAny(binding.requiredEnvironmentClasses),
			"requirementId":                     binding.requirementID,
			"scenarioId":                        binding.scenarioID,
			"surfaceId":                         binding.surfaceID,
			"testWitnesses": map[string]any{
				"falsification": resolverWitness(bindingRoutes[0]),
				"positive":      resolverWitness(bindingRoutes[1]),
			},
			"verifyCommands": stringSliceToAny(binding.verifyCommands),
		})
	}
	sort.Slice(routes, func(left, right int) bool { return routes[left].RouteID < routes[right].RouteID })
	return bindings, routes, nil
}

func resolverWitness(route WitnessRoute) map[string]any {
	return map[string]any{
		"environmentClasses":   stringSliceToAny(route.EnvironmentClasses),
		"resolutionOrderIndex": route.ResolutionOrder,
		"role":                 route.Role,
		"selector":             route.Selector,
		"verifyCommandRefs":    stringSliceToAny(route.VerifyCommands),
		"witnessRouteId":       route.RouteID,
	}
}

func resolverPreconditioned(surface Surface, required []string, localClasses []string) bool {
	if len(surface.preconditionedEnvironmentClasses) > 0 {
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

func resolverSurfaces(surfaces []Surface, bindings []any) []any {
	bindingIDsBySurface := make(map[string][]string, len(surfaces))
	requirementIDsBySurface := make(map[string][]string, len(surfaces))
	for _, bindingValue := range bindings {
		binding := bindingValue.(map[string]any)
		surfaceID := binding["surfaceId"].(string)
		bindingIDsBySurface[surfaceID] = append(bindingIDsBySurface[surfaceID], binding["bindingRecordId"].(string))
		requirementIDsBySurface[surfaceID] = append(requirementIDsBySurface[surfaceID], binding["requirementId"].(string))
	}
	result := make([]any, 0, len(surfaces))
	for _, surface := range surfaces {
		result = append(result, map[string]any{
			"bindingRecordIds": stringSliceToAny(sortedUnique(bindingIDsBySurface[surface.surfaceID])),
			"requirementIds":   stringSliceToAny(sortedUnique(requirementIDsBySurface[surface.surfaceID])),
			"surfaceId":        surface.surfaceID,
		})
	}
	return result
}

func resolverScenarios(bindings []any) []any {
	result := make([]any, 0, len(bindings))
	for _, bindingValue := range bindings {
		binding := bindingValue.(map[string]any)
		result = append(result, map[string]any{
			"bindingRecordId": binding["bindingRecordId"],
			"requirementId":   binding["requirementId"],
			"scenarioId":      binding["scenarioId"],
			"surfaceId":       binding["surfaceId"],
		})
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].(map[string]any)["scenarioId"].(string) < result[right].(map[string]any)["scenarioId"].(string)
	})
	return result
}

func witnessRoutesValue(routes []WitnessRoute) []any {
	result := make([]any, 0, len(routes))
	for _, route := range routes {
		result = append(result, map[string]any{
			"bindingRecordId":      route.BindingRecordID,
			"environmentClasses":   stringSliceToAny(route.EnvironmentClasses),
			"requirementId":        route.Identity.RequirementID,
			"resolutionOrderIndex": route.ResolutionOrder,
			"role":                 route.Role,
			"scenarioId":           route.Identity.ScenarioID,
			"selector":             route.Selector,
			"surfaceId":            route.Identity.SurfaceID,
			"verifyCommandRefs":    stringSliceToAny(route.VerifyCommands),
			"witnessRouteId":       route.RouteID,
		})
	}
	return result
}

func (contract Contract) resolverCommands(bindings []any, routes []WitnessRoute) []any {
	type commandFact struct {
		EnvironmentClasses map[string]struct{}
		BindingRecordIDs   map[string]struct{}
		WitnessRouteIDs    map[string]struct{}
	}
	byCommand := map[string]*commandFact{}
	factFor := func(command string) *commandFact {
		fact := byCommand[command]
		if fact == nil {
			fact = &commandFact{
				EnvironmentClasses: map[string]struct{}{},
				BindingRecordIDs:   map[string]struct{}{},
				WitnessRouteIDs:    map[string]struct{}{},
			}
			byCommand[command] = fact
		}
		return fact
	}
	for _, bindingValue := range bindings {
		binding := bindingValue.(map[string]any)
		for _, command := range stringArrayFromAny(binding["verifyCommands"]) {
			fact := factFor(command)
			add(fact.BindingRecordIDs, binding["bindingRecordId"].(string))
			for _, class := range stringArrayFromAny(binding["requiredEnvironmentClasses"]) {
				add(fact.EnvironmentClasses, class)
			}
		}
	}
	for _, route := range routes {
		for _, command := range route.VerifyCommands {
			fact := factFor(command)
			add(fact.BindingRecordIDs, route.BindingRecordID)
			add(fact.WitnessRouteIDs, route.RouteID)
			for _, class := range route.EnvironmentClasses {
				add(fact.EnvironmentClasses, class)
			}
		}
	}
	commands := keys(byCommand)
	out := make([]any, 0, len(commands))
	for _, command := range commands {
		fact := byCommand[command]
		out = append(out, map[string]any{
			"environmentClasses": stringSliceToAny(keys(fact.EnvironmentClasses)),
			"bindingRecordIds":   stringSliceToAny(keys(fact.BindingRecordIDs)),
			"verifyCommandRef":   command,
			"witnessRouteIds":    stringSliceToAny(keys(fact.WitnessRouteIDs)),
		})
	}
	return out
}

func (contract Contract) resolverEnvironmentClasses(bindings []any, routes []WitnessRoute) []any {
	type environmentFact struct {
		BindingRecordIDs map[string]struct{}
		SurfaceIDs       map[string]struct{}
		WitnessRouteIDs  map[string]struct{}
	}
	byClass := map[string]*environmentFact{}
	factFor := func(class string) *environmentFact {
		fact := byClass[class]
		if fact == nil {
			fact = &environmentFact{
				BindingRecordIDs: map[string]struct{}{},
				SurfaceIDs:       map[string]struct{}{},
				WitnessRouteIDs:  map[string]struct{}{},
			}
			byClass[class] = fact
		}
		return fact
	}
	for _, surface := range contract.surfaces {
		for _, class := range append(append([]string{}, surface.requiredEnvironmentClasses...), surface.preconditionedEnvironmentClasses...) {
			fact := factFor(class)
			add(fact.SurfaceIDs, surface.surfaceID)
		}
	}
	for _, bindingValue := range bindings {
		binding := bindingValue.(map[string]any)
		for _, class := range stringArrayFromAny(binding["requiredEnvironmentClasses"]) {
			fact := factFor(class)
			add(fact.BindingRecordIDs, binding["bindingRecordId"].(string))
			add(fact.SurfaceIDs, binding["surfaceId"].(string))
		}
	}
	for _, route := range routes {
		for _, class := range route.EnvironmentClasses {
			fact := factFor(class)
			add(fact.BindingRecordIDs, route.BindingRecordID)
			add(fact.SurfaceIDs, route.Identity.SurfaceID)
			add(fact.WitnessRouteIDs, route.RouteID)
		}
	}
	classes := keys(byClass)
	out := make([]any, 0, len(classes))
	for _, class := range classes {
		fact := byClass[class]
		out = append(out, map[string]any{
			"bindingRecordIds": stringSliceToAny(keys(fact.BindingRecordIDs)),
			"environmentClass": class,
			"surfaceIds":       stringSliceToAny(keys(fact.SurfaceIDs)),
			"witnessRouteIds":  stringSliceToAny(keys(fact.WitnessRouteIDs)),
		})
	}
	return out
}

func resolverNonClaims(nonClaims []string) []any {
	merged := append([]string{}, nonClaims...)
	merged = append(merged,
		"Requirement proof route declarations do not prove that witness selectors exist or resolve.",
		"Requirement proof route declarations do not assess oracle quality, mutation adequacy, finding absence, or finding completeness.",
		"Requirement proof route declarations do not execute witnesses or prove execution-backed coverage.",
		"Requirement proof route declarations do not prove freshness, authenticity, trust, assurance, merge approval, rollout, or production readiness.",
		"Consumers own local environment-class policy supplied to the preconditioned projection.",
	)
	return stringSliceToAny(sortedUnique(merged))
}

func admitScopedScenarioID(value string, surfaceID string, context string) (string, error) {
	scenarioID, scenarioSurfaceID, err := AdmitScenarioID(value, context)
	if err != nil {
		return "", err
	}
	if scenarioSurfaceID != surfaceID {
		return "", fmt.Errorf("%s must be scoped under surface_id %s", context, surfaceID)
	}
	return scenarioID, nil
}

// AdmitScenarioID preserves the compact-contract owner for the encoded
// surface_id::stable_anchor scenario identity used by child projections.
func AdmitScenarioID(value string, context string) (string, string, error) {
	parts := strings.Split(value, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%s must use surface_id::stable_anchor scenario identity", context)
	}
	scenarioSurfaceID, err := admit.RuleID(parts[0], context+" surface_id")
	if err != nil {
		return "", "", err
	}
	anchor, err := admit.RuleID(parts[1], context+" anchor")
	if err != nil {
		return "", "", err
	}
	return scenarioSurfaceID + "::" + anchor, scenarioSurfaceID, nil
}

// AdmitWitnessSelector preserves the compact-contract owner for selector
// identity when child projections re-admit compact witness routes.
func AdmitWitnessSelector(value string, context string) (string, error) {
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

func AdmitResolutionOrderIndex(raw any, context string) (int, error) {
	number, err := admit.CanonicalInteger(raw, context)
	if err != nil || number < 0 || number > maxJSONSafeInteger || int64(int(number)) != number {
		return 0, fmt.Errorf("%s must be a JSON-safe non-negative integer", context)
	}
	return int(number), nil
}

// AdmitProjectedResolutionOrderIndex preserves the JSON-safe wire owner when
// a typed in-process projection has already materialized the admitted integer.
func AdmitProjectedResolutionOrderIndex(raw any, context string) (int, error) {
	switch value := raw.(type) {
	case int:
		return AdmitResolutionOrderIndex(json.Number(strconv.Itoa(value)), context)
	case json.Number:
		return AdmitResolutionOrderIndex(value, context)
	default:
		return 0, fmt.Errorf("%s must be a JSON-safe non-negative integer", context)
	}
}

func assertReferentialIntegrity(contract Contract) error {
	surfaceIDs := make([]string, 0, len(contract.surfaces))
	surfaceSet := map[string]struct{}{}
	for _, surface := range contract.surfaces {
		surfaceIDs = append(surfaceIDs, surface.surfaceID)
		surfaceSet[surface.surfaceID] = struct{}{}
	}
	if err := assertUniqueStrings(surfaceIDs, "compact requirement proof surface_id"); err != nil {
		return err
	}
	bindingIDs := make([]string, 0, len(contract.bindings))
	bindingRecordCoordinates := map[string]string{}
	witnessRouteCoordinates := map[string]string{}
	for _, binding := range contract.bindings {
		bindingIDs = append(bindingIDs, bindingSortKey(binding))
		if _, ok := surfaceSet[binding.surfaceID]; !ok {
			return fmt.Errorf("compact requirement proof binding %s references unknown surfaceId=%s", binding.requirementID, binding.surfaceID)
		}
		coordinate := bindingSortKey(binding)
		if previous, ok := bindingRecordCoordinates[binding.recordID]; ok && previous != coordinate {
			return fmt.Errorf("compact requirement proof binding record id collision")
		}
		bindingRecordCoordinates[binding.recordID] = coordinate
		for _, route := range []struct {
			ID       string
			Role     string
			Selector string
		}{
			{ID: binding.falsificationWitnessRouteID, Role: FalsificationWitnessRole, Selector: binding.falsificationWitness.selector},
			{ID: binding.positiveWitnessRouteID, Role: PositiveWitnessRole, Selector: binding.positiveWitness.selector},
		} {
			routeCoordinate := binding.recordID + "\x00" + route.Role + "\x00" + route.Selector
			if previous, ok := witnessRouteCoordinates[route.ID]; ok && previous != routeCoordinate {
				return fmt.Errorf("compact requirement proof witness route id collision")
			}
			witnessRouteCoordinates[route.ID] = routeCoordinate
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
	return binding.requirementID + "\x00" + binding.surfaceID + "\x00" + binding.scenarioID
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
