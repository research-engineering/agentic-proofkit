package requirementcoverageview

import (
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"sort"
)

func admitCompositeInput(raw any) (compositeInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return compositeInput{}, fmt.Errorf("requirement coverage view input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"compactProofContract", "coverageUniverse", "localEnvironmentPolicy", "options", "ownerInvariantRegistry", "requirementProofBinding", "requirementSource", "schemaVersion", "testEvidenceInventory", "viewInputId"}, "requirement coverage view input"); err != nil {
		return compositeInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return compositeInput{}, fmt.Errorf("requirement coverage view schemaVersion must be 1")
	}
	viewInputID, err := admit.RuleID(record["viewInputId"], "requirement coverage view viewInputId")
	if err != nil {
		return compositeInput{}, err
	}
	if err := admitOptions(record["options"]); err != nil {
		return compositeInput{}, err
	}
	sourceResult, err := requirementsourceadmission.Evaluate(record["requirementSource"])
	if err != nil {
		return compositeInput{}, err
	}
	if sourceResult.Report.State != "passed" {
		return compositeInput{}, fmt.Errorf("cannot build requirement coverage view from failed requirement source admission")
	}
	universe, err := admitCoverageUniverse(record["coverageUniverse"])
	if err != nil {
		return compositeInput{}, err
	}
	registry, err := admitOwnerInvariantRegistry(record["ownerInvariantRegistry"])
	if err != nil {
		return compositeInput{}, err
	}
	policy, err := admitLocalEnvironmentPolicy(record["localEnvironmentPolicy"])
	if err != nil {
		return compositeInput{}, err
	}
	proof, err := buildProofProjection(record["requirementProofBinding"], record["compactProofContract"], policy)
	if err != nil {
		return compositeInput{}, err
	}
	var inventoryResult *testevidenceinventory.Result
	if record["testEvidenceInventory"] != nil {
		result, err := testevidenceinventory.Evaluate(record["testEvidenceInventory"])
		if err != nil {
			return compositeInput{}, err
		}
		inventoryResult = &result
	}
	return compositeInput{
		CoverageUniverse: universe, Inventory: inventoryResult,
		LocalEnvironmentPolicy: policy, OwnerInvariantRegistry: registry,
		Proof: proof, Source: sourceResult.Source, ViewInputID: viewInputID,
	}, nil
}
func buildProofProjection(structured any, compact any, policy *localEnvironmentPolicy) (proofProjection, error) {
	if (structured == nil && compact == nil) || (structured != nil && compact != nil) {
		return proofProjection{}, fmt.Errorf("requirement coverage view requires exactly one of requirementProofBinding or compactProofContract")
	}
	if structured != nil {
		result, err := requirementbinding.Build(structured)
		if err != nil {
			return proofProjection{}, err
		}
		if result.Record.State != "passed" {
			return proofProjection{}, fmt.Errorf("cannot build requirement coverage view from failed requirement proof bindings")
		}
		return structuredProofProjection(result.Graph), nil
	}
	if policy == nil {
		return proofProjection{}, fmt.Errorf("compact requirement coverage view requires localEnvironmentPolicy")
	}
	projection, _, err := requirementbinding.BuildResolver(compact, requirementbinding.ResolverOptions{LocalEnvironmentClasses: policy.LocalEnvironmentClasses})
	if err != nil {
		return proofProjection{}, err
	}
	return compactProofProjection(projection.(map[string]any))
}
func structuredProofProjection(graph map[string]any) proofProjection {
	requirements := map[string]proofRequirement{}
	commandIDs := []string{}
	witnessRefs := []string{}
	for _, rawRequirement := range anyArray(graph["requirements"]) {
		requirement := rawRequirement.(map[string]any)
		requirementID := stringValue(requirement["requirementId"])
		scenarios := []scenario{}
		reqCommands := []string{}
		environments := []string{}
		reqWitnessRefs := []string{}
		for _, rawScenario := range anyArray(requirement["scenarios"]) {
			item := rawScenario.(map[string]any)
			scenarioCommands := stringArray(item["commandIds"])
			scenarioWitness := stringValue(item["witnessId"])
			commandIDs = append(commandIDs, scenarioCommands...)
			reqCommands = append(reqCommands, scenarioCommands...)
			witnessRefs = append(witnessRefs, scenarioWitness)
			reqWitnessRefs = append(reqWitnessRefs, scenarioWitness)
			environments = append(environments, stringArray(item["environmentClasses"])...)
			scenarios = append(scenarios, scenario{
				CommandIDs: scenarioCommands, EnvironmentClasses: stringArray(item["environmentClasses"]),
				ScenarioID: stringValue(item["scenarioId"]), WitnessID: scenarioWitness,
				WitnessKind: stringValue(item["witnessKind"]), WitnessPath: stringValue(item["witnessPath"]),
			})
		}
		requirements[requirementID] = proofRequirement{
			CommandIDs: sortedUnique(reqCommands), EnvironmentClasses: sortedUnique(environments),
			ProofState: stringValue(requirement["proofState"]), Scenarios: scenarios,
			WitnessRefs: sortedUnique(reqWitnessRefs),
		}
	}
	return proofProjection{
		BindingID: stringValue(graph["bindingId"]), CommandIDs: sortedUnique(commandIDs),
		Mode: "structured", Requirements: requirements, WitnessRefs: sortedUnique(witnessRefs),
	}
}
func compactProofProjection(projection map[string]any) (proofProjection, error) {
	requirements := map[string]proofRequirement{}
	witnessSelectors := []string{}
	for _, rawRequirement := range anyArray(projection["requirements"]) {
		requirement := rawRequirement.(map[string]any)
		requirementID := stringValue(requirement["requirementId"])
		selectors := compactRequirementWitnessSelectors(requirement)
		witnessSelectors = append(witnessSelectors, selectors...)
		previous := requirements[requirementID]
		proofState := stringValue(requirement["proofContractState"])
		if previous.ProofState != "" && previous.ProofState != proofState {
			return proofProjection{}, fmt.Errorf("compact requirement coverage view has conflicting proofContractState for %s", requirementID)
		}
		requirements[requirementID] = proofRequirement{
			EnvironmentClasses: sortedUnique(append(previous.EnvironmentClasses, compactRequirementEnvironmentClasses(requirement)...)),
			ProofState:         proofState,
			Scenarios:          append(previous.Scenarios, compactRequirementScenarios(requirement)...),
			VerifyCommands:     sortedUnique(append(previous.VerifyCommands, stringArray(requirement["verifyCommands"])...)),
			WitnessSelectors:   sortedUnique(append(previous.WitnessSelectors, selectors...)),
		}
	}
	return proofProjection{
		ContractID: stringValue(projection["contractId"]), Mode: "compact",
		Requirements: requirements, WitnessSelectors: sortedUnique(witnessSelectors),
	}, nil
}

func compactRequirementScenarios(requirement map[string]any) []scenario {
	scenarioID := stringValue(requirement["scenarioId"])
	if scenarioID == "" {
		return nil
	}
	return []scenario{{
		EnvironmentClasses: compactRequirementEnvironmentClasses(requirement),
		ScenarioID:         scenarioID,
	}}
}

func compactRequirementEnvironmentClasses(requirement map[string]any) []string {
	values := append([]string{}, stringArray(requirement["requiredEnvironmentClasses"])...)
	for _, witness := range compactRequirementWitnesses(requirement) {
		values = append(values, stringArray(witness["environmentClasses"])...)
	}
	return sortedUnique(values)
}

func compactRequirementWitnessSelectors(requirement map[string]any) []string {
	selectors := []string{}
	for _, witness := range compactRequirementWitnesses(requirement) {
		selector := stringValue(witness["selector"])
		if selector != "" {
			selectors = append(selectors, selector)
		}
	}
	return sortedUnique(selectors)
}

func compactRequirementWitnesses(requirement map[string]any) []map[string]any {
	witnesses, ok := requirement["testWitnesses"].(map[string]any)
	if !ok {
		return nil
	}
	result := []map[string]any{}
	for _, role := range []string{"falsification", "positive"} {
		if witness, ok := witnesses[role].(map[string]any); ok {
			result = append(result, witness)
		}
	}
	return result
}

func admitCoverageUniverse(raw any) (coverageUniverse, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return coverageUniverse{}, fmt.Errorf("coverageUniverse must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority", "codeSurfaces", "commandRefs", "completenessDeclaration", "nonClaims", "ownerIds", "schemaVersion", "specSurfaces", "testSurfaces", "universeId"}, "coverageUniverse"); err != nil {
		return coverageUniverse{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return coverageUniverse{}, fmt.Errorf("coverageUniverse schemaVersion must be 1")
	}
	authority, err := literal(record["authority"], "caller_owned_inventory", "coverageUniverse authority")
	if err != nil {
		return coverageUniverse{}, err
	}
	universeID, err := admit.RuleID(record["universeId"], "coverageUniverse universeId")
	if err != nil {
		return coverageUniverse{}, err
	}
	completeness, err := admit.Enum(record["completenessDeclaration"], map[string]struct{}{"full_repository": {}, "selected_owner_surfaces": {}, "selected_paths_advisory": {}}, "coverageUniverse completenessDeclaration")
	if err != nil {
		return coverageUniverse{}, err
	}
	ownerIDs, err := sortedRuleIDs(record["ownerIds"], "coverageUniverse ownerIds", false)
	if err != nil {
		return coverageUniverse{}, err
	}
	codeSurfaces, err := admitSurfaces(record["codeSurfaces"], "coverageUniverse codeSurfaces")
	if err != nil {
		return coverageUniverse{}, err
	}
	specSurfaces, err := admitSurfaces(record["specSurfaces"], "coverageUniverse specSurfaces")
	if err != nil {
		return coverageUniverse{}, err
	}
	testSurfaces, err := admitSurfaces(record["testSurfaces"], "coverageUniverse testSurfaces")
	if err != nil {
		return coverageUniverse{}, err
	}
	ownerSet := mapSet(ownerIDs)
	if err := requireDeclaredSurfaceOwners(codeSurfaces, ownerSet, "coverageUniverse codeSurfaces"); err != nil {
		return coverageUniverse{}, err
	}
	if err := requireDeclaredSurfaceOwners(specSurfaces, ownerSet, "coverageUniverse specSurfaces"); err != nil {
		return coverageUniverse{}, err
	}
	if err := requireDeclaredSurfaceOwners(testSurfaces, ownerSet, "coverageUniverse testSurfaces"); err != nil {
		return coverageUniverse{}, err
	}
	commandRefs, err := sortedRuleIDs(record["commandRefs"], "coverageUniverse commandRefs", true)
	if err != nil {
		return coverageUniverse{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "coverageUniverse nonClaims", false)
	if err != nil {
		return coverageUniverse{}, err
	}
	return coverageUniverse{
		Authority: authority, CodeSurfaces: codeSurfaces, CommandRefs: commandRefs,
		CompletenessDeclaration: completeness, NonClaims: nonClaims, OwnerIDs: ownerIDs,
		SpecSurfaces: specSurfaces, TestSurfaces: testSurfaces, UniverseID: universeID,
	}, nil
}

func requireDeclaredSurfaceOwners(surfaces []surface, ownerSet map[string]struct{}, context string) error {
	for _, item := range surfaces {
		if _, ok := ownerSet[item.OwnerID]; !ok {
			return fmt.Errorf("%s ownerId %s must reference coverageUniverse ownerIds", context, item.OwnerID)
		}
	}
	return nil
}

func admitSurfaces(raw any, context string) ([]surface, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]surface, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s item must be an object", context)
		}
		if err := admit.KnownKeys(record, []string{"ownerId", "path", "surfaceId"}, context+" item"); err != nil {
			return nil, err
		}
		surfaceID, err := admit.RuleID(record["surfaceId"], context+" surfaceId")
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], context+" ownerId")
		if err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], context+" path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, context+" path")
		if err != nil {
			return nil, err
		}
		result = append(result, surface{OwnerID: ownerID, Path: pathValue, SurfaceID: surfaceID})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].SurfaceID < result[right].SurfaceID })
	return result, assertUnique(surfaceIDs(result), context+" surfaceIds")
}
func admitOwnerInvariantRegistry(raw any) (ownerInvariantRegistry, error) {
	if raw == nil {
		return ownerInvariantRegistry{}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return ownerInvariantRegistry{}, fmt.Errorf("ownerInvariantRegistry must be an object or null")
	}
	if err := admit.KnownKeys(record, []string{"invariants", "nonClaims", "registryId", "schemaVersion"}, "ownerInvariantRegistry"); err != nil {
		return ownerInvariantRegistry{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return ownerInvariantRegistry{}, fmt.Errorf("ownerInvariantRegistry schemaVersion must be 1")
	}
	registryID, err := admit.RuleID(record["registryId"], "ownerInvariantRegistry registryId")
	if err != nil {
		return ownerInvariantRegistry{}, err
	}
	invariants, err := admitOwnerInvariants(record["invariants"])
	if err != nil {
		return ownerInvariantRegistry{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "ownerInvariantRegistry nonClaims", false)
	if err != nil {
		return ownerInvariantRegistry{}, err
	}
	return ownerInvariantRegistry{Invariants: invariants, NonClaims: nonClaims, RegistryID: registryID}, nil
}
func admitOwnerInvariants(raw any) ([]ownerInvariant, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("ownerInvariantRegistry invariants must be an array")
	}
	result := make([]ownerInvariant, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("ownerInvariantRegistry invariant must be an object")
		}
		if err := admit.KnownKeys(record, []string{"nonClaims", "ownerId", "ownerInvariantId", "sourcePath", "summary"}, "ownerInvariantRegistry invariant"); err != nil {
			return nil, err
		}
		invariantID, err := admit.RuleID(record["ownerInvariantId"], "ownerInvariantRegistry ownerInvariantId")
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], "ownerInvariantRegistry ownerId")
		if err != nil {
			return nil, err
		}
		sourceText, err := admit.NonEmptyText(record["sourcePath"], "ownerInvariantRegistry sourcePath")
		if err != nil {
			return nil, err
		}
		sourcePath, err := admit.SafeRepoRelativePath(sourceText, "ownerInvariantRegistry sourcePath")
		if err != nil {
			return nil, err
		}
		summary, err := admit.NonEmptyText(record["summary"], "ownerInvariantRegistry summary")
		if err != nil {
			return nil, err
		}
		nonClaims, err := sortedText(record["nonClaims"], "ownerInvariantRegistry nonClaims", true)
		if err != nil {
			return nil, err
		}
		result = append(result, ownerInvariant{NonClaims: nonClaims, OwnerID: ownerID, OwnerInvariantID: invariantID, SourcePath: sourcePath, Summary: summary})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].OwnerInvariantID < result[right].OwnerInvariantID })
	return result, assertUnique(ownerInvariantIDs(result), "ownerInvariantRegistry ownerInvariantIds")
}
func admitLocalEnvironmentPolicy(raw any) (*localEnvironmentPolicy, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("localEnvironmentPolicy must be an object or null")
	}
	if err := admit.KnownKeys(record, []string{"authority", "localEnvironmentClasses"}, "localEnvironmentPolicy"); err != nil {
		return nil, err
	}
	authority, err := literal(record["authority"], "caller_provided", "localEnvironmentPolicy authority")
	if err != nil {
		return nil, err
	}
	classes, err := sortedRuleIDs(record["localEnvironmentClasses"], "localEnvironmentPolicy localEnvironmentClasses", true)
	if err != nil {
		return nil, err
	}
	return &localEnvironmentPolicy{Authority: authority, LocalEnvironmentClasses: classes}, nil
}
func admitOptions(raw any) error {
	if raw == nil {
		return nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("requirement coverage view options must be an object or null")
	}
	return admit.KnownKeys(record, []string{"scope"}, "requirement coverage view options")
}
