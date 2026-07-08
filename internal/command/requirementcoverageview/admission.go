package requirementcoverageview

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func admitCompositeInput(raw any) (compositeInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return compositeInput{}, fmt.Errorf("requirement coverage view input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"compactProofContract", "coverageUniverse", "localEnvironmentPolicy", "normalizedTestEvidenceInventory", "options", "ownerInvariantRegistry", "requirementProofBinding", "requirementSource", "schemaVersion", "testEvidenceInventory", "viewInputId"}, "requirement coverage view input"); err != nil {
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
	normalizedInventoryResult, err := admitNormalizedInventoryProvenance(record["normalizedTestEvidenceInventory"], record["testEvidenceInventory"])
	if err != nil {
		return compositeInput{}, err
	}
	if inventoryResult == nil && normalizedInventoryResult != nil {
		inventoryResult = normalizedInventoryResult
	}
	return compositeInput{
		CoverageUniverse: universe, Inventory: inventoryResult,
		LocalEnvironmentPolicy: policy, OwnerInvariantRegistry: registry,
		Proof: proof, Source: sourceResult.Source, ViewInputID: viewInputID,
	}, nil
}

func admitNormalizedInventoryProvenance(raw any, directInventory any) (*testevidenceinventory.Result, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory must be an object")
	}
	if err := admit.KnownKeys(record, []string{"entrySources", "inputPaths", "inventory", "nonClaims", "normalizedInventoryId", "normalizedKind", "projectionKind", "projectionSummary", "schemaVersion", "sourceAuthority", "sourceColumns", "sourceCount", "sources"}, "requirement coverage view normalizedTestEvidenceInventory"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory schemaVersion must be 1")
	}
	if _, err := admit.RuleID(record["normalizedInventoryId"], "requirement coverage view normalizedTestEvidenceInventory normalizedInventoryId"); err != nil {
		return nil, err
	}
	if record["normalizedKind"] != testevidenceinventory.NormalizedInventoryKind {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory normalizedKind must be %s", testevidenceinventory.NormalizedInventoryKind)
	}
	sourceAuthority, err := admit.Enum(record["sourceAuthority"], map[string]struct{}{"caller_owned_inventory": {}, "caller_owned_inventory_source_set": {}}, "requirement coverage view normalizedTestEvidenceInventory sourceAuthority")
	if err != nil {
		return nil, err
	}
	sourceCount, err := nonNegativeInt(record["sourceCount"], "requirement coverage view normalizedTestEvidenceInventory sourceCount")
	if err != nil {
		return nil, err
	}
	if err := exactTextArray(record["sourceColumns"], []string{"source_id", "path", "sha256", "role", "non_claims"}, "requirement coverage view normalizedTestEvidenceInventory sourceColumns"); err != nil {
		return nil, err
	}
	sourcePaths, sourcePathsByID, err := provenanceSources(record["sources"])
	if err != nil {
		return nil, err
	}
	if sourceCount != len(sourcePaths) {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory sourceCount must equal sources length")
	}
	inputPaths, err := admit.PreserveSortedPathArray(record["inputPaths"], "requirement coverage view normalizedTestEvidenceInventory inputPaths", true)
	if err != nil {
		return nil, err
	}
	if !equalStringSets(inputPaths, sourcePaths) {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory inputPaths must equal source paths")
	}
	if _, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement coverage view normalizedTestEvidenceInventory nonClaims", false); err != nil {
		return nil, err
	}
	inventoryResult, err := testevidenceinventory.Evaluate(record["inventory"])
	if err != nil {
		return nil, err
	}
	entrySources, err := provenanceEntrySources(record["entrySources"], sourcePathsByID)
	if err != nil {
		return nil, err
	}
	if sourceAuthority == "caller_owned_inventory_source_set" {
		if len(sourcePaths) == 0 {
			return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory source-set provenance must declare sources")
		}
		if err := requireEntrySourceCoverage(entrySources, inventoryResult.Inventory.Entries); err != nil {
			return nil, err
		}
	}
	if sourceAuthority == "caller_owned_inventory" && (len(sourcePaths) > 0 || len(entrySources) > 0) {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory direct inventory provenance must not declare source-set metadata")
	}
	if directInventory != nil && !reflect.DeepEqual(record["inventory"], directInventory) {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory inventory must match testEvidenceInventory")
	}
	if record["projectionKind"] != nil {
		if _, err := admit.RuleID(record["projectionKind"], "requirement coverage view normalizedTestEvidenceInventory projectionKind"); err != nil {
			return nil, err
		}
	}
	if record["projectionSummary"] != nil {
		if _, ok := record["projectionSummary"].(map[string]any); !ok {
			return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory projectionSummary must be an object when present")
		}
	}
	return &inventoryResult, nil
}

type provenanceEntrySource struct {
	Path     string
	SourceID string
	TestID   string
}

func provenanceSources(raw any) ([]string, map[string]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory sources must be an array")
	}
	paths := []string{}
	pathsByID := map[string]string{}
	sourceIDs := []string{}
	for index, value := range values {
		row, ok := value.([]any)
		if !ok || len(row) != 5 {
			return nil, nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory source row #%d must match sourceColumns", index+1)
		}
		sourceID, err := admit.RuleID(row[0], "requirement coverage view normalizedTestEvidenceInventory source source_id")
		if err != nil {
			return nil, nil, err
		}
		pathText, err := admit.NonEmptyText(row[1], "requirement coverage view normalizedTestEvidenceInventory source path")
		if err != nil {
			return nil, nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, "requirement coverage view normalizedTestEvidenceInventory source path")
		if err != nil {
			return nil, nil, err
		}
		if _, err := admit.LowercaseSHA256(row[2], "requirement coverage view normalizedTestEvidenceInventory source sha256"); err != nil {
			return nil, nil, err
		}
		if _, err := admit.Enum(row[3], map[string]struct{}{"test_evidence_inventory_contract": {}, "test_evidence_inventory_fragment": {}}, "requirement coverage view normalizedTestEvidenceInventory source role"); err != nil {
			return nil, nil, err
		}
		if _, err := admit.PreserveSortedTextArray(row[4], "requirement coverage view normalizedTestEvidenceInventory source non_claims", false); err != nil {
			return nil, nil, err
		}
		sourceIDs = append(sourceIDs, sourceID)
		paths = append(paths, pathValue)
		pathsByID[sourceID] = pathValue
	}
	if _, err := admit.PreserveSortedText(sourceIDs, "requirement coverage view normalizedTestEvidenceInventory source ids", true); err != nil {
		return nil, nil, err
	}
	if _, err := admit.SortedText(paths, "requirement coverage view normalizedTestEvidenceInventory source paths", true); err != nil {
		return nil, nil, err
	}
	return paths, pathsByID, nil
}

func provenanceEntrySources(raw any, sourcePathsByID map[string]string) ([]provenanceEntrySource, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory entrySources must be an array")
	}
	result := make([]provenanceEntrySource, 0, len(values))
	testIDs := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory entrySources item #%d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"path", "sourceId", "testId"}, "requirement coverage view normalizedTestEvidenceInventory entrySources item"); err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], "requirement coverage view normalizedTestEvidenceInventory entrySources path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, "requirement coverage view normalizedTestEvidenceInventory entrySources path")
		if err != nil {
			return nil, err
		}
		sourceID, err := admit.RuleID(record["sourceId"], "requirement coverage view normalizedTestEvidenceInventory entrySources sourceId")
		if err != nil {
			return nil, err
		}
		sourcePath, ok := sourcePathsByID[sourceID]
		if !ok {
			return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory entrySources sourceId %s must reference sources", sourceID)
		}
		if sourcePath != pathValue {
			return nil, fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory entrySources path must match source path for %s", sourceID)
		}
		testID, err := admit.RuleID(record["testId"], "requirement coverage view normalizedTestEvidenceInventory entrySources testId")
		if err != nil {
			return nil, err
		}
		testIDs = append(testIDs, testID)
		result = append(result, provenanceEntrySource{Path: pathValue, SourceID: sourceID, TestID: testID})
	}
	if _, err := admit.PreserveSortedText(testIDs, "requirement coverage view normalizedTestEvidenceInventory entrySources testIds", true); err != nil {
		return nil, err
	}
	return result, nil
}

func requireEntrySourceCoverage(entrySources []provenanceEntrySource, entries []testevidenceinventory.Entry) error {
	covered := map[string]struct{}{}
	for _, entrySource := range entrySources {
		covered[entrySource.TestID] = struct{}{}
	}
	entrySet := map[string]struct{}{}
	for _, entry := range entries {
		entrySet[entry.TestID] = struct{}{}
		if _, ok := covered[entry.TestID]; !ok {
			return fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory entrySources must cover every nested inventory entry")
		}
	}
	for _, entrySource := range entrySources {
		if _, ok := entrySet[entrySource.TestID]; !ok {
			return fmt.Errorf("requirement coverage view normalizedTestEvidenceInventory entrySources must reference nested inventory entries")
		}
	}
	return nil
}

func exactTextArray(raw any, expected []string, context string) error {
	values, ok := raw.([]any)
	if !ok || len(values) != len(expected) {
		return fmt.Errorf("%s must equal %v", context, expected)
	}
	for index, value := range values {
		text, ok := value.(string)
		if !ok || text != expected[index] {
			return fmt.Errorf("%s must equal %v", context, expected)
		}
	}
	return nil
}

func nonNegativeInt(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	value, err := number.Int64()
	if err != nil || value < 0 || int64(int(value)) != value {
		return 0, fmt.Errorf("%s must be a non-negative integer", context)
	}
	return int(value), nil
}

func equalStringSets(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
	if err := admit.KnownKeys(record, []string{"scope"}, "requirement coverage view options"); err != nil {
		return err
	}
	if _, ok := record["scope"]; ok {
		if _, err := admit.RuleID(record["scope"], "requirement coverage view options scope"); err != nil {
			return err
		}
	}
	return nil
}
