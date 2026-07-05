package requirementcoverageinput

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

const NormalizedInventoryKind = "proofkit.test-evidence-inventory.normalized"

var normalizedSourceColumns = []string{"source_id", "path", "sha256", "role", "non_claims"}
var normalizedSourceRoles = map[string]struct{}{
	"test_evidence_inventory_contract": {},
	"test_evidence_inventory_fragment": {},
}

type input struct {
	CompactProofContract    any
	CoverageUniverse        universe
	LocalEnvironmentPolicy  any
	NormalizedInventory     normalizedInventory
	Options                 any
	OwnerInvariantRegistry  any
	RequirementProofBinding any
	RequirementSource       any
	SelectedOwnerIDs        []string
	ViewInputID             string
}

type normalizedInventory struct {
	Envelope  map[string]any
	Inventory map[string]any
	Result    testevidenceinventory.Result
}

type universe struct {
	Authority               string
	CodeSurfaces            []surface
	CommandRefs             []string
	CompletenessDeclaration string
	NonClaims               []string
	OwnerIDs                []string
	SpecSurfaces            []surface
	TestSurfaces            []surface
	UniverseID              string
}

type surface struct {
	OwnerID   string
	Path      string
	SurfaceID string
}

type normalizedSource struct {
	NonClaims []string
	Path      string
	Role      string
	SHA256    string
	SourceID  string
}

type normalizedEntrySource struct {
	Path     string
	SourceID string
	TestID   string
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
	if _, _, err := requirementcoverageview.BuildJSON(output, requirementcoverageview.Options{}); err != nil {
		return nil, 1, err
	}
	return output, 0, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("requirement coverage input compose input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"compactProofContract", "composerInputId", "coverageUniverse", "localEnvironmentPolicy", "normalizedTestEvidenceInventory", "options", "ownerInvariantRegistry", "requirementProofBinding", "requirementSource", "schemaVersion", "selectedOwnerIds", "testEvidenceInventory", "viewInputId"}, "requirement coverage input compose input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("requirement coverage input compose schemaVersion must be 1")
	}
	if _, err := admit.RuleID(record["composerInputId"], "requirement coverage input compose composerInputId"); err != nil {
		return input{}, err
	}
	viewInputID, err := admit.RuleID(record["viewInputId"], "requirement coverage input compose viewInputId")
	if err != nil {
		return input{}, err
	}
	selectedOwnerIDs, err := sortedRuleIDs(record["selectedOwnerIds"], "requirement coverage input compose selectedOwnerIds", false)
	if err != nil {
		return input{}, err
	}
	source, err := requirementsourceadmission.Evaluate(record["requirementSource"])
	if err != nil {
		return input{}, err
	}
	if source.ExitCode != 0 {
		return input{}, fmt.Errorf("requirement coverage input compose requires passed requirement source admission")
	}
	proofBinding, compactContract, normalized, err := admitProofAndInventory(record)
	if err != nil {
		return input{}, err
	}
	universe, err := admitUniverse(record["coverageUniverse"])
	if err != nil {
		return input{}, err
	}
	if !equalStrings(selectedOwnerIDs, universe.OwnerIDs) {
		return input{}, fmt.Errorf("requirement coverage input compose selectedOwnerIds must equal coverageUniverse ownerIds")
	}
	ownerSet := mapSet(selectedOwnerIDs)
	for _, entry := range normalized.Result.Inventory.Entries {
		if _, ok := ownerSet[entry.OwnerID]; !ok {
			return input{}, fmt.Errorf("requirement coverage input compose inventory entry %s ownerId %s is outside selectedOwnerIds", entry.TestID, entry.OwnerID)
		}
	}
	return input{
		CompactProofContract:    compactContract,
		CoverageUniverse:        universe,
		LocalEnvironmentPolicy:  record["localEnvironmentPolicy"],
		NormalizedInventory:     normalized,
		Options:                 record["options"],
		OwnerInvariantRegistry:  record["ownerInvariantRegistry"],
		RequirementProofBinding: proofBinding,
		RequirementSource:       record["requirementSource"],
		SelectedOwnerIDs:        selectedOwnerIDs,
		ViewInputID:             viewInputID,
	}, nil
}

func admitProofAndInventory(record map[string]any) (any, any, normalizedInventory, error) {
	normalizedRaw, hasNormalized := record["normalizedTestEvidenceInventory"]
	directRaw, hasDirectInventory := record["testEvidenceInventory"]
	if hasNormalized == hasDirectInventory {
		return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose must provide exactly one of normalizedTestEvidenceInventory or testEvidenceInventory")
	}
	if hasNormalized {
		if _, hasDirectProof := record["requirementProofBinding"]; hasDirectProof {
			return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose normalized mode must not provide requirementProofBinding")
		}
		if _, err := compactproofcontract.Admit(record["compactProofContract"]); err != nil {
			return nil, nil, normalizedInventory{}, err
		}
		normalized, err := admitNormalizedInventory(normalizedRaw)
		if err != nil {
			return nil, nil, normalizedInventory{}, err
		}
		return nil, record["compactProofContract"], normalized, nil
	}
	if _, hasCompact := record["compactProofContract"]; hasCompact {
		return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose direct mode must not provide compactProofContract")
	}
	proofRaw, ok := record["requirementProofBinding"]
	if !ok {
		return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose direct mode requires requirementProofBinding")
	}
	proofResult, err := requirementbinding.Build(proofRaw)
	if err != nil {
		return nil, nil, normalizedInventory{}, err
	}
	if proofResult.Record.State != "passed" {
		return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose requires passed requirement proof binding admission")
	}
	inventoryResult, err := testevidenceinventory.Evaluate(directRaw)
	if err != nil {
		return nil, nil, normalizedInventory{}, err
	}
	if inventoryResult.ExitCode != 0 {
		return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose requires passed test evidence inventory admission")
	}
	if inventoryResult.Inventory.Authority != "caller_owned_inventory" {
		return nil, nil, normalizedInventory{}, fmt.Errorf("requirement coverage input compose direct mode requires caller_owned_inventory; use normalizedTestEvidenceInventory for source-set inventory")
	}
	return requirementbinding.InputValue(proofResult.Input), nil, normalizedInventory{Inventory: testevidenceinventory.InventoryValue(inventoryResult.Inventory), Result: inventoryResult}, nil
}

func admitNormalizedInventory(raw any) (normalizedInventory, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory must be an object")
	}
	if err := admit.KnownKeys(record, []string{"entrySources", "inputPaths", "inventory", "nonClaims", "normalizedInventoryId", "normalizedKind", "projectionKind", "projectionSummary", "schemaVersion", "sourceAuthority", "sourceColumns", "sourceCount", "sources"}, "normalizedTestEvidenceInventory"); err != nil {
		return normalizedInventory{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory schemaVersion must be 1")
	}
	if record["normalizedKind"] != NormalizedInventoryKind {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory normalizedKind must be %s", NormalizedInventoryKind)
	}
	if _, err := admit.RuleID(record["normalizedInventoryId"], "normalizedTestEvidenceInventory normalizedInventoryId"); err != nil {
		return normalizedInventory{}, err
	}
	sourceAuthority, err := admit.Enum(record["sourceAuthority"], map[string]struct{}{"caller_owned_inventory": {}, "caller_owned_inventory_source_set": {}}, "normalizedTestEvidenceInventory sourceAuthority")
	if err != nil {
		return normalizedInventory{}, err
	}
	sourceCount, err := nonNegativeInteger(record["sourceCount"], "normalizedTestEvidenceInventory sourceCount")
	if err != nil {
		return normalizedInventory{}, err
	}
	if err := admitExactTextArray(record["sourceColumns"], normalizedSourceColumns, "normalizedTestEvidenceInventory sourceColumns"); err != nil {
		return normalizedInventory{}, err
	}
	sources, err := admitNormalizedSources(record["sources"])
	if err != nil {
		return normalizedInventory{}, err
	}
	if sourceCount != len(sources) {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory sourceCount must equal sources length")
	}
	inputPaths, err := admit.PreserveSortedPathArray(record["inputPaths"], "normalizedTestEvidenceInventory inputPaths", true)
	if err != nil {
		return normalizedInventory{}, err
	}
	if !equalStrings(inputPaths, sourcePaths(sources)) {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory inputPaths must equal source paths")
	}
	inventory, ok := record["inventory"].(map[string]any)
	if !ok {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory inventory must be an object")
	}
	result, err := testevidenceinventory.Evaluate(inventory)
	if err != nil {
		return normalizedInventory{}, err
	}
	if result.ExitCode != 0 {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory nested inventory must pass test-evidence-inventory admission")
	}
	if result.Inventory.Authority != "caller_owned_inventory" {
		return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory nested inventory authority must be caller_owned_inventory")
	}
	entrySources, err := admitNormalizedEntrySources(record["entrySources"])
	if err != nil {
		return normalizedInventory{}, err
	}
	if err := validateSourceEnvelope(sourceAuthority, sources, inputPaths, entrySources, result.Inventory.Entries); err != nil {
		return normalizedInventory{}, err
	}
	if _, err := admit.PreserveSortedTextArray(record["nonClaims"], "normalizedTestEvidenceInventory nonClaims", false); err != nil {
		return normalizedInventory{}, err
	}
	if record["projectionKind"] != nil {
		if _, err := admit.RuleID(record["projectionKind"], "normalizedTestEvidenceInventory projectionKind"); err != nil {
			return normalizedInventory{}, err
		}
	}
	if record["projectionSummary"] != nil {
		if _, ok := record["projectionSummary"].(map[string]any); !ok {
			return normalizedInventory{}, fmt.Errorf("normalizedTestEvidenceInventory projectionSummary must be an object when present")
		}
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "normalizedTestEvidenceInventory nonClaims", false)
	if err != nil {
		return normalizedInventory{}, err
	}
	envelope := map[string]any{
		"schemaVersion":         json.Number("1"),
		"normalizedInventoryId": record["normalizedInventoryId"],
		"normalizedKind":        record["normalizedKind"],
		"sourceAuthority":       sourceAuthority,
		"sourceCount":           json.Number(fmt.Sprintf("%d", sourceCount)),
		"sourceColumns":         admit.StringSliceToAny(normalizedSourceColumns),
		"sources":               normalizedSourcesValue(sources),
		"entrySources":          normalizedEntrySourcesValue(entrySources),
		"inputPaths":            admit.StringSliceToAny(inputPaths),
		"inventory":             testevidenceinventory.InventoryValue(result.Inventory),
		"nonClaims":             admit.StringSliceToAny(nonClaims),
	}
	if record["projectionKind"] != nil {
		envelope["projectionKind"] = record["projectionKind"]
	}
	if record["projectionSummary"] != nil {
		envelope["projectionSummary"] = record["projectionSummary"]
	}
	return normalizedInventory{Envelope: envelope, Inventory: testevidenceinventory.InventoryValue(result.Inventory), Result: result}, nil
}

func admitNormalizedSources(raw any) ([]normalizedSource, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("normalizedTestEvidenceInventory sources must be an array")
	}
	result := make([]normalizedSource, 0, len(values))
	ids := []string{}
	paths := []string{}
	for index, value := range values {
		row, ok := value.([]any)
		if !ok || len(row) != len(normalizedSourceColumns) {
			return nil, fmt.Errorf("normalizedTestEvidenceInventory sources row #%d must match sourceColumns", index+1)
		}
		sourceID, err := admit.RuleID(row[0], "normalizedTestEvidenceInventory source source_id")
		if err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(row[1], "normalizedTestEvidenceInventory source path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, "normalizedTestEvidenceInventory source path")
		if err != nil {
			return nil, err
		}
		sha, err := admit.LowercaseSHA256(row[2], "normalizedTestEvidenceInventory source sha256")
		if err != nil {
			return nil, err
		}
		role, err := admit.RuleID(row[3], "normalizedTestEvidenceInventory source role")
		if err != nil {
			return nil, err
		}
		if _, ok := normalizedSourceRoles[role]; !ok {
			return nil, fmt.Errorf("normalizedTestEvidenceInventory source role must be test_evidence_inventory_contract or test_evidence_inventory_fragment")
		}
		nonClaims, err := admit.PreserveSortedTextArray(row[4], "normalizedTestEvidenceInventory source non_claims", false)
		if err != nil {
			return nil, err
		}
		result = append(result, normalizedSource{NonClaims: nonClaims, Path: pathValue, Role: role, SHA256: sha, SourceID: sourceID})
		ids = append(ids, sourceID)
		paths = append(paths, pathValue)
	}
	if _, err := admit.PreserveSortedText(ids, "normalizedTestEvidenceInventory source ids", true); err != nil {
		return nil, err
	}
	if _, err := admit.SortedText(paths, "normalizedTestEvidenceInventory source paths", true); err != nil {
		return nil, err
	}
	return result, nil
}

func admitNormalizedEntrySources(raw any) ([]normalizedEntrySource, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("normalizedTestEvidenceInventory entrySources must be an array")
	}
	result := make([]normalizedEntrySource, 0, len(values))
	testIDs := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("normalizedTestEvidenceInventory entrySources item #%d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"path", "sourceId", "testId"}, "normalizedTestEvidenceInventory entrySources item"); err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], "normalizedTestEvidenceInventory entrySources path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, "normalizedTestEvidenceInventory entrySources path")
		if err != nil {
			return nil, err
		}
		sourceID, err := admit.RuleID(record["sourceId"], "normalizedTestEvidenceInventory entrySources sourceId")
		if err != nil {
			return nil, err
		}
		testID, err := admit.RuleID(record["testId"], "normalizedTestEvidenceInventory entrySources testId")
		if err != nil {
			return nil, err
		}
		result = append(result, normalizedEntrySource{Path: pathValue, SourceID: sourceID, TestID: testID})
		testIDs = append(testIDs, testID)
	}
	if _, err := admit.PreserveSortedText(testIDs, "normalizedTestEvidenceInventory entrySources testIds", true); err != nil {
		return nil, err
	}
	return result, nil
}

func validateSourceEnvelope(sourceAuthority string, sources []normalizedSource, inputPaths []string, entrySources []normalizedEntrySource, entries []testevidenceinventory.Entry) error {
	if sourceAuthority == "caller_owned_inventory" {
		if len(sources) != 0 || len(inputPaths) != 0 || len(entrySources) != 0 {
			return fmt.Errorf("normalizedTestEvidenceInventory direct inventory envelope must not declare source-set metadata")
		}
		return nil
	}
	if sourceAuthority != "caller_owned_inventory_source_set" {
		return fmt.Errorf("normalizedTestEvidenceInventory sourceAuthority is unsupported")
	}
	if len(sources) == 0 {
		return fmt.Errorf("normalizedTestEvidenceInventory source-set envelope must declare sources")
	}
	if len(entrySources) != len(entries) {
		return fmt.Errorf("normalizedTestEvidenceInventory entrySources must cover every nested inventory entry")
	}
	sourceSet := map[string]string{}
	for _, source := range sources {
		sourceSet[source.SourceID] = source.Path
	}
	entrySet := map[string]struct{}{}
	for _, entry := range entries {
		entrySet[entry.TestID] = struct{}{}
	}
	for _, entrySource := range entrySources {
		path, ok := sourceSet[entrySource.SourceID]
		if !ok {
			return fmt.Errorf("normalizedTestEvidenceInventory entrySources sourceId %s must reference sources", entrySource.SourceID)
		}
		if path != entrySource.Path {
			return fmt.Errorf("normalizedTestEvidenceInventory entrySources path must match source path for %s", entrySource.SourceID)
		}
		if _, ok := entrySet[entrySource.TestID]; !ok {
			return fmt.Errorf("normalizedTestEvidenceInventory entrySources testId %s must reference nested inventory entries", entrySource.TestID)
		}
		delete(entrySet, entrySource.TestID)
	}
	if len(entrySet) != 0 {
		return fmt.Errorf("normalizedTestEvidenceInventory entrySources must cover every nested inventory entry")
	}
	return nil
}

func admitUniverse(raw any) (universe, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return universe{}, fmt.Errorf("coverageUniverse must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority", "codeSurfaces", "commandRefs", "completenessDeclaration", "nonClaims", "ownerIds", "schemaVersion", "specSurfaces", "testSurfaces", "universeId"}, "coverageUniverse"); err != nil {
		return universe{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return universe{}, fmt.Errorf("coverageUniverse schemaVersion must be 1")
	}
	if record["authority"] != "caller_owned_inventory" {
		return universe{}, fmt.Errorf("coverageUniverse authority must be caller_owned_inventory")
	}
	universeID, err := admit.RuleID(record["universeId"], "coverageUniverse universeId")
	if err != nil {
		return universe{}, err
	}
	completeness, err := admit.Enum(record["completenessDeclaration"], map[string]struct{}{"full_repository": {}, "selected_owner_surfaces": {}, "selected_paths_advisory": {}}, "coverageUniverse completenessDeclaration")
	if err != nil {
		return universe{}, err
	}
	ownerIDs, err := sortedRuleIDs(record["ownerIds"], "coverageUniverse ownerIds", false)
	if err != nil {
		return universe{}, err
	}
	ownerSet := mapSet(ownerIDs)
	codeSurfaces, err := admitSurfaces(record["codeSurfaces"], "coverageUniverse codeSurfaces", ownerSet)
	if err != nil {
		return universe{}, err
	}
	specSurfaces, err := admitSurfaces(record["specSurfaces"], "coverageUniverse specSurfaces", ownerSet)
	if err != nil {
		return universe{}, err
	}
	testSurfaces, err := admitSurfaces(record["testSurfaces"], "coverageUniverse testSurfaces", ownerSet)
	if err != nil {
		return universe{}, err
	}
	commandRefs, err := sortedRuleIDs(record["commandRefs"], "coverageUniverse commandRefs", true)
	if err != nil {
		return universe{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "coverageUniverse nonClaims", false)
	if err != nil {
		return universe{}, err
	}
	return universe{
		Authority:               "caller_owned_inventory",
		CodeSurfaces:            codeSurfaces,
		CommandRefs:             commandRefs,
		CompletenessDeclaration: completeness,
		NonClaims:               nonClaims,
		OwnerIDs:                ownerIDs,
		SpecSurfaces:            specSurfaces,
		TestSurfaces:            testSurfaces,
		UniverseID:              universeID,
	}, nil
}

func admitSurfaces(raw any, context string, ownerSet map[string]struct{}) ([]surface, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]surface, 0, len(values))
	ids := map[string]surface{}
	pairs := map[string]string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s item #%d must be an object", context, index+1)
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
		if _, ok := ownerSet[ownerID]; !ok {
			return nil, fmt.Errorf("%s ownerId %s must reference coverageUniverse ownerIds", context, ownerID)
		}
		pathText, err := admit.NonEmptyText(record["path"], context+" path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, context+" path")
		if err != nil {
			return nil, err
		}
		item := surface{OwnerID: ownerID, Path: pathValue, SurfaceID: surfaceID}
		if previous, ok := ids[surfaceID]; ok {
			return nil, fmt.Errorf("%s duplicate surfaceId %s for %s and %s", context, surfaceID, previous.Path, pathValue)
		}
		pairKey := ownerID + "\x00" + pathValue
		if previous, ok := pairs[pairKey]; ok {
			return nil, fmt.Errorf("%s duplicate owner/path surface %s and %s", context, previous, surfaceID)
		}
		ids[surfaceID] = item
		pairs[pairKey] = surfaceID
		result = append(result, item)
	}
	sortSurfaces(result)
	return result, nil
}

func compose(input input) (map[string]any, error) {
	universe, err := mergeUniverse(input.CoverageUniverse, input.NormalizedInventory.Result.Inventory.Entries)
	if err != nil {
		return nil, err
	}
	output := map[string]any{
		"schemaVersion":           json.Number("1"),
		"viewInputId":             input.ViewInputID,
		"requirementSource":       input.RequirementSource,
		"requirementProofBinding": input.RequirementProofBinding,
		"compactProofContract":    input.CompactProofContract,
		"ownerInvariantRegistry":  input.OwnerInvariantRegistry,
		"coverageUniverse":        universeValue(universe),
		"testEvidenceInventory":   input.NormalizedInventory.Inventory,
		"localEnvironmentPolicy":  input.LocalEnvironmentPolicy,
		"options":                 input.Options,
	}
	if input.NormalizedInventory.Envelope != nil {
		output["normalizedTestEvidenceInventory"] = input.NormalizedInventory.Envelope
	}
	return output, nil
}

func mergeUniverse(base universe, entries []testevidenceinventory.Entry) (universe, error) {
	out := base
	commandRefs := append([]string{}, base.CommandRefs...)
	for _, entry := range entries {
		commandRefs = append(commandRefs, entry.CommandRefs...)
	}
	out.CommandRefs = sortedUnique(commandRefs)
	testSurfaces, err := mergeObservedTestSurfaces(base.TestSurfaces, entries)
	if err != nil {
		return universe{}, err
	}
	out.TestSurfaces = testSurfaces
	return out, nil
}

func mergeObservedTestSurfaces(declared []surface, entries []testevidenceinventory.Entry) ([]surface, error) {
	result := append([]surface{}, declared...)
	byPair := map[string]surface{}
	byID := map[string]surface{}
	for _, item := range result {
		byPair[item.OwnerID+"\x00"+item.Path] = item
		byID[item.SurfaceID] = item
	}
	for _, entry := range entries {
		pair := entry.OwnerID + "\x00" + entry.SourcePath
		if _, ok := byPair[pair]; ok {
			continue
		}
		surfaceID := observedTestSurfaceID(entry.OwnerID, entry.SourcePath)
		if previous, ok := byID[surfaceID]; ok && (previous.OwnerID != entry.OwnerID || previous.Path != entry.SourcePath) {
			return nil, fmt.Errorf("requirement coverage input compose observed test surface id collision: %s", surfaceID)
		}
		item := surface{OwnerID: entry.OwnerID, Path: entry.SourcePath, SurfaceID: surfaceID}
		byPair[pair] = item
		byID[surfaceID] = item
		result = append(result, item)
	}
	sortSurfaces(result)
	return result, nil
}

func universeValue(value universe) map[string]any {
	return map[string]any{
		"schemaVersion":           json.Number("1"),
		"universeId":              value.UniverseID,
		"authority":               value.Authority,
		"completenessDeclaration": value.CompletenessDeclaration,
		"ownerIds":                admit.StringSliceToAny(value.OwnerIDs),
		"codeSurfaces":            surfacesValue(value.CodeSurfaces),
		"specSurfaces":            surfacesValue(value.SpecSurfaces),
		"testSurfaces":            surfacesValue(value.TestSurfaces),
		"commandRefs":             admit.StringSliceToAny(value.CommandRefs),
		"nonClaims":               admit.StringSliceToAny(value.NonClaims),
	}
}

func surfacesValue(values []surface) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"surfaceId": value.SurfaceID,
			"ownerId":   value.OwnerID,
			"path":      value.Path,
		})
	}
	return result
}

func normalizedSourcesValue(values []normalizedSource) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, []any{
			value.SourceID,
			value.Path,
			value.SHA256,
			value.Role,
			admit.StringSliceToAny(value.NonClaims),
		})
	}
	return result
}

func normalizedEntrySourcesValue(values []normalizedEntrySource) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"path":     value.Path,
			"sourceId": value.SourceID,
			"testId":   value.TestID,
		})
	}
	return result
}

func observedTestSurfaceID(ownerID string, sourcePath string) string {
	sum := sha256.Sum256([]byte(ownerID + "\x00" + sourcePath))
	return "surface.observed_test." + ruleFragment(ownerID) + "." + letters(sum[:8])
}

func letters(raw []byte) string {
	var builder strings.Builder
	for _, value := range raw {
		builder.WriteByte('a' + (value >> 4))
		builder.WriteByte('a' + (value & 0x0f))
	}
	return builder.String()
}

func ruleFragment(value string) string {
	var builder strings.Builder
	lastUnderscore := false
	for _, item := range strings.ToLower(value) {
		if unicode.IsLetter(item) || unicode.IsDigit(item) {
			builder.WriteRune(item)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	fragment := strings.Trim(builder.String(), "_")
	if fragment == "" || !unicode.IsLetter(rune(fragment[0])) {
		return "id_" + fragment
	}
	return fragment
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		value, err := admit.RuleID(item, context)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return admit.PreserveSortedText(result, context, allowEmpty)
}

func nonNegativeInteger(raw any, context string) (int, error) {
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

func admitExactTextArray(raw any, expected []string, context string) error {
	values, err := admit.TextArray(raw, context, false)
	if err != nil {
		return err
	}
	if !equalStrings(values, expected) {
		return fmt.Errorf("%s must equal %s", context, strings.Join(expected, ", "))
	}
	return nil
}

func sourcePaths(values []normalizedSource) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Path)
	}
	sort.Strings(result)
	return result
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
			previous = value
		}
	}
	return append([]string{}, result...)
}

func sortSurfaces(values []surface) {
	sort.Slice(values, func(left, right int) bool {
		return values[left].SurfaceID < values[right].SurfaceID
	})
}

func equalStrings(left []string, right []string) bool {
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

func mapSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
