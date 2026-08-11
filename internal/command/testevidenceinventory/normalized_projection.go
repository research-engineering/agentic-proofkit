package testevidenceinventory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

const ProofBindingProjectionKind = "proofkit.proof-binding-test-inventory"

var proofBindingEntryNonClaims = []string{
	"This inventory entry does not execute native tests or authenticate receipts.",
	"This inventory entry projects proof-route wiring only and cannot satisfy semantic coverage.",
}

// ProofBindingTestID owns the stable inventory identity derived from a compact
// falsification witness route. Both the producer and normalized re-admission use
// this function so a synchronized mapping/entry mutation cannot fabricate an ID.
func ProofBindingTestID(witnessRouteID string) (string, error) {
	witnessRouteID, err := admit.SHA256Ref(witnessRouteID, "proof-binding test inventory witnessRouteId")
	if err != nil {
		return "", err
	}
	fragment := strings.NewReplacer(
		"0", "g", "1", "h", "2", "i", "3", "j", "4", "k",
		"5", "l", "6", "m", "7", "n", "8", "o", "9", "p",
	).Replace(strings.TrimPrefix(witnessRouteID, "sha256:"))
	return admit.RuleID("test.proof_route."+fragment, "proof-binding test inventory derived testId")
}

func ProofBindingEntryNonClaims() []string {
	return append([]string{}, proofBindingEntryNonClaims...)
}

// NormalizedProjection is the owner-owned projection used by downstream
// commands that need the flattened direct inventory and its source-set envelope.
type NormalizedProjection struct {
	Envelope  map[string]any
	Inventory map[string]any
	Result    Result
}

func AdmitNormalizedProjection(raw any, directInventory any, context string) (NormalizedProjection, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return NormalizedProjection{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"entrySources", "inputPaths", "inventory", "nonClaims", "normalizedInventoryId", "normalizedKind", "projectionKind", "projectionSummary", "schemaVersion", "sourceAuthority", "sourceColumns", "sourceCount", "sources"}, context); err != nil {
		return NormalizedProjection{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return NormalizedProjection{}, fmt.Errorf("%s schemaVersion must be 1", context)
	}
	if record["normalizedKind"] != NormalizedInventoryKind {
		return NormalizedProjection{}, fmt.Errorf("%s normalizedKind must be %s", context, NormalizedInventoryKind)
	}
	if _, err := admit.RuleID(record["normalizedInventoryId"], context+" normalizedInventoryId"); err != nil {
		return NormalizedProjection{}, err
	}
	sourceAuthority, err := admit.Enum(record["sourceAuthority"], map[string]struct{}{directAuthority: {}, sourceSetAuthority: {}}, context+" sourceAuthority")
	if err != nil {
		return NormalizedProjection{}, err
	}
	sourceCount, err := nonNegativeInteger(record["sourceCount"], context+" sourceCount")
	if err != nil {
		return NormalizedProjection{}, err
	}
	if err := exactTextArray(record["sourceColumns"], sourceSetColumns, context+" sourceColumns"); err != nil {
		return NormalizedProjection{}, err
	}
	sources, err := admitNormalizedSources(record["sources"], context)
	if err != nil {
		return NormalizedProjection{}, err
	}
	if sourceCount != len(sources) {
		return NormalizedProjection{}, fmt.Errorf("%s sourceCount must equal sources length", context)
	}
	inputPaths, err := admit.PreserveSortedPathArray(record["inputPaths"], context+" inputPaths", true)
	if err != nil {
		return NormalizedProjection{}, err
	}
	if !equalStrings(inputPaths, sourcePaths(sources)) {
		return NormalizedProjection{}, fmt.Errorf("%s inputPaths must equal source paths", context)
	}
	inventory, ok := record["inventory"].(map[string]any)
	if !ok {
		return NormalizedProjection{}, fmt.Errorf("%s inventory must be an object", context)
	}
	result, err := Evaluate(inventory)
	if err != nil {
		return NormalizedProjection{}, err
	}
	if result.ExitCode != 0 {
		return NormalizedProjection{}, fmt.Errorf("%s nested inventory must pass test-evidence-inventory admission", context)
	}
	if result.Inventory.Authority != directAuthority {
		return NormalizedProjection{}, fmt.Errorf("%s nested inventory authority must be %s", context, directAuthority)
	}
	entrySources, err := admitNormalizedEntrySources(record["entrySources"], context)
	if err != nil {
		return NormalizedProjection{}, err
	}
	if err := validateSourceEnvelope(sourceAuthority, sources, inputPaths, entrySources, result.Inventory.Entries, context); err != nil {
		return NormalizedProjection{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], context+" nonClaims", false)
	if err != nil {
		return NormalizedProjection{}, err
	}
	if directInventory != nil && !reflect.DeepEqual(record["inventory"], directInventory) {
		return NormalizedProjection{}, fmt.Errorf("%s inventory must match testEvidenceInventory", context)
	}
	projectionKind := ""
	if record["projectionKind"] != nil {
		projectionKind, err = admit.RuleID(record["projectionKind"], context+" projectionKind")
		if err != nil {
			return NormalizedProjection{}, err
		}
	}
	if (projectionKind == "") != (record["projectionSummary"] == nil) {
		return NormalizedProjection{}, fmt.Errorf("%s projectionKind and projectionSummary must be present together", context)
	}
	var projectionSummary map[string]any
	if projectionKind != "" {
		if projectionKind != ProofBindingProjectionKind {
			return NormalizedProjection{}, fmt.Errorf("%s projectionKind is unsupported", context)
		}
		projectionSummary, err = admitProofBindingProjectionSummary(record["projectionSummary"], result.Inventory.Entries, context+" projectionSummary")
		if err != nil {
			return NormalizedProjection{}, err
		}
	}
	envelope := map[string]any{
		"schemaVersion":         json.Number("1"),
		"normalizedInventoryId": record["normalizedInventoryId"],
		"normalizedKind":        record["normalizedKind"],
		"sourceAuthority":       sourceAuthority,
		"sourceCount":           json.Number(fmt.Sprintf("%d", sourceCount)),
		"sourceColumns":         admit.StringSliceToAny(sourceSetColumns),
		"sources":               sourceRowsToAny(sources),
		"entrySources":          entrySourcesToAny(entrySources),
		"inputPaths":            admit.StringSliceToAny(inputPaths),
		"inventory":             InventoryValue(result.Inventory),
		"nonClaims":             admit.StringSliceToAny(nonClaims),
	}
	if projectionKind != "" {
		envelope["projectionKind"] = projectionKind
	}
	if projectionSummary != nil {
		envelope["projectionSummary"] = projectionSummary
	}
	return NormalizedProjection{Envelope: envelope, Inventory: InventoryValue(result.Inventory), Result: result}, nil
}

func admitProofBindingProjectionSummary(raw any, entries []Entry, context string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"commandRefCount", "entryCount", "routeEntryMappings", "schemaVersion"}, context); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 2) {
		return nil, fmt.Errorf("%s schemaVersion must be 2", context)
	}
	entryCount, err := nonNegativeInteger(record["entryCount"], context+" entryCount")
	if err != nil {
		return nil, err
	}
	if entryCount != len(entries) {
		return nil, fmt.Errorf("%s entryCount must equal nested inventory entries", context)
	}
	commandRefs := []string{}
	entriesByID := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		entriesByID[entry.TestID] = entry
		commandRefs = append(commandRefs, entry.CommandRefs...)
	}
	commandRefCount, err := nonNegativeInteger(record["commandRefCount"], context+" commandRefCount")
	if err != nil {
		return nil, err
	}
	if commandRefCount != len(sortedUnique(commandRefs)) {
		return nil, fmt.Errorf("%s commandRefCount must equal unique nested inventory commandRefs", context)
	}
	mappings, err := admitRouteEntryMappings(record["routeEntryMappings"], entriesByID, context+" routeEntryMappings")
	if err != nil {
		return nil, err
	}
	if len(mappings) != len(entries) {
		return nil, fmt.Errorf("%s routeEntryMappings must map every nested inventory entry exactly once", context)
	}
	return map[string]any{
		"commandRefCount":    json.Number(fmt.Sprintf("%d", commandRefCount)),
		"entryCount":         json.Number(fmt.Sprintf("%d", entryCount)),
		"routeEntryMappings": mappings,
		"schemaVersion":      json.Number("2"),
	}, nil
}

func admitRouteEntryMappings(raw any, entriesByID map[string]Entry, context string) ([]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]any, 0, len(values))
	previousRouteID := ""
	seenTests := map[string]struct{}{}
	for index, rawMapping := range values {
		record, ok := rawMapping.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		mappingContext := fmt.Sprintf("%s[%d]", context, index)
		if err := admit.KnownKeys(record, []string{"bindingRecordId", "requirementId", "resolutionOrderIndex", "role", "scenarioId", "selector", "surfaceId", "testId", "witnessRouteId"}, mappingContext); err != nil {
			return nil, err
		}
		bindingRecordID, err := admit.SHA256Ref(record["bindingRecordId"], mappingContext+" bindingRecordId")
		if err != nil {
			return nil, err
		}
		requirementID, err := admit.RuleID(record["requirementId"], mappingContext+" requirementId")
		if err != nil {
			return nil, err
		}
		surfaceID, err := admit.RuleID(record["surfaceId"], mappingContext+" surfaceId")
		if err != nil {
			return nil, err
		}
		scenarioText, err := admit.NonEmptyText(record["scenarioId"], mappingContext+" scenarioId")
		if err != nil {
			return nil, err
		}
		scenarioID, scenarioSurfaceID, err := compactproofcontract.AdmitScenarioID(scenarioText, mappingContext+" scenarioId")
		if err != nil {
			return nil, err
		}
		if scenarioSurfaceID != surfaceID {
			return nil, fmt.Errorf("%s scenarioId must be scoped to surfaceId", mappingContext)
		}
		expectedBindingRecordID, err := compactproofcontract.BindingRecordID(compactproofcontract.BindingIdentity{RequirementID: requirementID, ScenarioID: scenarioID, SurfaceID: surfaceID})
		if err != nil {
			return nil, err
		}
		if bindingRecordID != expectedBindingRecordID {
			return nil, fmt.Errorf("%s bindingRecordId does not match its requirement, surface, and scenario identity", mappingContext)
		}
		role, err := admit.Enum(record["role"], map[string]struct{}{compactproofcontract.FalsificationWitnessRole: {}}, mappingContext+" role")
		if err != nil {
			return nil, err
		}
		selectorText, err := admit.NonEmptyText(record["selector"], mappingContext+" selector")
		if err != nil {
			return nil, err
		}
		selector, err := compactproofcontract.AdmitWitnessSelector(selectorText, mappingContext+" selector")
		if err != nil {
			return nil, err
		}
		witnessRouteID, err := admit.SHA256Ref(record["witnessRouteId"], mappingContext+" witnessRouteId")
		if err != nil {
			return nil, err
		}
		expectedRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, role, selector)
		if err != nil {
			return nil, err
		}
		if witnessRouteID != expectedRouteID {
			return nil, fmt.Errorf("%s witnessRouteId does not match its binding, role, and selector identity", mappingContext)
		}
		resolutionOrderIndex, err := compactproofcontract.AdmitResolutionOrderIndex(record["resolutionOrderIndex"], mappingContext+" resolutionOrderIndex")
		if err != nil {
			return nil, err
		}
		expectedTestID, err := ProofBindingTestID(witnessRouteID)
		if err != nil {
			return nil, err
		}
		if previousRouteID != "" && previousRouteID >= witnessRouteID {
			return nil, fmt.Errorf("%s must be sorted and unique by witnessRouteId", context)
		}
		previousRouteID = witnessRouteID
		testID, err := admit.RuleID(record["testId"], mappingContext+" testId")
		if err != nil {
			return nil, err
		}
		if testID != expectedTestID {
			return nil, fmt.Errorf("%s testId does not match witnessRouteId", mappingContext)
		}
		if _, duplicate := seenTests[testID]; duplicate {
			return nil, fmt.Errorf("%s must not map multiple routes to testId %s", context, testID)
		}
		seenTests[testID] = struct{}{}
		entry, exists := entriesByID[testID]
		if !exists {
			return nil, fmt.Errorf("%s testId %s does not resolve to a nested inventory entry", mappingContext, testID)
		}
		if entry.Selector != selector || !slices.Equal(entry.RequirementRefs, []string{requirementID}) || !slices.Equal(entry.WitnessRefs, []string{witnessRouteID}) {
			return nil, fmt.Errorf("%s does not match its nested inventory entry", mappingContext)
		}
		if entry.EvidenceClass != EvidenceClassProofRouteCandidate || entry.Falsifier != nil || entry.Oracle != nil || len(entry.OwnerInvariantRefs) != 0 || len(entry.QualityFindings) != 0 || !slices.Equal(entry.NonClaims, proofBindingEntryNonClaims) {
			return nil, fmt.Errorf("%s nested inventory entry must retain exact proof-route-candidate semantics", mappingContext)
		}
		result = append(result, map[string]any{
			"bindingRecordId":      bindingRecordID,
			"requirementId":        requirementID,
			"resolutionOrderIndex": json.Number(strconv.Itoa(resolutionOrderIndex)),
			"role":                 role,
			"scenarioId":           scenarioID,
			"selector":             selector,
			"surfaceId":            surfaceID,
			"testId":               testID,
			"witnessRouteId":       witnessRouteID,
		})
	}
	return result, nil
}

func admitNormalizedSources(raw any, context string) ([]SourceMetadata, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s sources must be an array", context)
	}
	result := make([]SourceMetadata, 0, len(values))
	ids := []string{}
	paths := []string{}
	for index, value := range values {
		row, ok := value.([]any)
		if !ok || len(row) != len(sourceSetColumns) {
			return nil, fmt.Errorf("%s sources row #%d must match sourceColumns", context, index+1)
		}
		sourceID, err := admit.RuleID(row[0], context+" source source_id")
		if err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(row[1], context+" source path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, context+" source path")
		if err != nil {
			return nil, err
		}
		sha, err := admit.LowercaseSHA256(row[2], context+" source sha256")
		if err != nil {
			return nil, err
		}
		role, err := admit.Enum(row[3], sourceRoles, context+" source role")
		if err != nil {
			return nil, err
		}
		nonClaims, err := admit.PreserveSortedTextArray(row[4], context+" source non_claims", false)
		if err != nil {
			return nil, err
		}
		result = append(result, SourceMetadata{NonClaims: nonClaims, Path: pathValue, Role: role, SHA256: sha, SourceID: sourceID})
		ids = append(ids, sourceID)
		paths = append(paths, pathValue)
	}
	if _, err := admit.PreserveSortedText(ids, context+" source ids", true); err != nil {
		return nil, err
	}
	if _, err := admit.SortedText(paths, context+" source paths", true); err != nil {
		return nil, err
	}
	return result, nil
}

func admitNormalizedEntrySources(raw any, context string) ([]EntrySourceMetadata, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s entrySources must be an array", context)
	}
	result := make([]EntrySourceMetadata, 0, len(values))
	testIDs := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s entrySources item #%d must be an object", context, index+1)
		}
		if err := admit.KnownKeys(record, []string{"path", "sourceId", "testId"}, context+" entrySources item"); err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], context+" entrySources path")
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(pathText, context+" entrySources path")
		if err != nil {
			return nil, err
		}
		sourceID, err := admit.RuleID(record["sourceId"], context+" entrySources sourceId")
		if err != nil {
			return nil, err
		}
		testID, err := admit.RuleID(record["testId"], context+" entrySources testId")
		if err != nil {
			return nil, err
		}
		result = append(result, EntrySourceMetadata{Path: pathValue, SourceID: sourceID, TestID: testID})
		testIDs = append(testIDs, testID)
	}
	if _, err := admit.PreserveSortedText(testIDs, context+" entrySources testIds", true); err != nil {
		return nil, err
	}
	return result, nil
}

func validateSourceEnvelope(sourceAuthority string, sources []SourceMetadata, inputPaths []string, entrySources []EntrySourceMetadata, entries []Entry, context string) error {
	if sourceAuthority == directAuthority {
		if len(sources) != 0 || len(inputPaths) != 0 || len(entrySources) != 0 {
			return fmt.Errorf("%s direct inventory envelope must not declare source-set metadata", context)
		}
		return nil
	}
	if sourceAuthority != sourceSetAuthority {
		return fmt.Errorf("%s sourceAuthority is unsupported", context)
	}
	if len(sources) == 0 {
		return fmt.Errorf("%s source-set envelope must declare sources", context)
	}
	if len(entrySources) != len(entries) {
		return fmt.Errorf("%s entrySources must cover every nested inventory entry", context)
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
			return fmt.Errorf("%s entrySources sourceId %s must reference sources", context, entrySource.SourceID)
		}
		if path != entrySource.Path {
			return fmt.Errorf("%s entrySources path must match source path for %s", context, entrySource.SourceID)
		}
		if _, ok := entrySet[entrySource.TestID]; !ok {
			return fmt.Errorf("%s entrySources testId %s must reference nested inventory entries", context, entrySource.TestID)
		}
		delete(entrySet, entrySource.TestID)
	}
	if len(entrySet) != 0 {
		return fmt.Errorf("%s entrySources must cover every nested inventory entry", context)
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

func sourcePaths(values []SourceMetadata) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Path)
	}
	sort.Strings(result)
	return result
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
