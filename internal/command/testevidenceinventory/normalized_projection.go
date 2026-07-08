package testevidenceinventory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

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
	if record["projectionKind"] != nil {
		if _, err := admit.RuleID(record["projectionKind"], context+" projectionKind"); err != nil {
			return NormalizedProjection{}, err
		}
	}
	if record["projectionSummary"] != nil {
		if _, ok := record["projectionSummary"].(map[string]any); !ok {
			return NormalizedProjection{}, fmt.Errorf("%s projectionSummary must be an object when present", context)
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
	if record["projectionKind"] != nil {
		envelope["projectionKind"] = record["projectionKind"]
	}
	if record["projectionSummary"] != nil {
		envelope["projectionSummary"] = record["projectionSummary"]
	}
	return NormalizedProjection{Envelope: envelope, Inventory: InventoryValue(result.Inventory), Result: result}, nil
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
