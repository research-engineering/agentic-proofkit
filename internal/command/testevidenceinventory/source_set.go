package testevidenceinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var sourceRoles = map[string]struct{}{
	"test_evidence_inventory_contract": {},
	"test_evidence_inventory_fragment": {},
}

var sourceSetColumns = []string{"source_id", "path", "sha256", "role", "non_claims"}

type sourceRow struct {
	NonClaims []string
	Path      string
	Role      string
	SHA256    string
	SourceID  string
}

func admitSourceSetInventory(record map[string]any) (Inventory, error) {
	if err := admit.KnownKeys(record, []string{"authority", "inventoryId", "nonClaims", "schemaVersion", "sourceColumns", "sourceTexts", "sources"}, "test evidence inventory source set"); err != nil {
		return Inventory{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Inventory{}, fmt.Errorf("test evidence inventory source set schemaVersion must be 1")
	}
	authority, err := literal(record["authority"], sourceSetAuthority, "test evidence inventory source set authority")
	if err != nil {
		return Inventory{}, err
	}
	inventoryID, err := admit.RuleID(record["inventoryId"], "test evidence inventory source set inventoryId")
	if err != nil {
		return Inventory{}, err
	}
	columns, err := admit.TextArray(record["sourceColumns"], "test evidence inventory source set sourceColumns", false)
	if err != nil {
		return Inventory{}, err
	}
	if err := assertExact(columns, sourceSetColumns, "test evidence inventory source set sourceColumns"); err != nil {
		return Inventory{}, err
	}
	sourceRows, err := admitSourceRows(record["sources"])
	if err != nil {
		return Inventory{}, err
	}
	texts, err := admitSourceTexts(record["sourceTexts"])
	if err != nil {
		return Inventory{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "test evidence inventory source set nonClaims", false)
	if err != nil {
		return Inventory{}, err
	}
	entries := []Entry{}
	entrySources := []EntrySourceMetadata{}
	inputPaths := []string{}
	for _, row := range sourceRows {
		text, ok := texts[row.Path]
		if !ok {
			return Inventory{}, fmt.Errorf("test evidence inventory source %s text is missing for %s", row.SourceID, row.Path)
		}
		if sha256Hex(text) != row.SHA256 {
			return Inventory{}, fmt.Errorf("test evidence inventory source %s sha256 drift", row.SourceID)
		}
		sourceInventory, err := admitSourceInventoryText(row, text)
		if err != nil {
			return Inventory{}, err
		}
		entries = append(entries, sourceInventory.Entries...)
		for _, entry := range sourceInventory.Entries {
			entrySources = append(entrySources, EntrySourceMetadata{
				Path:     row.Path,
				SourceID: row.SourceID,
				TestID:   entry.TestID,
			})
		}
		nonClaims = append(nonClaims, row.NonClaims...)
		nonClaims = append(nonClaims, sourceInventory.NonClaims...)
		inputPaths = append(inputPaths, row.Path)
	}
	referenced := map[string]struct{}{}
	for _, path := range inputPaths {
		referenced[path] = struct{}{}
	}
	for path := range texts {
		if _, ok := referenced[path]; !ok {
			return Inventory{}, fmt.Errorf("test evidence inventory source text is not referenced by source set: %s", path)
		}
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].TestID < entries[right].TestID })
	sort.Slice(entrySources, func(left, right int) bool { return entrySources[left].TestID < entrySources[right].TestID })
	if err := assertUnique(entryIDs(entries), "test evidence inventory source set testIds"); err != nil {
		return Inventory{}, err
	}
	sort.Strings(inputPaths)
	return Inventory{
		Authority: authority, Entries: entries, EntrySources: entrySources, InputPaths: inputPaths, InventoryID: inventoryID,
		NonClaims: sortedUnique(nonClaims), SourceCount: len(sourceRows), SourceRows: sourceMetadata(sourceRows),
	}, nil
}

func sourceMetadata(rows []sourceRow) []SourceMetadata {
	result := make([]SourceMetadata, 0, len(rows))
	for _, row := range rows {
		result = append(result, SourceMetadata{
			NonClaims: append([]string{}, row.NonClaims...),
			Path:      row.Path,
			Role:      row.Role,
			SHA256:    row.SHA256,
			SourceID:  row.SourceID,
		})
	}
	return result
}

func admitSourceInventoryText(row sourceRow, text string) (Inventory, error) {
	raw, err := admission.DecodeJSON(strings.NewReader(text), int64(len(text)+1))
	if err != nil {
		return Inventory{}, fmt.Errorf("test evidence inventory source %s invalid JSON: %w", row.SourceID, err)
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return Inventory{}, fmt.Errorf("test evidence inventory source %s must be a JSON object", row.SourceID)
	}
	inventoryRecord, err := unwrapInventory(record, "test evidence inventory source "+row.SourceID)
	if err != nil {
		return Inventory{}, err
	}
	if inventoryRecord["authority"] == sourceSetAuthority {
		return Inventory{}, fmt.Errorf("test evidence inventory source %s must not reference another source set", row.SourceID)
	}
	inventory, err := admitDirectInventory(inventoryRecord, "test evidence inventory source "+row.SourceID)
	if err != nil {
		return Inventory{}, err
	}
	if inventory.SourceID == "" {
		if row.Role == "test_evidence_inventory_fragment" {
			return Inventory{}, fmt.Errorf("test evidence inventory source %s.sourceId must match fragment source_id", row.SourceID)
		}
		return inventory, nil
	}
	if inventory.SourceID != row.SourceID {
		return Inventory{}, fmt.Errorf("test evidence inventory source %s.sourceId must match source set id", row.SourceID)
	}
	return inventory, nil
}

func admitSourceRows(raw any) ([]sourceRow, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("test evidence inventory source set sources must be a non-empty array")
	}
	result := make([]sourceRow, 0, len(values))
	for index, value := range values {
		row, err := admitSourceRow(value, index)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	if err := assertUnique(project(result, func(row sourceRow) string { return row.SourceID }), "test evidence inventory source_id"); err != nil {
		return nil, err
	}
	if err := assertUnique(project(result, func(row sourceRow) string { return row.Path }), "test evidence inventory source path"); err != nil {
		return nil, err
	}
	sort.Slice(result, func(left, right int) bool { return result[left].SourceID < result[right].SourceID })
	return result, nil
}

func admitSourceRow(raw any, index int) (sourceRow, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != len(sourceSetColumns) {
		return sourceRow{}, fmt.Errorf("test evidence inventory source row #%d must use sourceColumns", index+1)
	}
	sourceID, err := admit.RuleID(values[0], fmt.Sprintf("test evidence inventory source row #%d.source_id", index+1))
	if err != nil {
		return sourceRow{}, err
	}
	pathText, err := admit.NonEmptyText(values[1], "test evidence inventory source "+sourceID+".path")
	if err != nil {
		return sourceRow{}, err
	}
	path, err := admit.SafeRepoRelativePath(pathText, "test evidence inventory source "+sourceID+".path")
	if err != nil {
		return sourceRow{}, err
	}
	sha, err := admit.LowercaseSHA256(values[2], "test evidence inventory source "+sourceID+".sha256")
	if err != nil {
		return sourceRow{}, err
	}
	role, err := admit.Enum(values[3], sourceRoles, "test evidence inventory source "+sourceID+".role")
	if err != nil {
		return sourceRow{}, err
	}
	nonClaims, err := sortedText(values[4], "test evidence inventory source "+sourceID+".non_claims", false)
	if err != nil {
		return sourceRow{}, err
	}
	return sourceRow{NonClaims: nonClaims, Path: path, Role: role, SHA256: sha, SourceID: sourceID}, nil
}

func admitSourceTexts(raw any) (map[string]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("test evidence inventory sourceTexts must be an array")
	}
	result := map[string]string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		context := fmt.Sprintf("test evidence inventory sourceText #%d", index+1)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", context)
		}
		if err := admit.KnownKeys(record, []string{"path", "text"}, context); err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], context+".path")
		if err != nil {
			return nil, err
		}
		path, err := admit.SafeRepoRelativePath(pathText, context+".path")
		if err != nil {
			return nil, err
		}
		text, ok := record["text"].(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s.text must be non-empty text", context)
		}
		if _, exists := result[path]; exists {
			return nil, fmt.Errorf("duplicate test evidence inventory source text path=%s", path)
		}
		result[path] = text
	}
	return result, nil
}

func assertExact(actual []string, expected []string, context string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%s drift", context)
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return fmt.Errorf("%s drift", context)
		}
	}
	return nil
}

func project[T any](values []T, fn func(T) string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, fn(value))
	}
	sort.Strings(result)
	return result
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
