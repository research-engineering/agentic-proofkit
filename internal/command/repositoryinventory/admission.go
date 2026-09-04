package repositoryinventory

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func AdmitOutput(raw any) (Snapshot, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Snapshot{}, fmt.Errorf("repository inventory must be an object")
	}
	if err := admit.KnownKeys(record, []string{"entries", "inventoryId", "inventoryKind", "nonClaims", "omissions", "policyId", "schemaVersion", "scope"}, "repository inventory"); err != nil {
		return Snapshot{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], SchemaVersion) || record["inventoryKind"] != InventoryKind || record["policyId"] != PolicyID {
		return Snapshot{}, fmt.Errorf("repository inventory identity is invalid")
	}
	if err := admitExactScope(record["scope"]); err != nil {
		return Snapshot{}, err
	}
	entries, err := admitEntries(record["entries"])
	if err != nil {
		return Snapshot{}, err
	}
	omissions, err := admitOmissions(record["omissions"])
	if err != nil {
		return Snapshot{}, err
	}
	seenPaths := make(map[string]struct{}, len(entries)+len(omissions.OmittedRecognized))
	for _, entry := range entries {
		seenPaths[entry.Path] = struct{}{}
	}
	for _, entry := range omissions.OmittedRecognized {
		if _, duplicate := seenPaths[entry.Path]; duplicate {
			return Snapshot{}, fmt.Errorf("repository inventory observed and omitted paths must be disjoint")
		}
		seenPaths[entry.Path] = struct{}{}
	}
	if omissions.RootEntryCount != len(entries)+len(omissions.OmittedRecognized)+omissions.UnrecognizedCount {
		return Snapshot{}, fmt.Errorf("repository inventory omissions do not partition root entries")
	}
	nonClaims, err := admit.TextArray(record["nonClaims"], "repository inventory nonClaims", false)
	if err != nil || !equalStrings(nonClaims, boundaryNonClaims) {
		return Snapshot{}, fmt.Errorf("repository inventory nonClaims are not exact")
	}
	inventoryID, err := admit.SHA256Ref(record["inventoryId"], "repository inventory inventoryId")
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := finalize(Snapshot{Entries: entries, Omissions: omissions})
	if err != nil {
		return Snapshot{}, err
	}
	if snapshot.InventoryID != inventoryID {
		return Snapshot{}, fmt.Errorf("repository inventory inventoryId does not match admitted content")
	}
	return snapshot, nil
}

func admitExactScope(raw any) error {
	record, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("repository inventory scope must be an object")
	}
	if err := admit.KnownKeys(record, []string{"class", "repositoryRootState", "versionControlState"}, "repository inventory scope"); err != nil {
		return err
	}
	if record["class"] != "root_catalog" || record["repositoryRootState"] != "caller_selected_not_disclosed" || record["versionControlState"] != "not_evaluated" {
		return fmt.Errorf("repository inventory scope is invalid")
	}
	return nil
}

func admitEntries(raw any) ([]Entry, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > len(rootCatalog) {
		return nil, fmt.Errorf("repository inventory entries must be a bounded array")
	}
	entries := make([]Entry, 0, len(values))
	previousPath := ""
	aggregateBytes := 0
	for index, rawEntry := range values {
		record, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("repository inventory entry %d must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"byteLength", "contentSha256", "path", "role", "syntaxState"}, "repository inventory entry"); err != nil {
			return nil, err
		}
		path, err := admit.NonEmptyText(record["path"], "repository inventory entry path")
		if err != nil {
			return nil, err
		}
		role, recognized := catalogRole(path)
		if !recognized || record["role"] != role || record["syntaxState"] != "not_evaluated" {
			return nil, fmt.Errorf("repository inventory entry does not match the catalog")
		}
		if previousPath != "" && previousPath >= path {
			return nil, fmt.Errorf("repository inventory entries must be sorted and unique")
		}
		previousPath = path
		length, err := boundedCount(record["byteLength"], MaximumFileBytes, "repository inventory entry byteLength")
		if err != nil {
			return nil, err
		}
		if aggregateBytes > MaximumAggregateBytes-length {
			return nil, fmt.Errorf("repository inventory entries exceed aggregate byte limit")
		}
		aggregateBytes += length
		sha, err := admit.SHA256Ref(record["contentSha256"], "repository inventory entry contentSha256")
		if err != nil {
			return nil, err
		}
		entries = append(entries, Entry{ByteLength: length, ContentSHA256: sha, Path: path, Role: role, SyntaxState: "not_evaluated"})
	}
	return entries, nil
}

func admitOmissions(raw any) (Omissions, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Omissions{}, fmt.Errorf("repository inventory omissions must be an object")
	}
	if err := admit.KnownKeys(record, []string{"omittedRecognized", "rootEntryCount", "unrecognizedCount"}, "repository inventory omissions"); err != nil {
		return Omissions{}, err
	}
	rootCount, err := boundedCount(record["rootEntryCount"], MaximumRootEntries, "repository inventory rootEntryCount")
	if err != nil {
		return Omissions{}, err
	}
	unknownCount, err := boundedCount(record["unrecognizedCount"], MaximumRootEntries, "repository inventory unrecognizedCount")
	if err != nil {
		return Omissions{}, err
	}
	rawOmitted, ok := record["omittedRecognized"].([]any)
	if !ok || len(rawOmitted) > len(rootCatalog) {
		return Omissions{}, fmt.Errorf("repository inventory omittedRecognized must be a bounded array")
	}
	omitted := make([]OmittedRecognizedEntry, 0, len(rawOmitted))
	previousPath := ""
	for _, rawEntry := range rawOmitted {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return Omissions{}, fmt.Errorf("repository inventory omittedRecognized entry must be an object")
		}
		if err := admit.KnownKeys(entry, []string{"path", "reason"}, "repository inventory omittedRecognized entry"); err != nil {
			return Omissions{}, err
		}
		path, err := admit.NonEmptyText(entry["path"], "repository inventory omittedRecognized path")
		if err != nil {
			return Omissions{}, err
		}
		if _, recognized := catalogRole(path); !recognized || previousPath != "" && previousPath >= path {
			return Omissions{}, fmt.Errorf("repository inventory omittedRecognized entries must be sorted unique catalog paths")
		}
		previousPath = path
		reason, err := admit.Enum(entry["reason"], map[string]struct{}{OmissionNonText: {}, OmissionOversize: {}}, "repository inventory omittedRecognized reason")
		if err != nil {
			return Omissions{}, err
		}
		omitted = append(omitted, OmittedRecognizedEntry{Path: path, Reason: reason})
	}
	return Omissions{OmittedRecognized: omitted, RootEntryCount: rootCount, UnrecognizedCount: unknownCount}, nil
}

func boundedCount(raw any, maximum int, context string) (int, error) {
	value, err := admit.CanonicalInteger(raw, context)
	if err != nil || value < 0 || value > int64(maximum) {
		return 0, fmt.Errorf("%s must be an integer between 0 and %d", context, maximum)
	}
	return int(value), nil
}

func equalStrings(left, right []string) bool {
	return slices.Equal(left, right)
}
