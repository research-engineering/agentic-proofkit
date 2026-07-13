package requirementdiff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maxChanges = 8192

var nonClaims = []string{
	"Semantic diff is a derived comparison and does not own requirement meaning, proof freshness, merge, release, or rollout decisions.",
	"Semantic diff compares only admitted owner-declared requirement fields and is not a textual or Git diff.",
}

type query struct {
	MaxChanges     int
	OwnerIDs       map[string]struct{}
	RequirementIDs map[string]struct{}
}

type requirementRecord struct {
	Digest      string
	Requirement requirementsourceadmission.Requirement
}

func Build(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement semantic diff input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baseContext", "currentContext", "diffId", "query", "schemaVersion"}, "requirement semantic diff input"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, fmt.Errorf("requirement semantic diff schemaVersion must be 1")
	}
	diffID, err := admit.RuleID(record["diffId"], "requirement semantic diff diffId")
	if err != nil {
		return nil, err
	}
	base, err := requirementcontext.AdmitSnapshot(record["baseContext"])
	if err != nil {
		return nil, err
	}
	current, err := requirementcontext.AdmitSnapshot(record["currentContext"])
	if err != nil {
		return nil, err
	}
	diffQuery, err := admitQuery(record["query"])
	if err != nil {
		return nil, err
	}
	baseRequirements := requirementsByID(base, diffQuery.RequirementIDs)
	currentRequirements := requirementsByID(current, diffQuery.RequirementIDs)
	changes, err := compareRequirements(base, current, baseRequirements, currentRequirements, diffQuery.OwnerIDs, diffQuery.MaxChanges)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"baseBaselineVerification":    base.BaselineVerification,
		"baseSnapshotId":              base.SnapshotID,
		"changeCount":                 len(changes),
		"changes":                     changes,
		"currentBaselineVerification": current.BaselineVerification,
		"currentSnapshotId":           current.SnapshotID,
		"diffId":                      diffID,
		"diffKind":                    "proofkit.requirement-semantic-diff",
		"nonClaims":                   admit.StringSliceToAny(nonClaims),
		"schemaVersion":               json.Number("1"),
	}, nil
}

func admitQuery(raw any) (query, error) {
	if raw == nil {
		return query{MaxChanges: maxChanges, OwnerIDs: map[string]struct{}{}, RequirementIDs: map[string]struct{}{}}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return query{}, fmt.Errorf("requirement semantic diff query must be an object")
	}
	if err := admit.KnownKeys(record, []string{"maxChanges", "ownerIds", "requirementIds"}, "requirement semantic diff query"); err != nil {
		return query{}, err
	}
	limit := maxChanges
	if record["maxChanges"] != nil {
		value, err := admit.PositiveInteger(record["maxChanges"], "requirement semantic diff maxChanges")
		if err != nil || value > maxChanges {
			return query{}, fmt.Errorf("requirement semantic diff maxChanges must be between 1 and %d", maxChanges)
		}
		limit = value
	}
	owners, err := admitIDSet(record["ownerIds"], "requirement semantic diff ownerIds")
	if err != nil {
		return query{}, err
	}
	requirements, err := admitIDSet(record["requirementIds"], "requirement semantic diff requirementIds")
	if err != nil {
		return query{}, err
	}
	return query{MaxChanges: limit, OwnerIDs: owners, RequirementIDs: requirements}, nil
}

func admitIDSet(raw any, context string) (map[string]struct{}, error) {
	result := map[string]struct{}{}
	if raw == nil {
		return result, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	for _, rawValue := range values {
		value, err := admit.RuleID(rawValue, context)
		if err != nil {
			return nil, err
		}
		if _, exists := result[value]; exists {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func requirementsByID(snapshot requirementcontext.Snapshot, requirementFilter map[string]struct{}) map[string]requirementRecord {
	digestBySource := map[string]string{}
	for _, source := range snapshot.Sources {
		if source.Kind == "requirement_source" {
			digestBySource[source.SourceRef] = source.CurrentDigest
		}
	}
	result := map[string]requirementRecord{}
	for _, source := range snapshot.RequirementSources {
		for _, requirement := range source.Requirements {
			if len(requirementFilter) > 0 {
				if _, ok := requirementFilter[requirement.RequirementID]; !ok {
					continue
				}
			}
			result[requirement.RequirementID] = requirementRecord{Digest: digestBySource[source.SourceID], Requirement: requirement}
		}
	}
	return result
}

func compareRequirements(base, current requirementcontext.Snapshot, before, after map[string]requirementRecord, ownerFilter map[string]struct{}, limit int) ([]any, error) {
	ids := map[string]struct{}{}
	for id := range before {
		ids[id] = struct{}{}
	}
	for id := range after {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	changes := []any{}
	for _, id := range ordered {
		baseRecord, beforeOK := before[id]
		currentRecord, afterOK := after[id]
		if !matchesOwnerFilter(baseRecord, beforeOK, currentRecord, afterOK, ownerFilter) {
			continue
		}
		if !beforeOK || !afterOK {
			changeClass := "entity_added"
			var beforeValue any
			var afterValue any
			if !afterOK {
				changeClass = "entity_removed"
				beforeValue = requirementsourceadmission.RequirementValue(baseRecord.Requirement)
			} else {
				afterValue = requirementsourceadmission.RequirementValue(currentRecord.Requirement)
			}
			change, err := changeValue(base, current, id, "", changeClass, baseRecord, currentRecord, beforeValue, afterValue)
			if err != nil {
				return nil, err
			}
			changes = append(changes, change)
		} else {
			fieldChanges, err := compareFields(base, current, baseRecord, currentRecord)
			if err != nil {
				return nil, err
			}
			changes = append(changes, fieldChanges...)
		}
		if len(changes) > limit {
			return nil, fmt.Errorf("requirement semantic diff exceeds maxChanges")
		}
	}
	sortChangesCanonical(changes)
	return changes, nil
}

func matchesOwnerFilter(before requirementRecord, beforeOK bool, after requirementRecord, afterOK bool, owners map[string]struct{}) bool {
	if len(owners) == 0 {
		return true
	}
	if beforeOK {
		if _, ok := owners[before.Requirement.OwnerID]; ok {
			return true
		}
	}
	if afterOK {
		if _, ok := owners[after.Requirement.OwnerID]; ok {
			return true
		}
	}
	return false
}

func compareFields(base, current requirementcontext.Snapshot, before, after requirementRecord) ([]any, error) {
	left := requirementsourceadmission.ComparisonFields(before.Requirement)
	right := requirementsourceadmission.ComparisonFields(after.Requirement)
	if len(left) != len(right) {
		return nil, fmt.Errorf("requirement semantic diff owner comparison projections are incompatible")
	}
	changes := []any{}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].Class != right[index].Class {
			return nil, fmt.Errorf("requirement semantic diff owner comparison metadata is incompatible")
		}
		beforeValue := normalizedField(left[index].Value, left[index].Class)
		afterValue := normalizedField(right[index].Value, right[index].Class)
		if reflect.DeepEqual(beforeValue, afterValue) {
			continue
		}
		changeClass := comparisonChangeClass(left[index].Name, left[index].Class)
		change, err := changeValue(base, current, before.Requirement.RequirementID, left[index].Name, changeClass, before, after, beforeValue, afterValue)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func comparisonChangeClass(field, class string) string {
	if field == "lifecycle" {
		return "lifecycle_transition"
	}
	switch class {
	case "scalar":
		return "scalar_changed"
	case "set":
		return "set_membership_changed"
	default:
		return "opaque_value_changed"
	}
}

func changeValue(base, current requirementcontext.Snapshot, requirementID, field, changeClass string, before, after requirementRecord, beforeValue, afterValue any) (map[string]any, error) {
	pointer := "/requirements/" + escapePointer(requirementID)
	if field != "" {
		pointer += "/" + escapePointer(field)
	}
	identity := map[string]any{
		"after":               afterValue,
		"baseSnapshotId":      base.SnapshotID,
		"baseSourceDigest":    before.Digest,
		"before":              beforeValue,
		"changeClass":         changeClass,
		"currentSnapshotId":   current.SnapshotID,
		"currentSourceDigest": after.Digest,
		"entityId":            requirementID,
		"entityKind":          "requirement",
		"jsonPointer":         pointer,
	}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"after":               afterValue,
		"baseSourceDigest":    before.Digest,
		"before":              beforeValue,
		"changeClass":         changeClass,
		"changeId":            digest.SHA256TextRef(string(encoded)),
		"currentSourceDigest": after.Digest,
		"entityId":            requirementID,
		"entityKind":          "requirement",
		"jsonPointer":         pointer,
	}, nil
}

func normalizedField(value any, class string) any {
	if class != "set" {
		return value
	}
	values, _ := value.([]any)
	texts := make([]string, 0, len(values))
	for _, item := range values {
		if text, ok := item.(string); ok {
			texts = append(texts, text)
		}
	}
	sort.Strings(texts)
	result := make([]any, len(texts))
	for index, item := range texts {
		result[index] = item
	}
	return result
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
