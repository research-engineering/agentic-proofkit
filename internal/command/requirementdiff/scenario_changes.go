package requirementdiff

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

type scenarioRecord struct {
	Digest   string
	SourceID string
	Value    map[string]any
}

// scenariosByIdentity keys canonical scenario records by source and scenario,
// because scenario identities are unique only within one requirement source.
func scenariosByIdentity(snapshot requirementcontext.Snapshot) (map[[2]string]scenarioRecord, error) {
	digestBySource := map[string]string{}
	for _, source := range snapshot.Sources {
		if source.Kind == "requirement_source" {
			digestBySource[source.SourceRef] = source.CurrentDigest
		}
	}
	result := map[[2]string]scenarioRecord{}
	for _, source := range snapshot.RequirementSources {
		values, err := requirementsourceadmission.ScenarioValues(source)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			scenarioID, _ := value["scenarioId"].(string)
			result[[2]string{source.SourceID(), scenarioID}] = scenarioRecord{Digest: digestBySource[source.SourceID()], SourceID: source.SourceID(), Value: value}
		}
	}
	return result, nil
}

// compareScenarios reports scenario edits that the requirement review digest
// only summarizes. A scenario is in scope when a requirement it links to on
// either side passes the requirement and owner query.
func compareScenarios(base, current requirementcontext.Snapshot, before, after map[string]requirementRecord, ownerFilter map[string]struct{}, limit int) ([]any, error) {
	left, err := scenariosByIdentity(base)
	if err != nil {
		return nil, err
	}
	right, err := scenariosByIdentity(current)
	if err != nil {
		return nil, err
	}
	keys := map[[2]string]struct{}{}
	for key := range left {
		keys[key] = struct{}{}
	}
	for key := range right {
		keys[key] = struct{}{}
	}
	ordered := make([][2]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i][1] != ordered[j][1] {
			return ordered[i][1] < ordered[j][1]
		}
		return ordered[i][0] < ordered[j][0]
	})
	inScope := func(record scenarioRecord, present bool) bool {
		if !present {
			return false
		}
		ids, _ := record.Value["requirementIds"].([]any)
		for _, raw := range ids {
			id, _ := raw.(string)
			baseRecord, beforeOK := before[id]
			currentRecord, afterOK := after[id]
			if (beforeOK || afterOK) && matchesOwnerFilter(baseRecord, beforeOK, currentRecord, afterOK, ownerFilter) {
				return true
			}
		}
		return false
	}
	changes := []any{}
	for _, key := range ordered {
		baseRecord, beforeOK := left[key]
		currentRecord, afterOK := right[key]
		if !inScope(baseRecord, beforeOK) && !inScope(currentRecord, afterOK) {
			continue
		}
		entity := entityRef{kind: "scenario", id: key[1], pointer: scenarioPointer(key[0], key[1])}
		if !beforeOK || !afterOK {
			changeClass := "entity_added"
			var beforeValue, afterValue any
			if !afterOK {
				changeClass, beforeValue = "entity_removed", baseRecord.Value
			} else {
				afterValue = currentRecord.Value
			}
			change, err := entityChange(base, current, entity, "", changeClass, baseRecord.Digest, currentRecord.Digest, beforeValue, afterValue)
			if err != nil {
				return nil, err
			}
			changes = append(changes, change)
		} else {
			leftFields := requirementsourceadmission.ScenarioComparisonFields(baseRecord.Value)
			rightFields := requirementsourceadmission.ScenarioComparisonFields(currentRecord.Value)
			for index := range leftFields {
				if reflect.DeepEqual(leftFields[index].Value, rightFields[index].Value) {
					continue
				}
				changeClass := comparisonChangeClass(leftFields[index].Name, leftFields[index].Class)
				change, err := entityChange(base, current, entity, leftFields[index].Name, changeClass, baseRecord.Digest, currentRecord.Digest, leftFields[index].Value, rightFields[index].Value)
				if err != nil {
					return nil, err
				}
				changes = append(changes, change)
			}
		}
		if len(changes) > limit {
			return nil, fmt.Errorf("requirement semantic diff exceeds maxChanges")
		}
	}
	return changes, nil
}
