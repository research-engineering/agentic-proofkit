package adoptionplan

import (
	"bytes"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var intentValueSet = func() map[string]struct{} {
	values := make(map[string]struct{}, len(intentValues))
	for _, value := range intentValues {
		values[value] = struct{}{}
	}
	return values
}()

// AdmitOutput replays the plan's semantic owners and requires byte-canonical
// equality with their deterministic projection.
func AdmitOutput(raw any) (Plan, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Plan{}, fmt.Errorf("adoption plan must be an object")
	}
	intent, err := admit.Enum(record["intent"], intentValueSet, "adoption plan intent")
	if err != nil {
		return Plan{}, err
	}
	inventory, err := repositoryinventory.AdmitOutput(record["repositoryInventory"])
	if err != nil {
		return Plan{}, err
	}
	stackPresetID := ""
	if rawHint := record["stackHint"]; rawHint != nil {
		hint, err := stackpreset.AdmitPlanningHint(rawHint)
		if err != nil {
			return Plan{}, err
		}
		stackPresetID = hint.PresetID
	}
	expected, err := Build(intent, inventory, stackPresetID)
	if err != nil {
		return Plan{}, err
	}
	rawBytes, err := stablejson.Marshal(record)
	if err != nil {
		return Plan{}, fmt.Errorf("encode adoption plan")
	}
	expectedBytes, err := stablejson.Marshal(expected.JSONValue())
	if err != nil {
		return Plan{}, fmt.Errorf("encode expected adoption plan")
	}
	if !bytes.Equal(rawBytes, expectedBytes) {
		return Plan{}, fmt.Errorf("adoption plan does not match its semantic owners")
	}
	return expected, nil
}
