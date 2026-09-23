package requirementcoverageinput

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
)

func TestCompositionOwnsGroupedSourceBeforeCallerMutation(t *testing.T) {
	raw := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	source := raw["requirementSource"].(map[string]any)
	group := source["groups"].([]any)[0].(map[string]any)
	group["statementStem"] = "Coverage"
	group["sharedPremises"] = []any{"Only selected owner surfaces are included."}
	group["profileId"] = "RPROF-COVERAGE"
	source["profiles"] = []any{map[string]any{"profileId": "RPROF-COVERAGE", "fields": map[string]any{"ownerId": "proofkit.coverage"}}}
	first := group["members"].([]any)[0].(map[string]any)
	first["statementCompletion"] = "preserves selected evidence."
	delete(first["fields"].(map[string]any), "ownerId")
	second := cloneJSONValue(first).(map[string]any)
	second["requirementId"], second["statementCompletion"] = "REQ-PROOFKIT-COVERAGE-002", "does not create execution."
	second["fields"].(map[string]any)["claimLevel"] = "advisory"
	group["members"] = []any{second, first}
	admitted, err := admitInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := compose(admitted)
	if err != nil {
		t.Fatal(err)
	}
	want := cloneJSONValue(baseline)
	mutateJSONStrings(source)
	mutateJSONStrings(baseline["requirementSource"])
	output, err := compose(admitted)
	if err != nil || !reflect.DeepEqual(output, want) {
		t.Fatalf("composer reread or aliased caller source: %v", err)
	}
	if output["schemaVersion"] != json.Number("3") {
		t.Fatal("composer did not advance downstream input identity")
	}
	view, _, err := requirementcoverageview.BuildJSON(output, requirementcoverageview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rows := view.(map[string]any)["requirementCoverage"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["invariant"] != "Coverage preserves selected evidence." || rows[1].(map[string]any)["invariant"] != "Coverage does not create execution." {
		t.Fatal("downstream lost full grouped invariant meaning")
	}
	for _, row := range rows {
		requirement := row.(map[string]any)
		if requirement["ownerId"] != "proofkit.coverage" || !reflect.DeepEqual(requirement["sharedPremises"], []any{"Only selected owner surfaces are included."}) {
			t.Fatal("profile or group context lost through composition")
		}
	}
	if _, err := requirementcoverageview.AdmitOutput(view); err != nil {
		t.Fatalf("composed view does not satisfy its owner: %v", err)
	}
}

func TestCoverageComposerRejectsOldSourceInputContractIdentity(t *testing.T) {
	raw := validComposeInput(t, baseInventoryEntries()).(map[string]any)
	raw["schemaVersion"] = json.Number("2")
	if out, code, err := Build(raw); err == nil || out != nil || code != 1 {
		t.Fatalf("old identity accepted: %v, %d, %v", out, code, err)
	}
}
