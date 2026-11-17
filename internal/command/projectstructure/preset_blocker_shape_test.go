package projectstructure

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestEmbeddedPresetBlockerRetainsItsChildIdentity(t *testing.T) {
	input := validProjectStructureInput()
	delete(input["repoProfileScaffold"].(map[string]any), "presetId")
	result, err := BuildResult(input)
	if err != nil {
		t.Fatal(err)
	}
	plan := result.AdoptionWorkflowPlan
	if plan["planState"] != "blocked" || len(plan["blockers"].([]any)) != 1 {
		t.Fatal("control did not reach the sole preset-choice blocker")
	}
	for _, schema := range []struct {
		value  any
		schema map[string]any
	}{
		{plan, adoptionworkflow.OutputStructure()}, {result.JSONValue(), OutputStructure()},
	} {
		if err := schemacheck.Validate(schema.schema, schema.value); err != nil {
			t.Fatalf("control: %v", err)
		}
	}
	blocker := plan["blockers"].([]any)[0].(map[string]any)
	for field, replacement := range map[string]any{
		"blockerId": "example.unrelated", "reason": "Unrelated reason.", "scenario": "release_channel",
		"nonClaim": "Unrelated non-claim.", "inputAlternatives": []any{[]any{"release_authority"}},
	} {
		before := blocker[field]
		blocker[field] = replacement
		if schemacheck.Validate(adoptionworkflow.OutputStructure(), plan) == nil || schemacheck.Validate(OutputStructure(), result.JSONValue()) == nil {
			t.Fatalf("child/parent admitted substituted %s", field)
		}
		blocker[field] = before
	}
}
