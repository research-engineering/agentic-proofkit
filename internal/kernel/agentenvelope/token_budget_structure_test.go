package agentenvelope

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func tokenBudgetStructureParts(budget jsonshape.Shape) StructureParts {
	return StructureParts{
		ActionPlan: jsonshape.Tuple(), BlockedPreconditions: jsonshape.Tuple(),
		Bounds:                 CompatibilityBoundsWithTokenBudgetStructure(budget),
		ClarificationQuestions: jsonshape.Tuple(), Commands: jsonshape.Tuple(), ContextRefs: jsonshape.Tuple(),
		Omitted: jsonshape.Tuple(), ReceiptRefs: jsonshape.Tuple(), RouteQuestions: jsonshape.Tuple(),
		SourceReport: SourceReportStructure("fixture.source", jsonshape.StringLiteral("fixture.source"), jsonshape.Null(), jsonshape.StringLiteral("passed")),
	}
}

func TestTokenBudgetStructuresPreserveWholeBuildOutputs(t *testing.T) {
	// Build preserves a declaration, including zero, signed and large values;
	// the producer selects that domain, not a shared tokenizer policy.
	for _, budget := range []int64{0, -1, 1 << 40} {
		t.Run(strconv.FormatInt(budget, 10), func(t *testing.T) {
			for _, bound := range []int{0, 1 << 20} {
				bounds := map[string]any{
					"escalation": "Caller-owned review.", "fanout": "bounded", "maxTokenBudget": budget,
					"nonClaim": "Declared counts do not execute witnesses.", "omittedCount": 0,
				}
				for _, field := range []string{"maxActionItems", "maxCommandRefs", "maxContextRefs", "maxOmittedItems", "maxReceiptRefs"} {
					bounds[field] = bound
				}
				output := Build(Input{
					EnvelopeID: "fixture.envelope", Bounds: bounds,
					SourceReport: map[string]any{"reportId": "fixture.source", "reportKind": "fixture.source", "state": "passed"},
				})
				declaration := jsonshape.IntegerLiteral(budget)
				shape := StructureWithTokenBudget("fixture.envelope", tokenBudgetStructureParts(declaration), declaration)
				if err := shape.CheckGenerated(output, "envelope"); err != nil {
					t.Fatal(err)
				}
				if err := schemacheck.Validate(shape.JSONSchema(), output); err != nil {
					t.Fatal(err)
				}
				if output["costContract"].(map[string]any)["maxTokenBudget"] != json.Number(strconv.FormatInt(budget, 10)) {
					t.Fatal("Build changed the declared token budget")
				}
			}
		})
	}
}

func TestDefaultStructureKeepsNullTokenBudget(t *testing.T) {
	parts := tokenBudgetStructureParts(jsonshape.Null())
	if !reflect.DeepEqual(Structure("fixture.envelope", parts).JSONSchema(), StructureWithTokenBudget("fixture.envelope", parts, jsonshape.Null()).JSONSchema()) {
		t.Fatal("default structural contract changed")
	}
	if !reflect.DeepEqual(CompatibilityBoundsStructure().JSONSchema(), CompatibilityBoundsWithTokenBudgetStructure(jsonshape.Null()).JSONSchema()) {
		t.Fatal("default bounds contract changed")
	}
	schema := Structure("fixture.envelope", parts).JSONSchema()
	properties := schema["properties"].(map[string]any)
	for _, name := range []string{"bounds", "costContract"} {
		budget := properties[name].(map[string]any)["properties"].(map[string]any)["maxTokenBudget"].(map[string]any)
		if budget["type"] != "null" {
			t.Fatalf("default %s budget is not null", name)
		}
	}
	if err := schemacheck.Validate(InvalidInputStructure(), InvalidInput("Repair caller input.")); err != nil {
		t.Fatalf("existing null-budget producer no longer fits: %v", err)
	}
}
