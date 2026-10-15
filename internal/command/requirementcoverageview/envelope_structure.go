package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// EnvelopeShape describes the complete post-Build coverage guidance carrier.
// Reference joins, counts, ordering and state consistency remain native-owned.
func EnvelopeShape() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	budget := jsonshape.IntegerLiteral(coverageEnvelopeTokenBudget)
	command := jsonshape.Object(
		jsonshape.Required("argv", jsonshape.Array(text, 1)),
		jsonshape.Required("commandId", jsonshape.StringLiteral("proofkit.requirement-coverage-view.rerun")),
		jsonshape.Required("nonClaim", text), jsonshape.Required("reason", text),
	)
	return agentenvelope.StructureWithTokenBudget("proofkit.requirement-coverage-view.agent-envelope", agentenvelope.StructureParts{
		ActionPlan:             jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.StringLiteral("review")), 1, 1),
		BlockedPreconditions:   jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions),
		Bounds:                 agentenvelope.CompatibilityBoundsWithTokenBudgetStructure(budget),
		ClarificationQuestions: jsonshape.Tuple(), Commands: jsonshape.BoundedArray(command, 0, 1),
		ContextRefs: jsonshape.BoundedArray(agentenvelope.ContextRefStructure(
			jsonshape.StringLiteral("json-pointer"), jsonshape.StringLiteral("supporting")), 5, 5),
		Omitted: jsonshape.Tuple(), ReceiptRefs: jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport: agentenvelope.SourceReportStructure("proofkit.requirement-coverage-view", text, jsonshape.Null(),
			jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})),
	}, budget)
}

func EnvelopeStructure() map[string]any {
	schema := EnvelopeShape().JSONSchema()
	schema["description"] = "Complete coverage guidance envelope for admitted input, including failed coverage views. Native Build owns count arithmetic, local reference closure, ordering, truncation and state/exit consistency. maxTokenBudget preserves the producer's declaration, not measured tokenizer cost. No witness executes and no merge is approved."
	return schema
}
