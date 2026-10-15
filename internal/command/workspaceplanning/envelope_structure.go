package workspaceplanning

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func ChangedPlanEnvelopeShape() jsonshape.Shape {
	return workspaceEnvelopeShape(false)
}

func ChangedPlanEnvelopeStructure() map[string]any {
	return workspaceEnvelopeStructure(false)
}

func ShardEnvelopeShape() jsonshape.Shape {
	return workspaceEnvelopeShape(true)
}

func ShardEnvelopeStructure() map[string]any {
	return workspaceEnvelopeStructure(true)
}

func workspaceEnvelopeStructure(shard bool) map[string]any {
	schema := workspaceEnvelopeShape(shard).JSONSchema()
	schema["description"] = "Complete workspace planning guidance envelope, including failed shard partitions and empty plans. Native Build owns reference joins, count arithmetic, ordering, omissions and state/exit consistency. maxTokenBudget preserves the producer's declaration, not measured tokenizer cost. No package gate executes and no CI scheduling or merge is approved."
	return schema
}

func workspaceEnvelopeShape(shard bool) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	budget := jsonshape.IntegerLiteral(workspaceEnvelopeTokenBudget)
	kind, contexts := "proofkit.workspace-changed-package-plan", 3
	states, blockers := jsonshape.StringLiteral("passed"), jsonshape.Tuple()
	clarifications := jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral("policy_choice")), 0, 1)
	if shard {
		kind, contexts = "proofkit.workspace-shard-partition", 4
		states = jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
		blockers = jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, 1)
		clarifications = jsonshape.Tuple()
	}
	// Workspace omissions carry evidenceRefs, not the shared omission-record
	// helper's omittedKind/sourceField members.
	omission := jsonshape.Object(
		jsonshape.Required("escalation", text), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)),
		jsonshape.Required("nonClaim", text), jsonshape.Required("omissionId", text),
		jsonshape.Required("omittedCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("reason", text),
	)
	return agentenvelope.StructureWithTokenBudget(kind+".agent-envelope", agentenvelope.StructureParts{
		ActionPlan: jsonshape.BoundedArray(agentenvelope.ActionStructure(
			jsonshape.Enum(map[string]struct{}{"route": {}, "verify": {}})), 3, 3),
		BlockedPreconditions: blockers, Bounds: agentenvelope.CompatibilityBoundsWithTokenBudgetStructure(budget),
		ClarificationQuestions: clarifications, Commands: jsonshape.Tuple(),
		ContextRefs: jsonshape.BoundedArray(agentenvelope.ContextRefStructure(jsonshape.StringLiteral("json-pointer"),
			jsonshape.Enum(map[string]struct{}{"supporting": {}, "rule_reference": {}})), contexts, contexts),
		Omitted: jsonshape.BoundedArray(omission, 0, 2), ReceiptRefs: jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport:   agentenvelope.SourceReportStructure(kind, jsonshape.StringLiteral(kind), jsonshape.Null(), states),
	}, budget)
}
