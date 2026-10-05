package changedpathset

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func EnvelopeStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	omission := jsonshape.Object(jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)),
		jsonshape.Required("escalation", text), jsonshape.Required("nonClaim", text),
		jsonshape.Required("omissionId", text), jsonshape.Required("omittedCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("reason", text))
	schema := agentenvelope.Structure("", agentenvelope.StructureParts{
		ActionPlan:             jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.Enum(map[string]struct{}{"route": {}, "verify": {}})), 3, 3),
		BlockedPreconditions:   jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, 1),
		Bounds:                 agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral("policy_choice")), 0, 1),
		Commands:               jsonshape.Tuple(), ReceiptRefs: jsonshape.Tuple(),
		ContextRefs: jsonshape.BoundedArray(agentenvelope.ContextRefStructure(jsonshape.StringLiteral("json-pointer"),
			jsonshape.Enum(map[string]struct{}{"evidence": {}, "supporting": {}, "rule_reference": {}})), 6, 6),
		Omitted:        jsonshape.BoundedArray(omission, 0, 5),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport: agentenvelope.SourceReportStructure("proofkit.changed-path-set", id,
			jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["envelopeId"] = text.JSONSchema()
	// This producer supplies a token-budget declaration, unlike count-only plans.
	for _, name := range []string{"bounds", "costContract"} {
		properties[name].(map[string]any)["properties"].(map[string]any)["maxTokenBudget"] = jsonshape.IntegerLiteral(2200).JSONSchema()
	}
	schema["description"] = "This command uses three fixed actions, six context references, three route questions and no commands or receipt records. A failed source adds one blocker; an empty successful source adds one clarification. Up to five omission records summarize nonempty source fields; they retain references to the six constant context IDs. SourceReport and envelopeId are derived from the admitted report and sanitized by the envelope owner. Declared maxTokenBudget=2200 is not measured tokenizer cost. Native Build owns source identity/hash, ordering, reference closure, count/state relationships, redaction and escalation. Invalid input uses the separately declared invalid-input envelope."
	return schema
}
