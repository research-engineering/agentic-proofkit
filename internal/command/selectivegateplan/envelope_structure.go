package selectivegateplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func EnvelopeStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	command := jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("commandId", text),
		jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text), jsonshape.Required("purpose", text))
	receipt := jsonshape.Object(
		jsonshape.Required("commandId", text), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)),
		jsonshape.Required("kind", jsonshape.StringLiteral("required_receipt_class")), jsonshape.Required("nonClaim", text),
		jsonshape.Required("owner", text), jsonshape.Required("producer", jsonshape.Null()),
		jsonshape.Required("producerAdmission", jsonshape.StringLiteral("required")), jsonshape.Required("receiptRefId", text), jsonshape.Required("ref", text),
	)
	omission := jsonshape.Object(jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)), jsonshape.Required("escalation", text),
		jsonshape.Required("nonClaim", text), jsonshape.Required("omissionId", text), jsonshape.Required("omittedCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("reason", text))
	schema := agentenvelope.Structure("proofkit.selective-gate-plan.agent-envelope", agentenvelope.StructureParts{
		ActionPlan:           jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.Enum(map[string]struct{}{"route": {}, "verify": {}})), 2, 2),
		BlockedPreconditions: jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions), Bounds: agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral("owner_decision")), 0, agentenvelope.MaxClarificationQuestions),
		Commands:               jsonshape.BoundedArray(command, 0, commandLimit),
		ContextRefs:            jsonshape.BoundedArray(agentenvelope.ContextRefStructure(jsonshape.Enum(map[string]struct{}{"evidence": {}, "path": {}}), jsonshape.Enum(map[string]struct{}{"generated_lookup": {}, "owner_surface": {}, "proof_binding": {}})), 0, contextLimit),
		Omitted:                jsonshape.BoundedArray(jsonshape.OneOf(omission, agentenvelope.OmissionStructure()), 0, agentenvelope.MaxOmittedItems),
		ReceiptRefs:            jsonshape.BoundedArray(receipt, 0, commandLimit), RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport: agentenvelope.SourceReportStructure("proofkit.selective-gate-plan", jsonshape.StringLiteral("proofkit.selective-gate-plan"), jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})),
	}).JSONSchema()
	schema["description"] = "The two actions and three route questions remain; referenced commands, contexts and receipts can be pruned on identity ambiguity or bounds. Pruning may empty reference arrays and adds typed kernel omissions. Native Build owns ordering, reference closure, effective counts, escalation and source hash. Declared bounds do not prove a tokenizer budget. This envelope remains derived guidance, not proof truth or permission. Invalid caller input uses the separate invalid-input variant."
	return schema
}
