package selectivegateevidence

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func EnvelopeStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	command := jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("commandId", text),
		jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text), jsonshape.Required("purpose", text))
	receipts := []jsonshape.Shape{}
	for _, pair := range [][2]string{{"required_receipt_class", "required"}, {"receipt_artifact", "unverified"}} {
		receipts = append(receipts, jsonshape.Object(
			jsonshape.Required("commandId", text), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)),
			jsonshape.Required("kind", jsonshape.StringLiteral(pair[0])), jsonshape.Required("nonClaim", text),
			jsonshape.Required("owner", text), jsonshape.Required("producer", jsonshape.Null()),
			jsonshape.Required("producerAdmission", jsonshape.StringLiteral(pair[1])), jsonshape.Required("receiptRefId", text), jsonshape.Required("ref", text),
		))
	}
	omission := jsonshape.Object(jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)), jsonshape.Required("escalation", text),
		jsonshape.Required("nonClaim", text), jsonshape.Required("omissionId", text), jsonshape.Required("omittedCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("reason", text))
	schema := agentenvelope.Structure("proofkit.selective-gate-evidence.agent-envelope", agentenvelope.StructureParts{
		ActionPlan:           jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.Enum(map[string]struct{}{"route": {}, "verify": {}})), 2, 2),
		BlockedPreconditions: jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions), Bounds: agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral("owner_decision")), 0, agentenvelope.MaxClarificationQuestions),
		Commands:               jsonshape.BoundedArray(command, 0, itemLimit),
		ContextRefs:            jsonshape.BoundedArray(agentenvelope.ContextRefStructure(jsonshape.StringLiteral("evidence"), jsonshape.Enum(map[string]struct{}{"evidence": {}, "generated_lookup": {}})), 0, 2),
		Omitted:                jsonshape.BoundedArray(jsonshape.OneOf(omission, agentenvelope.OmissionStructure()), 0, agentenvelope.MaxOmittedItems),
		ReceiptRefs:            jsonshape.BoundedArray(jsonshape.DiscriminatedUnion("kind", receipts...), 0, itemLimit),
		RouteQuestions:         jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport:           agentenvelope.SourceReportStructure("proofkit.selective-gate-evidence", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "blocked": {}})),
	}).JSONSchema()
	schema["description"] = "Two guidance actions classify receipt gaps. Receipt refs distinguish missing required classes from supplied artifacts. Native Build may prune local identities/references, truncate lists, add omissions and update cost/bounds facts. Record ordering, source hash, count equalities and source-report linkage remain native. No evidence is executed, authenticated or declared fresh by this view. Invalid caller input uses the separate invalid-input variant."
	return schema
}
