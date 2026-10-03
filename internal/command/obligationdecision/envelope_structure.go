package obligationdecision

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func EnvelopeStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	kinds := jsonshape.Enum(map[string]struct{}{"requirement": {}, "proof-route": {}, "evidence": {}})
	receiptStates := jsonshape.Enum(map[string]struct{}{"missing_receipt": {}, "invalid_receipt": {}, "stale_receipt": {}})
	receipt := jsonshape.Object(
		jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)), jsonshape.Required("nonClaim", text), jsonshape.Required("obligationId", id),
		jsonshape.Required("owner", text), jsonshape.Required("proofRouteRef", id), jsonshape.Required("receiptClass", receiptStates),
		jsonshape.Required("receiptRefId", text), jsonshape.Required("requirementId", id), jsonshape.Required("selectedState", receiptStates),
	)
	omission := jsonshape.Object(jsonshape.Required("nonClaim", text), jsonshape.Required("omissionId", text),
		jsonshape.Required("omittedCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("owner", text), jsonshape.Required("reason", text))
	schema := agentenvelope.Structure("proofkit.obligation-decision.agent-envelope", agentenvelope.StructureParts{
		ActionPlan:           jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.Enum(map[string]struct{}{"route": {}, "verify": {}, "review": {}})), 0, maxEnvelopeDecisions),
		BlockedPreconditions: jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions), Bounds: agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.Enum(map[string]struct{}{"scope_decision": {}, "live_environment_decision": {}, "deferral_owner_decision": {}, "advisory_owner_decision": {}})), 0, agentenvelope.MaxClarificationQuestions),
		Commands:               jsonshape.Tuple(), ContextRefs: jsonshape.BoundedArray(agentenvelope.ContextRefStructure(kinds, kinds), 0, agentenvelope.MaxContextRefs),
		Omitted:     jsonshape.BoundedArray(jsonshape.OneOf(omission, agentenvelope.OmissionStructure()), 0, 1),
		ReceiptRefs: jsonshape.BoundedArray(receipt, 0, maxEnvelopeDecisions), RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport: agentenvelope.SourceReportStructure(reportKind, id, jsonshape.Null(), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})),
	}).JSONSchema()
	schema["description"] = "At most twenty actionable decisions produce actions; satisfied/not_applicable produce none. Commands are always empty. The kernel caps contexts at 48, even when declared maxContextRefs is larger, and prunes dangling local refs. Native logic owns role equality, receiptClass/selectedState equality, decision-to-guidance mapping, count and bounds relations, and omission aggregation. Source hash and artifact ref are null. This report does not approve edits or merge. Invalid caller input uses the separate invalid-input variant."
	return schema
}
