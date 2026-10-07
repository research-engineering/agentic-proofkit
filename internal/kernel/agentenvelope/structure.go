package agentenvelope

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// Descriptors share Build's limits without copying their numeric policy.
const (
	MaxBlockedPreconditions   = hardMaxBlockedPreconditions
	MaxClarificationQuestions = hardMaxClarificationQuestions
	MaxContextRefs            = hardMaxContextRefs
	MaxOmittedItems           = hardMaxOmittedItems
)

// StructureParts describes one producer's complete post-Build carrier. Build
// accepts heterogeneous records, so their schemas remain with each producer.
type StructureParts struct {
	ActionPlan, BlockedPreconditions, Bounds, ClarificationQuestions jsonshape.Shape
	Commands, ContextRefs, Omitted, ReceiptRefs, RouteQuestions      jsonshape.Shape
	SourceReport                                                     jsonshape.Shape
}

func Structure(envelopeID string, parts StructureParts) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerMinimum(0)
	cost := []jsonshape.Property{
		jsonshape.Required("affectedRequirementCount", jsonshape.Null()),
		jsonshape.Required("escalation", text), jsonshape.Required("graphQueryCount", jsonshape.IntegerLiteral(0)),
		jsonshape.Required("maxTokenBudget", jsonshape.Null()), jsonshape.Required("nonClaim", text),
		jsonshape.Required("omittedEdgesCounted", jsonshape.BooleanLiteral(true)),
		jsonshape.Required("referenceClosurePreserved", jsonshape.Boolean()),
		jsonshape.Required("stopReason", jsonshape.Enum(map[string]struct{}{"blocked_precondition": {}, "wide_or_full_gate_required": {}, "caller_review_required": {}})),
		jsonshape.Required("sufficiencyBasis", text),
	}
	for _, field := range []struct {
		name string
		max  int
	}{
		{"actionEvidenceRefCount", hardMaxActionEvidenceRefs}, {"actionItemCount", hardMaxActionItems},
		{"blockedPreconditionCount", hardMaxBlockedPreconditions}, {"clarificationQuestionCount", hardMaxClarificationQuestions},
		{"commandRefCount", hardMaxCommandRefs}, {"loadedRefCount", hardMaxContextRefs},
		{"receiptRecordCount", hardMaxReceiptRefs}, {"routeQuestionCount", hardMaxRouteQuestions},
	} {
		cost = append(cost, jsonshape.Required(field.name, jsonshape.IntegerRange(0, int64(field.max))))
	}
	for _, name := range []string{"boundsViolationCount", "omittedEdgeCount", "prunedLocalReferenceCount"} {
		cost = append(cost, jsonshape.Required(name, count))
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)), jsonshape.Required("envelopeId", jsonshape.StringLiteral(envelopeID)),
		jsonshape.Required("actionPlan", parts.ActionPlan), jsonshape.Required("blockedPreconditions", parts.BlockedPreconditions),
		jsonshape.Required("bounds", parts.Bounds), jsonshape.Required("clarificationQuestions", parts.ClarificationQuestions),
		jsonshape.Required("commands", parts.Commands), jsonshape.Required("contextRefs", parts.ContextRefs),
		jsonshape.Required("costContract", jsonshape.Object(cost...)), jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("omitted", parts.Omitted), jsonshape.Required("receiptRefs", parts.ReceiptRefs),
		jsonshape.Required("routeQuestions", parts.RouteQuestions), jsonshape.Required("sourceReport", parts.SourceReport),
	)
}

func SourceReportStructure(kind string, id, hash, state jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("artifactRef", jsonshape.Null()),
		jsonshape.Required("nonClaim", jsonshape.StringLiteral("Source report is projected because agent guidance envelopes do not carry full caller-owned report payloads.")),
		jsonshape.Required("reportId", id), jsonshape.Required("reportKind", jsonshape.StringLiteral(kind)),
		jsonshape.Required("stableHash", hash), jsonshape.Required("state", state),
	)
}

// CompatibilityBoundsStructure describes the shared item-count-only bounds
// used by these producers. Declared counts are not capped at effective limits.
func CompatibilityBoundsStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerMinimum(0)
	fields := []jsonshape.Property{
		jsonshape.Required("escalation", text), jsonshape.Required("fanout", jsonshape.Enum(map[string]struct{}{"bounded": {}, "wide": {}, "full-gate": {}, "wide_or_full_gate_required": {}})),
		jsonshape.Required("maxTokenBudget", jsonshape.Null()), jsonshape.Required("nonClaim", text),
		jsonshape.Optional("truncated", jsonshape.BooleanLiteral(true)),
		jsonshape.Optional("referenceClosurePreserved", jsonshape.BooleanLiteral(false)),
		jsonshape.Optional("prunedLocalReferenceCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Optional("boundsViolationCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Optional("boundsViolations", jsonshape.Array(text, 1)),
	}
	for _, name := range []string{"maxActionItems", "maxCommandRefs", "maxContextRefs", "maxOmittedItems", "maxReceiptRefs", "omittedCount"} {
		fields = append(fields, jsonshape.Required(name, count))
	}
	return jsonshape.Object(fields...)
}

func OmissionStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(
		jsonshape.Required("escalation", text), jsonshape.Required("nonClaim", text), jsonshape.Required("omissionId", text),
		jsonshape.Required("omittedCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("omittedKind", text),
		jsonshape.Required("reason", text), jsonshape.Required("sourceField", text),
	)
}

// Guidance record helpers describe a shared vocabulary, not arbitrary Input
// maps or permission to execute the referenced instructions.
func ActionStructure(phases jsonshape.Shape) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(
		jsonshape.Required("commandIds", jsonshape.Array(text, 0)), jsonshape.Required("evidenceRefs", jsonshape.BoundedArray(text, 0, hardMaxActionEvidenceRefs)),
		jsonshape.Required("instruction", text), jsonshape.Required("nonClaims", jsonshape.Array(text, 1)), jsonshape.Required("owner", text),
		jsonshape.Required("phase", phases), jsonshape.Required("rationale", text), jsonshape.Required("stepId", text),
	)
}

func BlockedStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(jsonshape.Required("description", text), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)),
		jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text), jsonshape.Required("preconditionId", text))
}

func ClarificationStructure(kinds jsonshape.Shape) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(jsonshape.Required("askWhen", text), jsonshape.Required("blocking", jsonshape.Boolean()),
		jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)), jsonshape.Required("expectedAnswerKind", kinds),
		jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text), jsonshape.Required("question", text), jsonshape.Required("questionId", text))
}

func ContextRefStructure(kinds, roles jsonshape.Shape) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(jsonshape.Required("kind", kinds), jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text),
		jsonshape.Required("purpose", text), jsonshape.Required("ref", text), jsonshape.Required("refId", text), jsonshape.Required("role", roles))
}

func RouteQuestionStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)), jsonshape.Required("nonClaim", text),
		jsonshape.Required("question", text), jsonshape.Required("questionId", text))
}

func InvalidInputStructure() map[string]any {
	identity := "proofkit.agent-envelope.invalid-input"
	return Structure(identity, StructureParts{
		ActionPlan:           jsonshape.BoundedArray(ActionStructure(jsonshape.StringLiteral("route")), 1, 1),
		BlockedPreconditions: jsonshape.BoundedArray(BlockedStructure(), 1, 1), Bounds: CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(ClarificationStructure(jsonshape.StringLiteral("missing_context_ref")), 1, 1),
		Commands:               jsonshape.Tuple(), ContextRefs: jsonshape.Tuple(), Omitted: jsonshape.Tuple(), ReceiptRefs: jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(RouteQuestionStructure(), 3, 3),
		SourceReport:   SourceReportStructure(identity, jsonshape.StringLiteral(identity), jsonshape.Null(), jsonshape.StringLiteral("failed")),
	}).JSONSchema()
}
