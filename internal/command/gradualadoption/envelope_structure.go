package gradualadoption

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func GuidanceEnvelopeStructure() map[string]any  { return envelopeStructure(false) }
func BootstrapEnvelopeStructure() map[string]any { return envelopeStructure(true) }

func envelopeStructure(bootstrap bool) map[string]any {
	t := jsonshape.String()
	kind := "proofkit.gradual-adoption-guidance"
	if bootstrap {
		kind = "proofkit.gradual-adoption-bootstrap"
	}
	parts := agentenvelope.StructureParts{
		ActionPlan:           jsonshape.BoundedArray(agentenvelope.ActionStructure(statesShape("route", "modernize-boundary", "bind", "verify", "promote")), 0, agentenvelope.MaxActionItems),
		BlockedPreconditions: jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions), Bounds: agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(statesShape("missing_witness", "blocked_external_input", "owner_boundary_decision")), 0, agentenvelope.MaxClarificationQuestions),
		Commands: jsonshape.BoundedArray(shapeFields(map[string]jsonshape.Shape{
			"command": t, "commandId": t, "nonClaim": t, "owner": jsonshape.StringLiteral("consumer_repository"), "purpose": t,
		}), 0, agentenvelope.MaxCommandRefs),
		ContextRefs: jsonshape.BoundedArray(agentenvelope.ContextRefStructure(statesShape("path", "rule", "candidate-boundary"),
			statesShape("evidence", "proof_binding", "spec_source", "rule_reference", "candidate_boundary", "command_registry", "owner_surface", "supporting")), 0, agentenvelope.MaxContextRefs),
		Omitted: jsonshape.BoundedArray(agentenvelope.OmissionStructure(), 0, agentenvelope.MaxOmittedItems), ReceiptRefs: jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport:   agentenvelope.SourceReportStructure(kind, t, jsonshape.Null(), statesShape("passed", "failed", "blocked")),
	}
	schema := agentenvelope.Structure("placeholder", parts).JSONSchema()
	schema["properties"].(map[string]any)["envelopeId"] = jsonshape.StringSuffix(".agent-envelope").JSONSchema()
	if !bootstrap {
		// The suffix can make an admitted ID secret-shaped after construction.
		schema["properties"].(map[string]any)["envelopeId"] = map[string]any{"anyOf": []any{
			jsonshape.StringSuffix(".agent-envelope").JSONSchema(),
			jsonshape.StringLiteral(admit.DiagnosticRedactionMarker).JSONSchema(),
		}}
	}
	// Failure-collecting producers retain empty normalized targets. Only their
	// carrier broadens this leaf; the shared admitted-reference owner is unchanged.
	refs := schema["properties"].(map[string]any)["contextRefs"].(map[string]any)
	refs["items"].(map[string]any)["properties"].(map[string]any)["ref"] = t.JSONSchema()
	return outputDescription(schema)
}
