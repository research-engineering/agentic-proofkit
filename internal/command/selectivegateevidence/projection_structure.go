package selectivegateevidence

import (
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/receiptcurrentnessscope"
	"github.com/research-engineering/agentic-proofkit/internal/command/receipttrustclass"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func ProjectionInputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 1)
	route := jsonshape.Object(
		jsonshape.Required("command", text), jsonshape.Required("commandId", id), jsonshape.Required("evidenceRefs", texts),
		jsonshape.Required("nonClaims", texts), jsonshape.Required("obligationClass", jsonshape.Enum(obligationClassSet)),
		jsonshape.Required("obligationId", id), jsonshape.Required("owner", text), jsonshape.Required("proofRouteRef", id),
		jsonshape.Required("reason", text), jsonshape.Required("requirementId", id), jsonshape.Optional("sourcePath", jsonshape.Nullable(text)),
	)
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)), jsonshape.Required("decisionId", id),
		jsonshape.Required("commandRoutes", jsonshape.Array(route, 0)), jsonshape.Required("nonClaims", texts),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["evidence"] = InputStructure()
	required := append(schema["required"].([]any), "evidence")
	sort.Slice(required, func(i, j int) bool { return required[i].(string) < required[j].(string) })
	schema["required"] = required
	properties["receiptCurrentnessScopeAdmission"] = map[string]any{"oneOf": []any{map[string]any{"type": "null"}, receiptcurrentnessscope.InputStructure()}}
	properties["receiptTrustClassAdmission"] = map[string]any{"oneOf": []any{map[string]any{"type": "null"}, receipttrustclass.InputStructure()}}
	schema["description"] = "Evidence is the selective-gate-evidence input, not its report. Missing/null currentness and trust inputs are allowed and add unknown_scope and invalid_producer respectively; supplied inputs use their child owners. Native checks require unique route command keys and obligation IDs, complete planned-command routing, scoped failure projection and matching requirement, route, receipt and producer identities across children. Unscoped plan/preexisting/producer failures and unexpected receipts reject. Route sourcePath admits absence/null, unlike evidence receipt sourcePath. No agent-envelope mode exists for this projector. Its output reuses the decision input structure, not a guarantee of downstream semantic admission: obligation-decision still rejects root nonClaims that collide with its builtin boundary claims after normalization."
	return schema
}
