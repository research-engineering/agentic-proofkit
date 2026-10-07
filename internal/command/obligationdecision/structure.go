package obligationdecision

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("decisionId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 1)),
		jsonshape.Required("obligations", jsonshape.Array(jsonshape.Object(obligationFields()...), 1)),
	).JSONSchema()
	schema["description"] = "Every member is required and nonnull; obligations, candidateStates, evidenceRefs and nonClaims are nonempty. Native admission owns privacy, canonical repository-relative evidence paths, normalized uniqueness, unique obligation IDs and sorting. Candidate states are sorted by the shared decision priority before selecting the first state. Root nonClaims must not duplicate builtin boundary claims after normalization. Structure is not evidence truth or merge approval."
	return schema
}

func obligationFields() []jsonshape.Property {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return []jsonshape.Property{
		jsonshape.Required("candidateStates", jsonshape.Array(jsonshape.Enum(decisionStateSet), 1)),
		jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("obligationClass", jsonshape.Enum(decisionClasses)),
		jsonshape.Required("obligationId", id), jsonshape.Required("owner", text),
		jsonshape.Required("proofRouteRef", id), jsonshape.Required("reason", text), jsonshape.Required("requirementId", id),
	}
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerMinimum(0)
	selected := []jsonshape.Property{
		jsonshape.Required("blocksProofSatisfaction", jsonshape.Boolean()),
		jsonshape.Required("decisionRank", jsonshape.IntegerRange(0, int64(len(decisionStates)-1))),
		jsonshape.Required("decisionState", jsonshape.Enum(decisionStateSet)),
	}
	decision := jsonshape.Object(append(obligationFields(), selected...)...)
	ruleFields := append([]jsonshape.Property{}, selected...)
	ruleFields = append(ruleFields,
		jsonshape.Required("candidateStates", jsonshape.Array(jsonshape.Enum(decisionStateSet), 1)),
		jsonshape.Required("obligationClass", jsonshape.Enum(decisionClasses)),
		jsonshape.Required("proofRouteRef", id), jsonshape.Required("requirementId", id))
	counts := make([]jsonshape.Property, 0, len(decisionStates))
	for _, state := range decisionStates {
		counts = append(counts, jsonshape.Required(state, count))
	}
	summary := jsonshape.Object(
		jsonshape.Required("advisoryObligationCount", count), jsonshape.Required("blockingObligationCount", count),
		jsonshape.Required("blockingUnsatisfiedCount", count), jsonshape.Required("deferredObligationCount", count),
		jsonshape.Required("obligationCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("stateCounts", jsonshape.Object(counts...)),
	)
	rulePrefix := "proofkit.obligation-decision."
	rule := report.RuleStructure(
		jsonshape.BoundedStringGrammar(`proofkit\.obligation-decision\.(?:`+admit.RuleIDPatternBody+`)`, len(rulePrefix)+admit.MaxRuleIDBytes),
		jsonshape.Enum(map[string]struct{}{"failed": {}, "passed": {}, "skipped": {}, "warning": {}}), text,
		jsonshape.Tuple(report.DiagnosticStructure("decision", jsonshape.Object(ruleFields...))),
	)
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"failed": {}, "passed": {}}), summary,
		jsonshape.Tuple(report.DiagnosticStructure("blockingUnsatisfiedObligationIds", jsonshape.Array(id, 0)), report.DiagnosticStructure("decisions", jsonshape.Array(decision, 1))),
		jsonshape.Array(rule, 1),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	properties["nonClaims"] = jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	schema["description"] = "reportId preserves decisionId. Native derivation owns priority/rank equality, decision/rule bijection, summary counts, sorted IDs and merged nonClaims. A blocking obligation blocks proof satisfaction except for satisfied or not_applicable; the report fails exactly when at least one obligation blocks. Other classes may retain unresolved states without a failed report. Rule diagnostics are projections of the corresponding decision. Passed reports exit 0; failed reports exit 1. Neither classification approves merge nor executes proof."
	return schema
}
