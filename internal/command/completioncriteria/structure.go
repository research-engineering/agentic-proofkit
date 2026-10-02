package completioncriteria

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"completionId", "criteria", "nonClaims", "schemaVersion"}
var criterionKeys = []string{"blocker", "criterion", "criterionClass", "criterionId", "evidenceRefs", "failsWhen", "nonClaims", "owner", "proofRefs", "status", "structuredDecisionRefs", "validatorRefs"}

func criterionFields() map[string]jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return map[string]jsonshape.Shape{
		"blocker": jsonshape.Nullable(text), "criterion": text, "criterionClass": jsonshape.Enum(criterionClasses),
		"criterionId":  jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes),
		"evidenceRefs": jsonshape.Array(text, 0), "failsWhen": jsonshape.Array(text, 1),
		"nonClaims": jsonshape.Array(text, 1), "owner": text, "proofRefs": jsonshape.Array(text, 0),
		"status": jsonshape.Enum(criterionStatuses), "structuredDecisionRefs": jsonshape.Array(text, 0),
		"validatorRefs": jsonshape.Array(text, 0),
	}
}

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"completionId": jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes),
		"criteria":     jsonshape.Array(jsonshape.ObjectFromKeys(criterionKeys, criterionFields(), "blocker"), 1),
		"nonClaims":    jsonshape.Array(text, 1), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["nonClaims"].(map[string]any)["uniqueItems"] = true
	properties["nonClaims"].(map[string]any)["items"].(map[string]any)["not"] = map[string]any{"enum": boundaryNonClaims}
	properties["criteria"].(map[string]any)["uniqueItems"] = true
	criterion := properties["criteria"].(map[string]any)["items"].(map[string]any)
	fields := criterion["properties"].(map[string]any)
	for _, name := range []string{"evidenceRefs", "failsWhen", "nonClaims", "proofRefs", "structuredDecisionRefs", "validatorRefs"} {
		fields[name].(map[string]any)["uniqueItems"] = true
	}
	status := func(values ...string) map[string]any {
		return map[string]any{"required": []any{"status"}, "properties": map[string]any{"status": map[string]any{"enum": admit.StringSliceToAny(values)}}}
	}
	criterion["allOf"] = []any{
		map[string]any{
			"if":   status("blocked_missing_precondition"),
			"then": map[string]any{"required": []any{"blocker"}, "properties": map[string]any{"blocker": text.JSONSchema()}},
			"else": map[string]any{"properties": map[string]any{"blocker": jsonshape.Null().JSONSchema()}},
		},
		map[string]any{"if": status("satisfied", "not_applicable", "deferred_admitted"), "then": map[string]any{"properties": map[string]any{"evidenceRefs": jsonshape.Array(text, 1).JSONSchema()}}},
		map[string]any{"if": status("deferred_admitted"), "then": map[string]any{"properties": map[string]any{"criterionClass": map[string]any{"const": "deferred"}}}},
		map[string]any{"if": status("advisory_skipped"), "then": map[string]any{"properties": map[string]any{"criterionClass": map[string]any{"const": "advisory"}}}},
		map[string]any{"anyOf": []any{
			map[string]any{"properties": map[string]any{"proofRefs": jsonshape.Array(text, 1).JSONSchema()}},
			map[string]any{"properties": map[string]any{"validatorRefs": jsonshape.Array(text, 1).JSONSchema()}},
		}},
	}
	schema["description"] = "All fields except criterion.blocker are required. Missing blocker equals null; it is nonempty exactly for blocked_missing_precondition. Criteria are sorted by unique criterionId. Text and reference arrays are trimmed, sorted and reject normalized duplicates; refs remain opaque text. failsWhen/nonClaims are nonempty; other arrays may be empty, but proofRefs or validatorRefs must be nonempty. Satisfied/not_applicable/deferred_admitted require evidence; deferred_admitted and advisory_skipped restrict class. Root builtin/caller nonClaim collisions reject. Privacy, canonical IDs, normalized uniqueness and exact integer token spelling remain native. Only unsatisfied blocking criteria fail the overall report; an admitted advisory/deferred failure may produce a warning with overall passed state."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	fields := criterionFields()
	fields["blocksCompletion"] = jsonshape.Boolean()
	keys := append(append([]string{}, criterionKeys...), "blocksCompletion")
	criterion := jsonshape.RequiredObject(keys, fields)
	counts := make([]jsonshape.Property, 0, len(criterionStatuses))
	for status := range criterionStatuses {
		counts = append(counts, jsonshape.Required(status, jsonshape.IntegerMinimum(0)))
	}
	summary := jsonshape.Object(
		jsonshape.Required("advisoryCriterionCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("blockingCriterionCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("blockingUnsatisfiedCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("criterionCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("deferredCriterionCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("statusCounts", jsonshape.Object(counts...)),
	)
	rule := report.RuleStructure(
		jsonshape.BoundedStringGrammar(regexp.QuoteMeta(reportKind+".")+admit.RuleIDPatternBody, len(reportKind)+1+admit.MaxRuleIDBytes),
		jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "skipped": {}, "warning": {}}),
		text, jsonshape.Tuple(report.DiagnosticStructure("criterion", criterion)),
	)
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}), summary,
		jsonshape.Tuple(report.DiagnosticStructure("blockingUnsatisfiedCriterionIds", jsonshape.Array(id, 0)), report.DiagnosticStructure("criteria", jsonshape.Array(criterion, 1))),
		jsonshape.Array(rule, 1),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	claims["uniqueItems"] = true
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	diagnostics := properties["diagnostics"].(map[string]any)["prefixItems"].([]any)
	diagnostics[0].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)["uniqueItems"] = true
	criteria := diagnostics[1].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)
	criteria["uniqueItems"] = true
	ruleFields := properties["ruleResults"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	ruleDiagnostics := ruleFields["diagnostics"].(map[string]any)["prefixItems"].([]any)
	ruleCriterion := ruleDiagnostics[0].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)
	for _, item := range []map[string]any{criteria["items"].(map[string]any), ruleCriterion} {
		for _, name := range []string{"evidenceRefs", "failsWhen", "nonClaims", "proofRefs", "structuredDecisionRefs", "validatorRefs"} {
			item["properties"].(map[string]any)[name].(map[string]any)["uniqueItems"] = true
		}
	}
	schema["description"] = "ReportId preserves completionId. Both criterion projections contain an explicit nullable blocker and blocksCompletion. Counts and the complete statusCounts vocabulary derive from admitted criteria, including zero bins. Only unsatisfied blocking criteria fail the report; rules independently use failed, passed, skipped or warning. Rule IDs prepend the report kind and a dot to criterionId, so their maximum is285ASCII bytes rather than256. Criterion identity, class/status relations, count equality, canonical order, messages and cross-projection equality remain native. Mandatory builtin and caller nonClaims are sorted and unique. The report does not execute validators, authenticate evidence, prove freshness or approve completion/merge/release policy."
	return schema
}
