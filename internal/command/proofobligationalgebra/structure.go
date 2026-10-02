package proofobligationalgebra

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"algebraId", "nonClaims", "obligations", "schemaVersion"}
var obligationKeys = []string{"childObligationIds", "conditionRefs", "delegationRefs", "evidenceRefs", "expiryRef", "nonClaims", "obligationId", "obligationKind", "owner", "proofRouteRefs", "rationale", "requirementId", "reviewConditionRef"}

func obligationFields() map[string]jsonshape.Shape {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return map[string]jsonshape.Shape{
		"childObligationIds": jsonshape.BoundedArray(id, 0, maxObligationEdgeCount),
		"conditionRefs":      jsonshape.Array(id, 0), "delegationRefs": jsonshape.Array(id, 0),
		"evidenceRefs": jsonshape.Array(text, 0), "expiryRef": jsonshape.Nullable(text),
		"nonClaims": jsonshape.Array(text, 1), "obligationId": id, "obligationKind": jsonshape.Enum(obligationKinds),
		"owner": text, "proofRouteRefs": jsonshape.Array(id, 0), "rationale": text,
		"requirementId": id, "reviewConditionRef": jsonshape.Nullable(text),
	}
}

func refineObligationLists(schema map[string]any) {
	fields := schema["properties"].(map[string]any)
	for _, name := range []string{"childObligationIds", "conditionRefs", "delegationRefs", "evidenceRefs", "nonClaims", "proofRouteRefs", "transitiveChildObligationIds"} {
		if field, ok := fields[name]; ok {
			field.(map[string]any)["uniqueItems"] = true
		}
	}
}

func InputStructure() map[string]any {
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"algebraId":     jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes),
		"nonClaims":     jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 1),
		"obligations":   jsonshape.BoundedArray(jsonshape.ObjectFromKeys(obligationKeys, obligationFields(), "expiryRef", "reviewConditionRef"), 1, maxObligationCount),
		"schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	claims := properties["nonClaims"].(map[string]any)
	claims["uniqueItems"] = true
	claims["items"].(map[string]any)["not"] = map[string]any{"enum": admit.StringSliceToAny(boundaryNonClaims)}
	obligations := properties["obligations"].(map[string]any)
	obligations["uniqueItems"] = true
	refineObligationLists(obligations["items"].(map[string]any))
	schema["description"] = "All members except expiryRef/reviewConditionRef are required; both exceptions are optional nullable nonempty text. Obligation rows sort by unique obligationId. ID/path lists must already be canonical sorted unique; evidence paths preserve spaces and use safe repository-relative POSIX admission. Text is privacy admitted; root builtin nonClaim collisions reject. At most2048obligations,16384total child edges and65536total transitive refs are admitted; the latter two aggregate bounds remain native. Kind-specific relations, missing children, cycles and cross-requirement edges produce failed reports, not malformed-input rejection. IDs, canonical integer spelling, privacy, normalized text uniqueness, path safety and graph evaluation remain native. No proof satisfaction or delegation authorization follows from admission."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerRange(0, maxObligationCount)
	fields := obligationFields()
	fields["graphDepth"] = jsonshape.Nullable(jsonshape.IntegerRange(0, maxObligationCount))
	fields["routeBearing"] = jsonshape.Boolean()
	fields["structuralFindings"] = jsonshape.Array(text, 0)
	fields["transitiveChildObligationIds"] = jsonshape.BoundedArray(id, 0, maxTransitiveReferenceCount)
	keys := append(append([]string{}, obligationKeys...), "graphDepth", "routeBearing", "structuralFindings", "transitiveChildObligationIds")
	obligation := jsonshape.RequiredObject(keys, fields)
	kinds := make([]jsonshape.Property, 0, len(obligationKinds))
	for kind := range obligationKinds {
		kinds = append(kinds, jsonshape.Required(kind, count))
	}
	rule := report.RuleStructure(
		jsonshape.BoundedStringGrammar(regexp.QuoteMeta(reportKind+".")+admit.RuleIDPatternBody, len(reportKind)+1+admit.MaxRuleIDBytes),
		jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "skipped": {}}), text,
		jsonshape.Tuple(report.DiagnosticStructure("obligation", obligation)),
	)
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}), jsonshape.Object(
		jsonshape.Required("crossRequirementDelegationCount", jsonshape.IntegerLiteral(0)),
		jsonshape.Required("failedObligationCount", count), jsonshape.Required("kindCounts", jsonshape.Object(kinds...)),
		jsonshape.Required("nonRouteBearingObligationCount", count), jsonshape.Required("obligationCount", jsonshape.IntegerRange(1, maxObligationCount)),
		jsonshape.Required("routeBearingObligationCount", count), jsonshape.Required("rootObligationCount", count),
	), jsonshape.Tuple(
		report.DiagnosticStructure("failedObligationIds", jsonshape.BoundedArray(id, 0, maxObligationCount)),
		report.DiagnosticStructure("nonRouteBearingObligationIds", jsonshape.BoundedArray(id, 0, maxObligationCount)),
		report.DiagnosticStructure("obligations", jsonshape.BoundedArray(obligation, 1, maxObligationCount)),
		report.DiagnosticStructure("rootObligationIds", jsonshape.BoundedArray(id, 0, maxObligationCount)),
	), jsonshape.BoundedArray(rule, 1, maxObligationCount)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	claims["uniqueItems"] = true
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	for _, diagnostic := range properties["diagnostics"].(map[string]any)["prefixItems"].([]any) {
		entry := diagnostic.(map[string]any)["properties"].(map[string]any)
		value := entry["value"].(map[string]any)
		value["uniqueItems"] = true
		if entry["key"].(map[string]any)["const"] == "obligations" {
			refineObligationLists(value["items"].(map[string]any))
		}
	}
	ruleFields := properties["ruleResults"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	ruleDiagnostic := ruleFields["diagnostics"].(map[string]any)["prefixItems"].([]any)[0].(map[string]any)
	refineObligationLists(ruleDiagnostic["properties"].(map[string]any)["value"].(map[string]any))
	schema["description"] = "ReportId preserves algebraId. All six kindCounts bins exist including zeros. Obligation copies have required nullable expiryRef/reviewConditionRef and graphDepth. Depth is null for cycle-affected nodes, but missing child references can coexist with a defined depth; transitive refs can include undeclared IDs or the node itself in a cycle. Non-route-bearing obligations use skipped rules unless structurally failed. Rule IDs prefix the admitted bounded ID; list order, graph relations, status/count equality and duplicate projection equality remain native. Builtin/caller nonClaims are sorted and unique. Reports do not prove witness execution, producer trust, currentness or proof satisfaction."
	return schema
}
