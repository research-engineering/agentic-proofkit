package deploymentevidenceadmission

import (
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// Member inventories are shared by native admission and the structural projection.
var (
	inputKeys               = []string{"admissionId", "evidence", "nonClaims", "policy", "rawOperatorEvidence", "schemaVersion"}
	rawOperatorEvidenceKeys = []string{"evidenceRef", "payload"}
	policyKeys              = []string{"expectedDeploymentClaim", "expectedEvidenceSchema", "expectedProofScope", "forbiddenValueIndicators", "localRefIndicators", "requireDigestPinnedImageRefs", "requireLowercaseSourceCommits", "requiredFactIds", "requiredFactKinds", "requiredNonClaims", "temporaryEndpointHostSuffixes"}
)

const callerJSONDefinition = "callerJSON"

// Evidence and operator payloads are caller JSON trees. Their only hard input
// predicate is the shared secret scanner's nonempty, control-free object keys.
func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	callerJSON := map[string]any{"$ref": "#/$defs/" + callerJSONDefinition}
	operator := map[string]any{
		"type": "object", "additionalProperties": false, "required": []any{"evidenceRef", "payload"},
		"properties": map[string]any{
			"evidenceRef": nestedSchema(text),
			"payload":     map[string]any{"$ref": "#/$defs/" + callerJSONDefinition, "description": "Required member; any JSON value including null. Secret-shaped keys and values become failed-report findings."},
		},
	}
	evidence := map[string]any{"type": "object", "propertyNames": callerJSONKeyStructure(), "additionalProperties": callerJSON}
	properties := map[string]any{
		"admissionId": nestedSchema(ruleIDShape()),
		"evidence": map[string]any{
			"anyOf":       []any{map[string]any{"type": "null"}, evidence},
			"description": "Required member. Null yields a blocked report. Object members, facts, endpoints and policy matches are evaluated into blocked or failed reports rather than input refusal.",
		},
		"nonClaims":           nestedSchema(jsonshape.Array(text, 1)),
		"policy":              PolicyStructure(),
		"rawOperatorEvidence": map[string]any{"anyOf": []any{map[string]any{"type": "null"}, map[string]any{"type": "array", "items": operator}}},
		"schemaVersion":       nestedSchema(jsonshape.IntegerLiteral(1)),
	}
	if len(properties) != len(inputKeys) {
		panic("deployment evidence structure differs from its native member inventory")
	}
	required := []any{}
	for _, key := range inputKeys {
		if _, exists := properties[key]; !exists {
			panic("deployment evidence structure omits a native member")
		}
		if key != "rawOperatorEvidence" {
			required = append(required, key)
		}
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"properties": properties, "required": required,
		"$defs": map[string]any{callerJSONDefinition: map[string]any{
			"description":          "Any JSON value. Every nested object key is nonempty text without C0 or DEL controls; otherwise the native secret scanner refuses the input.",
			"propertyNames":        callerJSONKeyStructure(),
			"additionalProperties": callerJSON, "items": callerJSON,
		}},
		"description": "Six members; rawOperatorEvidence alone may be absent, and null or absent means no operator evidence. evidence must be present but may be null. Policy, admissionId, schemaVersion and nonClaims have hard shapes: text trims by native Unicode whitespace to nonempty; requiredFactIds/Kinds items trim before RuleID admission and the trimmed ID must fit 256 bytes; at least one of those lists is nonempty. Native admission additionally owns text privacy, RuleID secret/timestamp exclusions, duplicate-tolerant normalization, local indicators that normalize to empty, DNS validity and post-normalization uniqueness of temporary suffixes. Evidence content, facts, URLs, image refs, commits, required facts and secret findings are evaluated into blocked or failed reports. No file, network or deployment check is performed.",
	}
}

// PolicyShape is the Go-side declaration; PolicyStructure adds the trimmed-ID
// byte bound and the nonempty-requirement disjunction.
func PolicyShape() jsonshape.Shape {
	text := jsonshape.NonBlankString()
	ids := jsonshape.Array(trimmedIDShape(), 0)
	return jsonshape.RequiredObject(policyKeys, map[string]jsonshape.Shape{
		"expectedDeploymentClaim": text, "expectedEvidenceSchema": text, "expectedProofScope": text,
		"forbiddenValueIndicators": jsonshape.Array(text, 0), "localRefIndicators": jsonshape.Array(text, 1),
		"requireDigestPinnedImageRefs": jsonshape.Boolean(), "requireLowercaseSourceCommits": jsonshape.Boolean(),
		"requiredFactIds": ids, "requiredFactKinds": ids, "requiredNonClaims": jsonshape.Array(text, 1),
		"temporaryEndpointHostSuffixes": jsonshape.Array(text, 0),
	})
}

func PolicyStructure() map[string]any {
	schema := nestedSchema(PolicyShape())
	properties := schema["properties"].(map[string]any)
	for _, key := range []string{"requiredFactIds", "requiredFactKinds"} {
		properties[key].(map[string]any)["items"].(map[string]any)["allOf"] = []any{map[string]any{"pattern": trimmedIDBoundShape().JSONSchema()["pattern"]}}
	}
	schema["anyOf"] = []any{
		map[string]any{"properties": map[string]any{"requiredFactIds": map[string]any{"minItems": 1}}},
		map[string]any{"properties": map[string]any{"requiredFactKinds": map[string]any{"minItems": 1}}},
	}
	return schema
}

// OutputShape is the exclusive state sum; failed reports split on whether shape
// blockers were also collected.
func OutputShape() jsonshape.Shape {
	return jsonshape.OneOf(reportShape("passed", false), reportShape("blocked", true), reportShape("failed", false), reportShape("failed", true))
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	for _, raw := range schema["oneOf"].([]any) {
		branch := raw.(map[string]any)
		properties := branch["properties"].(map[string]any)
		properties["reportId"] = nestedSchema(ruleIDShape())
		properties["nonClaims"] = reportNonClaimsStructure()
		branch["description"] = "reportId preserves admissionId. Failures dominate blockers: any failure fails the report, otherwise any blocker blocks it. blockedReasons and failures are sorted unique and repeated in the shape and safety rule diagnostics; failing rules join them with semicolons. evidenceId is null when evidence is null or its evidenceId is not admitted text. Counts derive from admitted policy and evaluated evidence. nonClaims merge builtin and caller claims in sorted order without deduplicating caller copies of builtin claims. Passed reports exit 0; blocked and failed reports exit 1 with JSON; input refusals exit 1 on stderr without a report. Structural validity does not authenticate evidence or approve rollout."
	}
	return schema
}

func reportShape(state string, blocked bool) jsonshape.Shape {
	text, count := jsonshape.StringGrammar(`[\s\S]+`), jsonshape.IntegerMinimum(0)
	blockers, failures := jsonshape.Tuple(), jsonshape.Tuple()
	blockerCount, failureCount := jsonshape.IntegerLiteral(0), jsonshape.IntegerLiteral(0)
	var blockerSample, failureSample []string
	if blocked {
		blockers, blockerCount, blockerSample = jsonshape.Array(text, 1), jsonshape.IntegerMinimum(1), []string{"blocked"}
	}
	if state == "failed" {
		failures, failureCount, failureSample = jsonshape.Array(text, 1), jsonshape.IntegerMinimum(1), []string{"failed"}
	}
	summary := jsonshape.Object(
		jsonshape.Required("blockedReasonCount", blockerCount), jsonshape.Required("endpointCount", count),
		jsonshape.Required("evidenceId", jsonshape.Nullable(canonicalTextShape())), jsonshape.Required("factCount", count),
		jsonshape.Required("failureCount", failureCount), jsonshape.Required("requiredFactIdCount", count),
		jsonshape.Required("requiredFactKindCount", count),
	)
	lists := map[string]jsonshape.Shape{"blockedReasons": blockers, "failures": failures, "state": jsonshape.StringLiteral(state)}
	nativeRules := deploymentEvidenceRuleResults(state, blockerSample, failureSample)
	rules := make([]jsonshape.Shape, len(nativeRules))
	for index, rule := range nativeRules {
		message := jsonshape.StringLiteral(rule.Message)
		if rule.Status == "failed" && index != 0 {
			message = text
		}
		key := rule.Diagnostics[0].Key
		rules[index] = report.RuleStructure(jsonshape.StringLiteral(rule.RuleID), jsonshape.StringLiteral(rule.Status), message,
			jsonshape.Tuple(report.DiagnosticStructure(key, lists[key])))
	}
	return report.Structure(1, reportKind, jsonshape.StringLiteral(state), summary,
		jsonshape.Tuple(report.DiagnosticStructure("blockedReasons", blockers), report.DiagnosticStructure("failures", failures)),
		jsonshape.Tuple(rules...))
}

func reportNonClaimsStructure() map[string]any {
	claims := nestedSchema(jsonshape.Array(canonicalTextShape(), len(boundaryNonClaims)+1))
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"] = contains
	return claims
}

// trimmedIDShape admits text whose Unicode-trimmed value is a RuleID; the
// byte bound of that trimmed value is the separate trimmedIDBoundShape.
func trimmedIDShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*(?:" + admit.RuleIDPatternBody + ")[" + space + "]*"
	})
}

func trimmedIDBoundShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*[^" + space + "]{1," + strconv.Itoa(admit.MaxRuleIDBytes) + "}[" + space + "]*"
	})
}

func callerJSONKeyStructure() map[string]any {
	return nestedSchema(jsonshape.StringGrammar(`[^\x00-\x1f\x7f]+`))
}

func canonicalTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[^" + space + "](?:[\\s\\S]*[^" + space + "])?"
	})
}

func ruleIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func nestedSchema(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}
